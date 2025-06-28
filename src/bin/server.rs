use actix_web::{App, HttpServer, middleware::Logger};
use clap::Parser;
use std::sync::{Arc, Mutex};
use tracing::warn;
use treetop_core::initialize_host_patterns;
use treetop_rest::config::Config;
use treetop_rest::fetcher::host_name_label::HostLabelAdapter;
use treetop_rest::fetcher::policy::PolicyFetchAdapter;
use treetop_rest::state::PolicyStore;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let config = Config::parse();

    initialize_host_patterns(vec![]);

    let store = Arc::new(Mutex::new(PolicyStore::new().unwrap()));

    if config.allow_upload {
        store.lock().unwrap().allow_upload = true;
        let token = uuid::Uuid::new_v4().to_string();
        warn!(message = "Uploads enabled", token = token);
        store.lock().unwrap().upload_token = Some(token);
    }

    if let Some(url) = config.policy_url.clone() {
        let freq = config.update_frequency.unwrap_or(60) as u64;
        // Create a block to that the lock on the store is released before spawning the adapter
        // to avoid deadlocks. The alternative would be to use drop(s) to release the lock.
        {
            let mut s = store.lock().unwrap();
            s.policies.source = Some(url.clone());
            s.policies.refresh_frequency = Some(freq as u32);
        }
        PolicyFetchAdapter::new(store.clone()).spawn(url, freq);
    }

    if let Some(hurl) = config.host_labels_url.clone() {
        let freq = config.host_labels_refresh.unwrap_or(60) as u64;
        {
            let mut s = store.lock().unwrap();
            s.host_labels.source = Some(hurl.clone());
            s.host_labels.refresh_frequency = Some(freq as u32);
        }
        HostLabelAdapter::new(store.clone()).spawn(hurl, freq);
    }

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(actix_web::web::Data::new(store.clone()))
            .configure(treetop_rest::handlers::init)
    })
    .bind((config.host.as_str(), config.port))?
    .workers(config.workers)
    .run()
    .await
}
