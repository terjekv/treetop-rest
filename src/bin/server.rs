use actix_web::{App, HttpServer, middleware::Logger};
use clap::Parser;
use std::sync::{Arc, Mutex};
use tracing::warn;
use treetop_core::initialize_host_patterns;
use treetop_rest::config::Config;
use treetop_rest::hostlabel_fetcher::HostLabelAdapter;
use treetop_rest::policy_fetcher::PolicyFetchAdapter;
use treetop_rest::state::PolicyStore;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let config = Config::parse();

    initialize_host_patterns(vec![]);

    let store = Arc::new(Mutex::new(PolicyStore::new(String::new())));

    if config.allow_upload {
        store.lock().unwrap().policies_allow_upload = true;
        let token = uuid::Uuid::new_v4().to_string();
        warn!(message = "Uploads enabled", token = token);
        store.lock().unwrap().upload_token = Some(token);
    }

    if let Some(url) = config.policy_url.clone() {
        let freq = config.update_frequency.unwrap_or(60) as u64;
        {
            let mut s = store.lock().unwrap();
            s.policies_url = Some(url.clone());
            s.policies_refresh_frequency = Some(freq as u32);
        }
        PolicyFetchAdapter::new(store.clone()).spawn(url.to_string(), freq);
    }

    if let Some(hurl) = config.host_labels_url.clone() {
        let freq = config.host_labels_refresh.unwrap_or(60) as u64;
        let mut s = store.lock().unwrap();
        s.host_labels_url = Some(hurl.clone());
        s.host_labels_refresh_frequency = Some(freq as u32);
        HostLabelAdapter::spawn(hurl.to_string(), freq);
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
