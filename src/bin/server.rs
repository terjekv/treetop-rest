use actix_web::{App, HttpServer};
use clap::Parser;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;
use treetop_rest::build_info::build_info;
use treetop_rest::config::Config;
use treetop_rest::fetcher::{LabelFetchAdapter, PolicyFetchAdapter};
use treetop_rest::middeware::TracingMiddleware;
use treetop_rest::state::PolicyStore;

use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let config = Config::parse();

    if config.version {
        println!(
            "Treetop REST API version: {} (core: {}, cedar: {})",
            build_info().version,
            build_info().core,
            build_info().cedar
        );
        return Ok(());
    }

    let store = Arc::new(Mutex::new(PolicyStore::new().unwrap()));

    info!(
        message = "Initializing server",
        version = build_info().version,
        core = build_info().core,
        cedar = build_info().cedar
    );

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

    if let Some(hurl) = config.labels_url.clone() {
        let freq = config.labels_refresh.unwrap_or(60) as u64;
        {
            let mut s = store.lock().unwrap();
            s.labels.source = Some(hurl.clone());
            s.labels.refresh_frequency = Some(freq as u32);
        }
        LabelFetchAdapter::new(store.clone()).spawn(hurl, freq);
    }

    HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .wrap(TracingMiddleware)
            .service(SwaggerUi::new("/swagger-ui/{_:.*}").url(
                "/api-docs/openapi.json",
                treetop_rest::handlers::ApiDoc::openapi(),
            ))
            .app_data(actix_web::web::Data::new(store.clone()))
            .configure(treetop_rest::handlers::init)
    })
    .bind((config.host.as_str(), config.port))?
    .workers(config.workers)
    .run()
    .await
}
