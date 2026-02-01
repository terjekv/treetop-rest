use actix_web::{App, HttpServer};
use clap::Parser;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use treetop_rest::build_info::build_info;
use treetop_rest::config::Config;
use treetop_rest::fetcher::{LabelFetchAdapter, PolicyFetchAdapter};
use treetop_rest::middeware::{ClientAllowlistMiddleware, TracingMiddleware};
use treetop_rest::state::PolicyStore;

use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .with_current_span(true)
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

    let parallel_config = treetop_rest::parallel::init_parallelism(
        config.workers,
        config.rayon_threads,
        config.par_threshold,
    );

    info!(
        message = "Scale out config",
        cpu_count = parallel_config.cpu_count,
        actix_workers = parallel_config.workers,
        rayon_threads = parallel_config.rayon_threads,
        parallel_threshold = parallel_config.par_threshold,
        allow_parallel = parallel_config.allow_parallel
    );

    // Initialize Prometheus metrics and set treetop-core sink
    let metrics_registry =
        treetop_rest::metrics::init_prometheus().expect("Failed to init metrics");

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

    let client_allowlist = config.client_allowlist.clone();
    let trust_ip_headers = config.trust_ip_headers;

    HttpServer::new(move || {
        App::new()
            .wrap(ClientAllowlistMiddleware::new_with_trust(
                client_allowlist.clone(),
                trust_ip_headers,
            ))
            .wrap(TracingMiddleware::new_with_trust(trust_ip_headers))
            .service(SwaggerUi::new("/swagger-ui/{_:.*}").url(
                "/api-docs/openapi.json",
                treetop_rest::handlers::ApiDoc::openapi(),
            ))
            .app_data(actix_web::web::Data::new(store.clone()))
            .app_data(actix_web::web::Data::new(parallel_config))
            .app_data(actix_web::web::Data::new(metrics_registry.clone()))
            .configure(treetop_rest::handlers::init)
    })
    .bind((config.host.as_str(), config.port))?
    .workers(parallel_config.workers)
    .run()
    .await
}
