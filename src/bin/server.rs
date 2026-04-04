use actix_web::{App, HttpServer};
use clap::Parser;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use treetop_rest::build_info::build_info;
use treetop_rest::config::Config;
use treetop_rest::fetcher::{LabelFetchAdapter, PolicyFetchAdapter, SchemaFetchAdapter};
use treetop_rest::handlers::AuthorizeRuntimeConfig;
use treetop_rest::middleware::{ClientAllowlistMiddleware, TracingMiddleware};
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

    let store = Arc::new(RwLock::new(PolicyStore::new().unwrap()));

    info!(
        message = "Initializing server",
        version = build_info().version,
        core = build_info().core,
        cedar = build_info().cedar
    );

    if config.allow_upload {
        store.write().unwrap().allow_upload = true;
        let token = uuid::Uuid::new_v4().to_string();
        warn!(message = "Uploads enabled", token = token);
        store.write().unwrap().upload_token = Some(token);
    }
    store
        .write()
        .unwrap()
        .set_schema_validation_mode(config.schema_validation_mode);

    if let Some(url) = config.policy_url.clone() {
        let freq = config.update_frequency.unwrap_or(60) as u64;
        // Create a block to that the lock on the store is released before spawning the adapter
        // to avoid deadlocks. The alternative would be to use drop(s) to release the lock.
        {
            let mut s = store.write().unwrap();
            s.policies.source = Some(url.clone());
            s.policies.refresh_frequency = Some(freq as u32);
        }
        PolicyFetchAdapter::new(store.clone()).spawn(url, freq);
    }

    if let Some(hurl) = config.labels_url.clone() {
        let freq = config.labels_refresh.unwrap_or(60) as u64;
        {
            let mut s = store.write().unwrap();
            s.labels.source = Some(hurl.clone());
            s.labels.refresh_frequency = Some(freq as u32);
        }
        LabelFetchAdapter::new(store.clone()).spawn(hurl, freq);
    }

    if let Some(surl) = config.schema_url.clone() {
        let freq = config.schema_refresh.unwrap_or(60) as u64;
        {
            let mut s = store.write().unwrap();
            s.schema.source = Some(surl.clone());
            s.schema.refresh_frequency = Some(freq as u32);
        }
        SchemaFetchAdapter::new(store.clone()).spawn(surl, freq);
    }

    let authorize_runtime = AuthorizeRuntimeConfig {
        // Current treetop-core version in this service does not support request context evaluation yet.
        context_enabled: false,
        max_context_bytes: config.max_context_bytes,
        max_context_depth: config.max_context_depth,
        max_context_keys: config.max_context_keys,
    };

    let client_allowlist = config.client_allowlist.clone();
    let trust_ip_headers = config.trust_ip_headers;
    let max_request_size = config.max_request_size;

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
            .app_data(actix_web::web::JsonConfig::default().limit(max_request_size))
            .app_data(actix_web::web::PayloadConfig::default().limit(max_request_size))
            .app_data(actix_web::web::Data::new(store.clone()))
            .app_data(actix_web::web::Data::new(parallel_config))
            .app_data(actix_web::web::Data::new(authorize_runtime))
            .app_data(actix_web::web::Data::new(metrics_registry.clone()))
            .configure(treetop_rest::handlers::init)
    })
    .bind((config.host.as_str(), config.port))?
    .workers(parallel_config.workers)
    .shutdown_timeout(30)
    .run()
    .await
}
