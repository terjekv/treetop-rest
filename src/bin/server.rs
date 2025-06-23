use treetop_rest;

use actix_web::{App, HttpServer, middleware::Logger};
use clap::Parser;
use env_logger;
use regex::Regex;
use std::sync::{Arc, Mutex};
use treetop_core::initialize_host_patterns;
use treetop_rest::config::Config;
use treetop_rest::state::PolicyStore;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    let config = Config::parse();

    initialize_host_patterns(vec![
        (
            "in_domain".to_string(),
            Regex::new(r"example\.com$").unwrap(),
        ),
        (
            "valid_webserver_name".to_string(),
            Regex::new(r"^web-\d+").unwrap(),
        ),
    ]);

    let store = Arc::new(Mutex::new(PolicyStore::new(String::new())));

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
