use actix_web::{App, HttpServer, middleware::Logger};
use clap::Parser;
use regex::Regex;
use std::sync::{Arc, Mutex};
use tracing::warn;
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

    if config.allow_upload {
        store.lock().unwrap().allow_upload = true;
        let token = uuid::Uuid::new_v4().to_string();
        warn!(uploads = "Enabled", token = token);
        store.lock().unwrap().upload_token = Some(token);
    }

    if let Some(policy_url) = config.policy_url.clone() {
        let refresh_frequency = config.update_frequency.unwrap_or(60);
        store.lock().unwrap().url = Some(policy_url.clone());
        store.lock().unwrap().refresh_frequency = Some(refresh_frequency);

        let store_clone = Arc::clone(&store);

        // Spawn the background task
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            let inner_policy_url = policy_url.clone();

            loop {
                match client.get(inner_policy_url.to_string()).send().await {
                    Ok(resp) => match resp.text().await {
                        Ok(text) => {
                            let mut store = store_clone.lock().unwrap();
                            match store.update_dsl(&text) {
                                Ok(_) => {
                                    tracing::info!(
                                        fetcher = "Policy DSL updated successfully",
                                        url = inner_policy_url.to_string(),
                                        sha256 = store.sha256,
                                        size = store.size,
                                        timestamp = store.timestamp.to_rfc3339()
                                    );
                                }
                                Err(err) => {
                                    tracing::error!(
                                        fetcher = "Failed to update policy DSL",
                                        error = err.to_string(),
                                        url = inner_policy_url.to_string()
                                    );
                                }
                            }
                        }
                        Err(err) => {
                            tracing::error!(
                                fetcher = "Failed to read policy body",
                                error = err.to_string(),
                                url = inner_policy_url.to_string()
                            );
                        }
                    },
                    Err(err) => {
                        tracing::error!(
                            fetcher = "Failed to fetch policy URL",
                            error = err.to_string(),
                            url = inner_policy_url.to_string()
                        );
                    }
                }

                tokio::time::sleep(std::time::Duration::from_secs(refresh_frequency as u64)).await;
            }
        });
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
