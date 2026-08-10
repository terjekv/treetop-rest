use reqwest::{Client, header};
use sha2::{Digest, Sha256};
use std::fmt::Write;
use std::{error::Error, io, time::Duration};
use tracing::{debug, error, info};

/// Trait for things that can apply a validated body from a successful remote response.
pub trait Fetchable {
    fn apply_successful_response(&mut self, body: &str) -> Result<(), Box<dyn Error>>;
    fn current_hash(&self) -> Option<&String>;
    fn set_hash(&mut self, new: String);
}

/// Generic fetcher: HEAD/GET + ETag/Last‑Modified + SHA checks
pub struct GenericFetcher<T: Fetchable + Send + 'static> {
    client: Client,
    inner: T,
    url: String,
    refresh_secs: u64,
    etag: Option<String>,
    last_modified: Option<String>,
}

impl<T: Fetchable + Send + 'static> GenericFetcher<T> {
    pub fn new(inner: T, url: String, refresh_secs: u64) -> Self {
        GenericFetcher {
            client: Client::new(),
            inner,
            url,
            refresh_secs,
            etag: None,
            last_modified: None,
        }
    }

    pub fn spawn(mut self) {
        tokio::spawn(async move {
            loop {
                if let Err(e) = self.check_and_update().await {
                    error!(message = "fetch loop error", url = &self.url, error = %e);
                }
                tokio::time::sleep(Duration::from_secs(self.refresh_secs)).await;
            }
        });
    }

    async fn check_and_update(&mut self) -> Result<(), Box<dyn Error>> {
        // 1. HEAD for conditional
        let mut hb = self.client.head(&self.url);
        if let Some(et) = &self.etag {
            hb = hb.header(header::IF_NONE_MATCH, et);
        }
        if let Some(lm) = &self.last_modified {
            hb = hb.header(header::IF_MODIFIED_SINCE, lm);
        }
        let head = hb.send().await?;
        if head.status() == reqwest::StatusCode::NOT_MODIFIED {
            debug!(message = "not modified (HEAD)", url = &self.url);
            return Ok(());
        }
        if head.status().is_success() {
            self.etag = head
                .headers()
                .get(header::ETAG)
                .and_then(|v| v.to_str().ok())
                .map(ToString::to_string);
            self.last_modified = head
                .headers()
                .get(header::LAST_MODIFIED)
                .and_then(|v| v.to_str().ok())
                .map(ToString::to_string);
        }

        // 2. GET + SHA256
        let resp = self.client.get(&self.url).send().await?;
        if !resp.status().is_success() {
            return Err(io::Error::other(format!(
                "GET {} returned HTTP {}",
                self.url,
                resp.status()
            ))
            .into());
        }
        let body = resp.text().await?;
        let new_hash = {
            let mut hasher = Sha256::new();
            hasher.update(body.as_bytes());
            hasher
                .finalize()
                .iter()
                .fold(String::with_capacity(64), |mut s, b| {
                    let _ = write!(s, "{b:02x}");
                    s
                })
        };

        if let Some(old_hash) = self.inner.current_hash()
            && old_hash == &new_hash
        {
            debug!(message = "body unchanged", url = &self.url);
            return Ok(());
        }

        // 3. Update store and record hash
        self.inner.apply_successful_response(&body)?;
        self.inner.set_hash(new_hash.clone());
        info!(
            message = "fetched and applied update",
            url = &self.url,
            sha256 = &new_hash
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetcher::PolicyFetchAdapter;
    use crate::state::{PolicyStore, RemoteSourceKind, SharedPolicyStore};
    use actix_web::{App, HttpResponse, HttpServer, dev::ServerHandle, http::StatusCode, web};
    use std::net::TcpListener;
    use std::sync::{Arc, RwLock};

    fn spawn_response_server(status: StatusCode, body: &'static str) -> (String, ServerHandle) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = HttpServer::new(move || {
            App::new().default_service(web::to(move || async move {
                HttpResponse::build(status).body(body)
            }))
        })
        .listen(listener)
        .unwrap()
        .run();
        let handle = server.handle();
        actix_web::rt::spawn(server);
        (format!("http://{address}/policies.cedar"), handle)
    }

    async fn fetch_policy_once(
        status: StatusCode,
        body: &'static str,
    ) -> (Result<(), String>, SharedPolicyStore) {
        let (url, server) = spawn_response_server(status, body);
        let endpoint = url.parse().unwrap();
        let store = Arc::new(RwLock::new(PolicyStore::new().unwrap()));
        store
            .write()
            .unwrap()
            .configure_remote_source(RemoteSourceKind::Policies, endpoint, 60);

        let adapter = PolicyFetchAdapter::new(store.clone());
        let mut fetcher = GenericFetcher::new(adapter, url, 60);
        let result = fetcher.check_and_update().await.map_err(|e| e.to_string());
        server.stop(false).await;
        (result, store)
    }

    #[actix_web::test]
    async fn non_success_response_is_not_applied_or_marked_loaded() {
        let (result, store) = fetch_policy_once(StatusCode::NOT_FOUND, "").await;

        assert!(result.unwrap_err().contains("404 Not Found"));
        let store = store.read().unwrap();
        assert!(store.policies.sha256.is_empty());
        assert!(!store.configured_sources_loaded());
    }

    #[actix_web::test]
    async fn invalid_success_response_is_not_marked_loaded() {
        let (result, store) = fetch_policy_once(StatusCode::OK, "not Cedar").await;

        assert!(result.is_err());
        assert!(!store.read().unwrap().configured_sources_loaded());
    }

    #[actix_web::test]
    async fn valid_success_response_is_applied_and_marked_loaded() {
        let (result, store) = fetch_policy_once(StatusCode::OK, "").await;

        assert!(result.is_ok());
        let store = store.read().unwrap();
        assert!(!store.policies.sha256.is_empty());
        assert!(store.configured_sources_loaded());
    }
}
