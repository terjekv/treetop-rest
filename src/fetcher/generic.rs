use reqwest::{Client, header};
use sha2::{Digest, Sha256};
use std::{error::Error, time::Duration};
use tracing::{debug, error, info};

/// Trait for things that can update a shared store from remote text
pub trait Fetchable {
    fn update_store(&mut self, body: &str) -> Result<(), Box<dyn Error>>;
    fn current_hash(&self) -> Option<&String>;
    #[allow(dead_code)]
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
        let body = resp.text().await?;
        let new_hash = {
            let mut hasher = Sha256::new();
            hasher.update(body.as_bytes());
            format!("{:x}", hasher.finalize())
        };

        if let Some(old_hash) = self.inner.current_hash()
            && old_hash == &new_hash
        {
            debug!(message = "body unchanged", url = &self.url);
            return Ok(());
        }

        // 3. Update store and record hash
        self.inner.update_store(&body)?;
        info!(
            message = "fetched and applied update",
            url = &self.url,
            sha256 = &new_hash
        );
        Ok(())
    }
}
