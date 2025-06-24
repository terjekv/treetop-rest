use crate::fetcher::{Fetchable, GenericFetcher};
use regex::Regex;
use serde::Deserialize;
use treetop_core::initialize_host_patterns;

#[derive(Deserialize)]
struct RawPattern {
    name: String,
    regex: String,
}

/// Adapter that replaces the global host‐labels
pub struct HostLabelAdapter {
    hash: Option<String>,
}

impl HostLabelAdapter {
    pub fn new() -> Self {
        Self { hash: None }
    }
}

impl Default for HostLabelAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl Fetchable for HostLabelAdapter {
    fn update_store(&mut self, body: &str) -> Result<(), Box<dyn std::error::Error>> {
        let raw: Vec<RawPattern> = serde_json::from_str(body)?;
        let mut patterns: Vec<(String, Regex)> = Vec::new();

        for r in &raw {
            if r.name.is_empty() || r.regex.is_empty() {
                tracing::error!(
                    message = "Invalid host pattern: name or regex is empty",
                    name = &r.name,
                    regex = &r.regex
                );
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid host pattern: name or regex is empty",
                )));
            }

            let regex = match Regex::new(&r.regex) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(
                        message = "Invalid regex in host pattern",
                        name = &r.name,
                        regex = &r.regex,
                        error = %e
                    );
                    return Err(Box::new(e));
                }
            };

            patterns.push((r.name.clone(), regex));
        }

        initialize_host_patterns(patterns);
        Ok(())
    }

    fn current_hash(&self) -> Option<&String> {
        self.hash.as_ref()
    }

    fn set_hash(&mut self, new: String) {
        self.hash = Some(new);
    }
}

impl HostLabelAdapter {
    /// Spawn the background loop
    pub fn spawn(url: String, refresh_secs: u64) {
        let adapter = HostLabelAdapter::new();
        GenericFetcher::new(adapter, url, refresh_secs).spawn();
    }
}
