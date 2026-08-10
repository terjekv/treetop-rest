use crate::fetcher::generic::{Fetchable, GenericFetcher};
use crate::models::Endpoint;
use crate::state::{PolicyStore, RemoteSourceKind};
use std::sync::{Arc, RwLock};

/// Wraps a PolicyStore to implement Fetchable
pub struct PolicyFetchAdapter {
    store: Arc<RwLock<PolicyStore>>,
    hash: Option<String>,
}

impl PolicyFetchAdapter {
    pub fn new(store: Arc<RwLock<PolicyStore>>) -> Self {
        Self { store, hash: None }
    }
}

impl Fetchable for PolicyFetchAdapter {
    fn apply_successful_response(&mut self, body: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut s = self
            .store
            .write()
            .map_err(|e| format!("policy store lock poisoned: {e}"))?;
        s.set_dsl(body, None, None)?;
        s.mark_remote_source_loaded(RemoteSourceKind::Policies);
        Ok(())
    }

    fn current_hash(&self) -> Option<&String> {
        self.hash.as_ref()
    }

    fn set_hash(&mut self, new: String) {
        self.hash = Some(new);
    }
}

impl PolicyFetchAdapter {
    /// Spawn the background loop
    pub fn spawn(self, url: Endpoint, refresh_secs: u64) {
        let adapter = self;
        {
            let mut s = adapter.store.write().unwrap();
            s.configure_remote_source(RemoteSourceKind::Policies, url.clone(), refresh_secs as u32);
        }
        GenericFetcher::new(adapter, url.to_string(), refresh_secs).spawn();
    }
}
