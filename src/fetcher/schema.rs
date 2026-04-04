use crate::fetcher::generic::{Fetchable, GenericFetcher};
use crate::models::Endpoint;
use crate::state::PolicyStore;
use std::sync::{Arc, RwLock};

/// Adapter that replaces the global schema definition.
pub struct SchemaFetchAdapter {
    store: Arc<RwLock<PolicyStore>>,
    hash: Option<String>,
}

impl SchemaFetchAdapter {
    pub fn new(store: Arc<RwLock<PolicyStore>>) -> Self {
        Self { store, hash: None }
    }
}

impl Fetchable for SchemaFetchAdapter {
    fn update_store(&mut self, body: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut s = self
            .store
            .write()
            .map_err(|e| format!("schema store lock poisoned: {e}"))?;
        s.set_schema(body, None, None)?;
        Ok(())
    }

    fn current_hash(&self) -> Option<&String> {
        self.hash.as_ref()
    }

    fn set_hash(&mut self, new: String) {
        self.hash = Some(new);
    }
}

impl SchemaFetchAdapter {
    /// Spawn the background loop
    pub fn spawn(self, url: Endpoint, refresh_secs: u64) {
        let adapter = self;
        {
            let mut s = adapter.store.write().unwrap();
            s.schema.source = Some(url.clone());
            s.schema.refresh_frequency = Some(refresh_secs as u32);
        }
        GenericFetcher::new(adapter, url.to_string(), refresh_secs).spawn();
    }
}
