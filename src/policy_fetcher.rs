use crate::fetcher::Fetchable;
use crate::fetcher::GenericFetcher;
use crate::state::PolicyStore;
use std::sync::{Arc, Mutex};

/// Wraps a PolicyStore to implement Fetchable
pub struct PolicyFetchAdapter {
    store: Arc<Mutex<PolicyStore>>,
    hash: Option<String>,
}

impl PolicyFetchAdapter {
    pub fn new(store: Arc<Mutex<PolicyStore>>) -> Self {
        Self { store, hash: None }
    }
}

impl Fetchable for PolicyFetchAdapter {
    fn update_store(&mut self, body: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut s = self.store.lock().unwrap();
        s.update_dsl(&body.to_string())?;
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
    pub fn spawn(self, url: String, refresh_secs: u64) {
        let adapter = self;
        GenericFetcher::new(adapter, url, refresh_secs).spawn();
    }
}
