use crate::fetcher::generic::{Fetchable, GenericFetcher};
use crate::models::Endpoint;
use crate::state::PolicyStore;
use std::sync::{Arc, Mutex};

/// Adapter that replaces the global host‐labels
pub struct HostLabelAdapter {
    store: Arc<Mutex<PolicyStore>>,
    hash: Option<String>,
}

impl HostLabelAdapter {
    pub fn new(store: Arc<Mutex<PolicyStore>>) -> Self {
        Self { store, hash: None }
    }
}

impl Fetchable for HostLabelAdapter {
    fn update_store(&mut self, body: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut s = self.store.lock().unwrap();
        s.set_host_labels(&body.to_string(), None, None)?;
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
    pub fn spawn(self, url: Endpoint, refresh_secs: u64) {
        let adapter = self;
        adapter.store.lock().unwrap().host_labels.source = Some(url.clone());
        adapter.store.lock().unwrap().host_labels.refresh_frequency = Some(refresh_secs as u32);
        GenericFetcher::new(adapter, url.to_string(), refresh_secs).spawn();
    }
}
