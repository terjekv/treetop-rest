use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use treetop_core::PolicyEngine;

use crate::{errors::ServiceError, models::Endpoint};

pub struct PolicyStore {
    pub engine: Arc<PolicyEngine>,
    pub dsl: String,
    pub policies_sha256: String,
    pub policies_timestamp: DateTime<Utc>,
    pub policies_size: usize,
    pub policies_allow_upload: bool,
    pub policies_url: Option<Endpoint>,
    pub policies_refresh_frequency: Option<u32>,

    pub host_labels_url: Option<Endpoint>,
    pub host_labels_refresh_frequency: Option<u32>,

    pub upload_token: Option<String>,
}

impl PolicyStore {
    /// Create a new PolicyStore initialized with the given DSL string.
    pub fn new(dsl: String) -> Self {
        let now = Utc::now();
        let mut hasher = Sha256::new();
        hasher.update(dsl.as_bytes());
        let sha256 = format!("{:x}", hasher.finalize());
        let engine =
            Arc::new(PolicyEngine::new_from_str(&dsl).expect("Failed to initialize policy engine"));
        let size = dsl.len();

        PolicyStore {
            engine,
            dsl,
            policies_sha256: sha256,
            policies_timestamp: now,
            policies_size: size,
            policies_allow_upload: false,
            policies_url: None,
            policies_refresh_frequency: None,
            host_labels_url: None,
            host_labels_refresh_frequency: None,
            upload_token: None,
        }
    }
}

pub type SharedPolicyStore = Arc<Mutex<PolicyStore>>;

impl PolicyStore {
    pub fn update_dsl(&mut self, dsl_string: &String) -> Result<(), ServiceError> {
        let mut hasher = Sha256::new();
        hasher.update(dsl_string.as_bytes());
        self.engine = Arc::new(PolicyEngine::new_from_str(dsl_string)?);
        self.policies_sha256 = format!("{:x}", hasher.finalize());
        self.dsl = dsl_string.clone();
        self.policies_timestamp = Utc::now();
        self.policies_size = self.dsl.len();
        Ok(())
    }
    pub fn update_host_labels(
        &mut self,
        pairs: Vec<(String, regex::Regex)>,
    ) -> Result<(), ServiceError> {
        treetop_core::initialize_host_patterns(pairs);
        Ok(())
    }
}
