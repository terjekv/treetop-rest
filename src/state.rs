use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use treetop_core::PolicyEngine;

use crate::{errors::ServiceError, models::PolicyURL};

pub struct PolicyStore {
    pub engine: Arc<PolicyEngine>,
    pub dsl: String,
    pub sha256: String,
    pub timestamp: DateTime<Utc>,
    pub size: usize,
    pub allow_upload: bool,
    pub url: Option<PolicyURL>,
    pub refresh_frequency: Option<u32>,
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
            sha256,
            timestamp: now,
            size,
            allow_upload: false,
            url: None,
            refresh_frequency: None,
            upload_token: None,
        }
    }
}

pub type SharedPolicyStore = Arc<Mutex<PolicyStore>>;

impl PolicyStore {
    pub fn update_dsl(&mut self, dsl_string: &String) -> Result<(), ServiceError> {
        let mut hasher = Sha256::new();
        hasher.update(dsl_string.as_bytes());
        self.engine = Arc::new(PolicyEngine::new_from_str(&dsl_string)?);
        self.sha256 = format!("{:x}", hasher.finalize());
        self.dsl = dsl_string.clone();
        self.timestamp = Utc::now();
        self.size = self.dsl.len();
        Ok(())
    }
}
