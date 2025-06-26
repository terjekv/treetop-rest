use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use treetop_core::{Action, Decision, Groups, Request, Resource, User};
use url::Url;

use crate::errors::ServiceError;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct Endpoint {
    url: Url,
}

impl Endpoint {
    pub fn new(url: Url) -> Self {
        Endpoint { url }
    }

    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    pub fn url(&self) -> &Url {
        &self.url
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}

impl std::str::FromStr for Endpoint {
    type Err = url::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Url::parse(s) {
            Ok(url) => Ok(Endpoint { url }),
            Err(e) => Err(e),
        }
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct CheckRequest {
    pub principal: String,
    pub action: String,
    pub resource: Resource,
}

#[derive(Serialize)]
pub struct CheckResponse {
    pub decision: Decision,
}

#[derive(Serialize)]
pub enum DecisionBrief {
    Allow,
    Deny,
}

#[derive(Serialize)]
pub struct CheckResponseBrief {
    pub decision: DecisionBrief,
}

#[derive(Serialize)]
pub struct PoliciesMetadata {
    pub policies_sha256: String,
    pub policies_uploaded_at: DateTime<Utc>,
    pub policies_size: usize,
    pub policies_allow_upload: bool,
    pub policies_url: Option<Endpoint>,
    pub policies_refresh_frequency: Option<u32>,
    pub host_labels_url: Option<Endpoint>,
    pub host_labels_refresh_frequency: Option<u32>,
}

#[derive(Serialize)]
pub struct PoliciesDownload {
    pub policies: String,
    pub sha256: String,
    pub uploaded_at: DateTime<Utc>,
}

pub fn build_request(req: &CheckRequest) -> Result<Request, ServiceError> {
    Ok(Request {
        principal: User::new(&req.principal, None),
        action: Action::new(&req.action, None),
        groups: Groups(vec![]),
        resource: req.resource.clone(),
    })
}
