use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use treetop_core::{Action, Decision, Groups, Host, Request, User};
use url::Url;

use crate::errors::ServiceError;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct PolicyURL {
    url: Url,
}

impl PolicyURL {
    pub fn new(url: Url) -> Self {
        PolicyURL { url }
    }

    pub fn as_str(&self) -> &str {
        self.url.as_str()
    }

    pub fn url(&self) -> &Url {
        &self.url
    }
}

impl std::fmt::Display for PolicyURL {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url)
    }
}

impl std::str::FromStr for PolicyURL {
    type Err = url::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match Url::parse(s) {
            Ok(url) => Ok(PolicyURL { url }),
            Err(e) => Err(e),
        }
    }
}

#[derive(Deserialize)]
pub struct CheckRequest {
    pub principal: String,
    pub action: String,
    pub resource_name: String,
    pub resource_ip: String,
}

#[derive(Serialize)]
pub struct CheckResponse {
    pub decision: Decision,
}

#[derive(Serialize)]
pub struct PoliciesMetadata {
    pub sha256: String,
    pub uploaded_at: DateTime<Utc>,
    pub size: usize,
    pub allow_upload: bool,
    pub url: Option<PolicyURL>,
    pub refresh_frequency: Option<u32>,
}

#[derive(Serialize)]
pub struct PoliciesDownload {
    pub policies: String,
    pub sha256: String,
    pub uploaded_at: DateTime<Utc>,
}

pub fn build_request(req: &CheckRequest) -> Result<Request, ServiceError> {
    let ip = req
        .resource_ip
        .parse()
        .map_err(|_| ServiceError::InvalidIp)?;
    Ok(Request {
        principal: User::new(&req.principal, None),
        action: Action::new(&req.action, None),
        groups: Groups(vec![]),
        resource: Host {
            name: req.resource_name.clone(),
            ip,
        },
    })
}
