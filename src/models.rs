use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use treetop_core::{Action, Decision, Host, Request, User};

use crate::errors::ServiceError;

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
        groups: vec![],
        resource: Host {
            name: req.resource_name.clone(),
            ip,
        },
    })
}
