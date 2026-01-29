use std::ops::Deref;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use treetop_core::{Decision, PermitPolicy, PolicyVersion, Request};
use url::Url;

use utoipa::ToSchema;

use crate::state::{Metadata, OfLabels, OfPolicies, PolicyStore};

#[derive(Deserialize, Serialize, Clone, Debug, ToSchema)]
pub struct Endpoint {
    #[schema(value_type = String, example = "https://example.com/api")]
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

#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub struct CheckResponse {
    pub policy: Option<PermitPolicy>,
    pub desicion: DecisionBrief,
    pub version: PolicyVersion,
}

impl From<Decision> for CheckResponse {
    fn from(decision: Decision) -> Self {
        match decision {
            Decision::Allow { policy, version } => CheckResponse {
                policy: Some(policy),
                desicion: DecisionBrief::Allow,
                version,
            },
            Decision::Deny { version } => CheckResponse {
                policy: None,
                desicion: DecisionBrief::Deny,
                version,
            },
        }
    }
}

#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub enum DecisionBrief {
    Allow,
    Deny,
}

#[derive(Serialize, Deserialize, ToSchema, Clone)]
pub struct CheckResponseBrief {
    pub decision: DecisionBrief,
    pub version: PolicyVersion,
}

impl From<Decision> for CheckResponseBrief {
    fn from(decision: Decision) -> Self {
        match decision {
            Decision::Allow { version, .. } => CheckResponseBrief {
                decision: DecisionBrief::Allow,
                version,
            },
            Decision::Deny { version, .. } => CheckResponseBrief {
                decision: DecisionBrief::Deny,
                version,
            },
        }
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct PoliciesMetadata {
    pub allow_upload: bool,

    pub policies: Metadata<OfPolicies>,
    pub labels: Metadata<OfLabels>,
}

impl<T> From<T> for PoliciesMetadata
where
    T: Deref<Target = PolicyStore>,
{
    fn from(store: T) -> Self {
        PoliciesMetadata {
            allow_upload: store.allow_upload,
            policies: store.policies.clone(),
            labels: store.labels.clone(),
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct PoliciesDownload {
    pub policies: Metadata<OfPolicies>,
}

#[derive(Serialize, ToSchema)]
pub struct UserPolicies {
    pub user: String,
    pub policies: Vec<Value>,
}

impl From<treetop_core::UserPolicies> for UserPolicies {
    fn from(user_policies: treetop_core::UserPolicies) -> Self {
        UserPolicies {
            user: user_policies.user().to_string(),
            policies: user_policies
                .policies()
                .iter()
                .map(|p| p.to_json().unwrap()) // Yuck.
                .collect(),
        }
    }
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct AuthRequest {
    /// Optional client-provided identifier for this request
    pub id: Option<String>,
    /// The actual authorization request
    #[serde(flatten)]
    pub request: Request,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct AuthorizeRequest {
    /// List of authorization requests to evaluate
    pub requests: Vec<AuthRequest>,
}

#[derive(Deserialize, ToSchema)]
pub struct BatchCheckRequest {
    /// List of authorization requests to evaluate
    pub requests: Vec<Request>,
}

#[derive(Serialize, ToSchema)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum BatchResult<T> {
    Success {
        #[serde(rename = "result")]
        data: T,
    },
    Failed {
        #[serde(rename = "error")]
        message: String,
    },
}

#[derive(Serialize, ToSchema)]
pub struct IndexedResult<T> {
    /// Index of the request in the original batch
    pub index: usize,
    /// Client-provided identifier for this request (if provided)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Result of the evaluation (success or error)
    #[serde(flatten)]
    pub result: BatchResult<T>,
}

#[derive(Serialize, ToSchema)]
pub struct AuthorizeResponse {
    /// Results for each request with optional client IDs
    pub results: Vec<IndexedResult<CheckResponseBrief>>,
    /// Policy version used for all evaluations
    pub version: PolicyVersion,
    /// Number of successful evaluations
    pub successful: usize,
    /// Number of failed evaluations
    pub failed: usize,
}

#[derive(Serialize, ToSchema)]
pub struct AuthorizeDetailedResponse {
    /// Detailed results for each request with optional client IDs
    pub results: Vec<IndexedResult<CheckResponse>>,
    /// Policy version used for all evaluations
    pub version: PolicyVersion,
    /// Number of successful evaluations
    pub successful: usize,
    /// Number of failed evaluations
    pub failed: usize,
}

/// Response from the authorize endpoint - either brief or detailed based on query parameter
#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub enum AuthorizeResponseVariant {
    /// Brief response with minimal decision information
    Brief(AuthorizeResponse),
    /// Detailed response with full decision reasoning
    Detailed(AuthorizeDetailedResponse),
}

#[derive(Serialize, ToSchema)]
pub struct BatchCheckResponse {
    /// Results for each request in the same order as input
    pub results: Vec<IndexedResult<CheckResponseBrief>>,
    /// Policy version used for all evaluations
    pub version: PolicyVersion,
    /// Number of successful evaluations
    pub successful: usize,
    /// Number of failed evaluations
    pub failed: usize,
}

#[derive(Serialize, ToSchema)]
pub struct BatchCheckDetailedResponse {
    /// Detailed results for each request in the same order as input
    pub results: Vec<IndexedResult<CheckResponse>>,
    /// Policy version used for all evaluations
    pub version: PolicyVersion,
    /// Number of successful evaluations
    pub successful: usize,
    /// Number of failed evaluations
    pub failed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_endpoint_new() {
        let url = Url::parse("https://example.com/api").unwrap();
        let endpoint = Endpoint::new(url.clone());
        assert_eq!(endpoint.as_str(), "https://example.com/api");
        assert_eq!(endpoint.url(), &url);
    }

    #[test]
    fn test_endpoint_from_str() {
        let endpoint = Endpoint::from_str("https://example.com/api").unwrap();
        assert_eq!(endpoint.as_str(), "https://example.com/api");
    }

    #[test]
    fn test_endpoint_from_str_invalid() {
        let result = Endpoint::from_str("not a valid url");
        assert!(result.is_err());
    }

    #[test]
    fn test_endpoint_display() {
        let endpoint = Endpoint::from_str("https://example.com/api").unwrap();
        assert_eq!(format!("{}", endpoint), "https://example.com/api");
    }
}
