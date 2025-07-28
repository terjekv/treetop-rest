use std::ops::Deref;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use treetop_core::Decision;
use url::Url;

use utoipa::ToSchema;

use crate::state::{Metadata, OfHostLabels, OfPolicies, PolicyStore};

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

#[derive(Serialize, ToSchema)]
pub struct CheckResponse {
    pub decision: Decision,
}

#[derive(Serialize, ToSchema)]
pub enum DecisionBrief {
    Allow,
    Deny,
}

#[derive(Serialize, ToSchema)]
pub struct CheckResponseBrief {
    pub decision: DecisionBrief,
}

impl From<Decision> for CheckResponseBrief {
    fn from(decision: Decision) -> Self {
        match decision {
            Decision::Allow { .. } => CheckResponseBrief {
                decision: DecisionBrief::Allow,
            },
            Decision::Deny => CheckResponseBrief {
                decision: DecisionBrief::Deny,
            },
        }
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct PoliciesMetadata {
    pub allow_upload: bool,

    pub policies: Metadata<OfPolicies>,
    pub host_labels: Metadata<OfHostLabels>,
}

impl<T> From<T> for PoliciesMetadata
where
    T: Deref<Target = PolicyStore>,
{
    fn from(store: T) -> Self {
        PoliciesMetadata {
            allow_upload: store.allow_upload,
            policies: store.policies.clone(),
            host_labels: store.host_labels.clone(),
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
