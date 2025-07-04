use std::ops::Deref;

use serde::{Deserialize, Serialize};
use treetop_core::Decision;
use url::Url;

use crate::state::{Metadata, OfHostLabels, OfPolicies, PolicyStore};

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

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize)]
pub struct PoliciesDownload {
    pub policies: Metadata<OfPolicies>,
}
