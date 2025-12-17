use std::{fmt, net::IpAddr, str::FromStr};

use colored::*;
use serde::{Deserialize, Serialize};
use treetop_core::AttrValue;

use crate::cli::style::{error, success};
use crate::models::{CheckResponse, CheckResponseBrief, DecisionBrief, PoliciesMetadata};
use crate::state::{Metadata, OfPolicies};

#[derive(Default, Clone)]
pub struct LastUsedValues {
    pub principal: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub attrs: Vec<(String, InputAttrValue)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InputAttrValue {
    Ip(IpAddr),
    Long(i64),
    Bool(bool),
    String(String),
}

impl fmt::Display for InputAttrValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputAttrValue::Ip(ip) => write!(f, "{ip}"),
            InputAttrValue::Long(i) => write!(f, "{i}"),
            InputAttrValue::Bool(b) => write!(f, "{b}"),
            InputAttrValue::String(s) => write!(f, "{s}"),
        }
    }
}

impl From<InputAttrValue> for AttrValue {
    fn from(v: InputAttrValue) -> Self {
        match v {
            InputAttrValue::Ip(ip) => AttrValue::Ip(ip.to_string()),
            InputAttrValue::Long(i) => AttrValue::Long(i),
            InputAttrValue::Bool(b) => AttrValue::Bool(b),
            InputAttrValue::String(s) => AttrValue::String(s),
        }
    }
}

impl FromStr for InputAttrValue {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Self::Ip(ip));
        }
        if let Ok(i) = s.parse::<i64>() {
            return Ok(Self::Long(i));
        }
        if let Ok(b) = s.parse::<bool>() {
            return Ok(Self::Bool(b));
        }
        let unquoted = s
            .strip_prefix('"')
            .and_then(|t| t.strip_suffix('"'))
            .unwrap_or(s);
        Ok(Self::String(unquoted.to_string()))
    }
}

pub trait CliDisplay {
    fn display(&self) -> String;
}

impl CliDisplay for PoliciesMetadata {
    fn display(&self) -> String {
        format!(
            "Allow upload: {}
 Policies:
{}
 Host labels:
{}",
            self.allow_upload, self.policies, self.labels,
        )
    }
}

impl CliDisplay for CheckResponseBrief {
    fn display(&self) -> String {
        match self.decision {
            DecisionBrief::Allow => format!("{} ({})", success("Allow"), self.version.hash),
            DecisionBrief::Deny => format!("{} ({})", error("Deny"), self.version.hash),
        }
    }
}

impl CliDisplay for CheckResponse {
    fn display(&self) -> String {
        match &self.policy {
            Some(policy) => format!(
                "{} ({})\n{}\n{}\n{}",
                success("Allow"),
                self.version.hash,
                "--- Matching policy ---".cyan(),
                policy.literal,
                "---".cyan()
            ),
            None => format!("{} ({})", error("Deny"), self.version.hash),
        }
    }
}

#[derive(Deserialize)]
pub struct PoliciesDownload {
    pub policies: Metadata<OfPolicies>,
}
impl CliDisplay for PoliciesDownload {
    fn display(&self) -> String {
        format!("Metadata:\n{}\nContent:\n{}", self.policies, self.policies.content)
    }
}

#[derive(Deserialize, Clone)]
pub struct UserPolicies(pub serde_json::Value);
impl CliDisplay for UserPolicies {
    fn display(&self) -> String {
        serde_json::to_string_pretty(&self.0).unwrap()
    }
}

#[derive(Deserialize, Clone)]
pub struct ErrorResponse {
    pub error: String,
}
