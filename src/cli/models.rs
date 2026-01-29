use std::{fmt, net::IpAddr, str::FromStr};

use colored::*;
use serde::{Deserialize, Serialize};
use tabled::{Table, Tabled, settings::Style};
use treetop_core::AttrValue;

use crate::cli::style::{error, success, warning};
use crate::models::{CheckResponse, CheckResponseBrief, DecisionBrief, PoliciesMetadata};
use crate::state::{Metadata, OfPolicies};

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
pub enum TableStyle {
    Ascii,
    #[default]
    Rounded,
    Unicode,
    Markdown,
}

impl std::str::FromStr for TableStyle {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ascii" => Ok(TableStyle::Ascii),
            "rounded" => Ok(TableStyle::Rounded),
            "unicode" => Ok(TableStyle::Unicode),
            "markdown" => Ok(TableStyle::Markdown),
            _ => Err(format!("unknown table style: {}", s)),
        }
    }
}

impl std::fmt::Display for TableStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TableStyle::Ascii => write!(f, "ascii"),
            TableStyle::Rounded => write!(f, "rounded"),
            TableStyle::Unicode => write!(f, "unicode"),
            TableStyle::Markdown => write!(f, "markdown"),
        }
    }
}

impl TableStyle {
    pub fn apply_to_table(&self, mut table: Table) -> Table {
        match self {
            TableStyle::Ascii => { table.with(Style::ascii()); },
            TableStyle::Rounded => { table.with(Style::rounded()); },
            TableStyle::Unicode => { table.with(Style::modern()); },
            TableStyle::Markdown => { table.with(Style::markdown()); },
        }
        table
    }
}

#[derive(Default, Clone)]
pub struct LastUsedValues {
    pub principal: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub attrs: Vec<(String, InputAttrValue)>,
    pub table_style: TableStyle,
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
        format!(
            "Metadata:\n{}\nContent:\n{}",
            self.policies, self.policies.content
        )
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

/// Union type for authorization check results (Brief or Detailed)
#[derive(Clone)]
pub enum AuthCheckResult {
    Brief(CheckResponseBrief),
    Detailed(CheckResponse),
}

impl<'de> serde::Deserialize<'de> for AuthCheckResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = serde_json::Value::deserialize(deserializer)?;

        // Try detailed first (has 'policy' field which is unique to CheckResponse)
        if let Ok(detailed) = serde_json::from_value::<CheckResponse>(v.clone()) {
            return Ok(AuthCheckResult::Detailed(detailed));
        }

        // Fall back to brief
        if let Ok(brief) = serde_json::from_value::<CheckResponseBrief>(v) {
            return Ok(AuthCheckResult::Brief(brief));
        }

        Err(serde::de::Error::custom(
            "Could not deserialize as CheckResponse or CheckResponseBrief",
        ))
    }
}

#[derive(Deserialize)]
pub struct AuthorizeResult {
    pub results: Vec<SingleResult>,
}

#[derive(Deserialize)]
pub struct SingleResult {
    pub index: usize,
    pub id: Option<String>,
    pub status: String,
    #[serde(default)]
    pub result: Option<AuthCheckResult>,
    pub error: Option<String>,
}

/// Table representation of a single result for displaying multiple results
#[derive(Tabled)]
struct ResultRow {
    #[tabled(rename = "#")]
    index: String,
    #[tabled(rename = "QID")]
    id: String,
    #[tabled(rename = "Status")]
    status: String,
    #[tabled(rename = "Decision")]
    decision: String,
    #[tabled(rename = "PolicyID")]
    policy: String,
}

impl CliDisplay for AuthCheckResult {
    fn display(&self) -> String {
        match self {
            AuthCheckResult::Detailed(detailed) => detailed.display(),
            AuthCheckResult::Brief(brief) => brief.display(),
        }
    }
}

impl AuthorizeResult {
    /// Display as a table with the specified style
    pub fn display_as_table_with_style(&self, style: TableStyle) -> String {
        if self.results.is_empty() {
            return warning("Warning: No results in response").to_string();
        }

        // Extract version - should be the same for all results
        let version = self
            .results
            .first()
            .and_then(|r| match &r.result {
                Some(AuthCheckResult::Detailed(detailed)) => Some(detailed.version.hash.clone()),
                Some(AuthCheckResult::Brief(brief)) => Some(brief.version.hash.clone()),
                None => None,
            })
            .unwrap_or_else(|| "-".to_string());

        let rows: Vec<ResultRow> = self
            .results
            .iter()
            .map(|r| self.result_to_row(r, false))
            .collect();

        let table = Table::new(rows);
        let styled_table = style.apply_to_table(table);
        let table_str = styled_table.to_string();
        format!("Version: {}\n{}", version, table_str)
    }

    /// Display as a table regardless of result count (without colors) - uses default ASCII style
    pub fn display_as_table(&self) -> String {
        self.display_as_table_with_style(TableStyle::default())
    }

    /// Extract policy @id from the policy literal text
    fn extract_policy_id(policy_literal: &str) -> String {
        // Look for pattern: @id("...") or @id("...", ...)
        if let Some(start) = policy_literal.find("@id(\"") {
            let offset = start + 5; // Skip "@id(\""
            if let Some(end) = policy_literal[offset..].find('"') {
                return policy_literal[offset..offset + end].to_string();
            }
        }
        "-".to_string()
    }

    /// Convert a single result to a table row
    fn result_to_row(&self, r: &SingleResult, use_colors: bool) -> ResultRow {
        let decision_str = match (&r.result, &r.error) {
            (Some(auth_result), _) => match auth_result {
                AuthCheckResult::Detailed(detailed) => match detailed.desicion {
                    DecisionBrief::Allow => {
                        if use_colors {
                            success("Allow").to_string()
                        } else {
                            "Allow".to_string()
                        }
                    }
                    DecisionBrief::Deny => {
                        if use_colors {
                            error("Deny").to_string()
                        } else {
                            "Deny".to_string()
                        }
                    }
                },
                AuthCheckResult::Brief(brief) => match brief.decision {
                    DecisionBrief::Allow => {
                        if use_colors {
                            success("Allow").to_string()
                        } else {
                            "Allow".to_string()
                        }
                    }
                    DecisionBrief::Deny => {
                        if use_colors {
                            error("Deny").to_string()
                        } else {
                            "Deny".to_string()
                        }
                    }
                },
            },
            (None, Some(err)) => {
                if use_colors {
                    error(err).to_string()
                } else {
                    err.clone()
                }
            }
            (None, None) => "-".to_string(),
        };

        let policy_id = match &r.result {
            Some(AuthCheckResult::Detailed(detailed)) => {
                if let Some(policy) = &detailed.policy {
                    Self::extract_policy_id(&policy.literal)
                } else {
                    "-".to_string()
                }
            }
            _ => "-".to_string(),
        };

        ResultRow {
            index: r.index.to_string(),
            id: r.id.as_deref().unwrap_or("-").to_string(),
            status: r.status.clone(),
            decision: decision_str,
            policy: policy_id,
        }
    }
}

impl CliDisplay for AuthorizeResult {
    fn display(&self) -> String {
        match self.results.len() {
            0 => warning("Warning: No results in response").to_string(),
            1 => {
                // Single result - display with full detail
                let result = &self.results[0];
                if result.status == "success" {
                    if let Some(auth_result) = &result.result {
                        auth_result.display()
                    } else {
                        "Success: no result data".to_string()
                    }
                } else {
                    format!(
                        "{}: {}",
                        error("Failed"),
                        result
                            .error
                            .as_ref()
                            .unwrap_or(&"Unknown error".to_string())
                    )
                }
            }
            _ => self.display_as_table_with_style(TableStyle::default()),
        }
    }
}
