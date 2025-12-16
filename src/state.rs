use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use tracing::{debug, trace};
use treetop_core::{LABEL_REGISTRY, Labeler, PolicyEngine, RegexLabeler};
use utoipa::ToSchema;

use crate::{errors::ServiceError, models::Endpoint};

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OfPolicies;
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct OfLabels;

pub trait MetadataParser {
    /// Count the number of entries in the content.
    fn count_entries(content: &str) -> Result<usize, ServiceError>;

    /// Return the size of the content in bytes.
    fn content_size(content: &str) -> usize {
        content.len()
    }

    /// Validate the content, by default does nothing.
    fn validate_content(_: &str) -> Result<(), ServiceError> {
        Ok(())
    }

    /// Make a sha256 hash of the content.
    fn make_hash(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Process the content after parsing, by default does nothing.
    fn process_content(_: &str) -> Result<(), ServiceError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Metadata<T> {
    pub timestamp: DateTime<Utc>,
    pub sha256: String,
    pub size: usize,
    pub source: Option<Endpoint>,
    pub refresh_frequency: Option<u32>,
    pub entries: usize,
    pub content: String,
    #[serde(skip)]
    _marker: PhantomData<T>,
}

impl<T> Display for Metadata<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let source = match &self.source {
            Some(s) => s.as_str(),
            None => "None",
        };

        let refresh = match self.refresh_frequency {
            Some(freq) => freq.to_string(),
            None => "None".into(),
        };

        write!(
            f,
            "   source: {}
   timestamp: {}
   sha256: {}
   size: {}
   refresh_frequency: {}
   entries: {}",
            source, self.timestamp, self.sha256, self.size, refresh, self.entries,
        )
    }
}

impl<T: MetadataParser> Metadata<T> {
    pub fn new(
        content: String,
        source: Option<Endpoint>,
        refresh_frequency: Option<u32>,
    ) -> Result<Self, ServiceError> {
        if content.is_empty() && source.is_none() && refresh_frequency.is_none() {
            return Ok(Metadata {
                timestamp: Utc::now(),
                sha256: String::new(),
                size: 0,
                source,
                refresh_frequency,
                entries: 0,
                content: String::new(),
                _marker: PhantomData,
            });
        }

        T::validate_content(&content)?;

        let sha256 = T::make_hash(&content);
        let size = T::content_size(&content);
        let entries = T::count_entries(&content)?;

        T::process_content(&content)?;

        if let Some(source) = source.clone() {
            debug!(
                update = "Metadata",
                source = source.to_string(),
                sha256 = sha256,
                size = size,
                entries = entries
            );
        }

        Ok(Metadata {
            timestamp: Utc::now(),
            sha256,
            size,
            source,
            refresh_frequency,
            entries,
            content,
            _marker: PhantomData,
        })
    }
}

#[derive(Deserialize)]
struct Label {
    kind: String,
    field: String,
    output: String,
    patterns: Vec<RawPattern>,
}

#[derive(Deserialize)]
struct RawPattern {
    name: String,
    regex: String,
}

/// Count the number of policy entries in the content.
///
/// The content is expected to be in the policy DSL format.
impl MetadataParser for OfPolicies {
    fn count_entries(content: &str) -> Result<usize, ServiceError> {
        Ok(content
            .lines()
            .filter(|line| line.starts_with("permit (") || line.starts_with("forbid ("))
            .count())
    }
}

/// Count the number of host labels in the content.
///
/// The format of the JSON is expected to be an array of objects, each with a "name" and "regex" field.
/// Example:
/// ```json
/// [
///     { "name": "example.com", "regex": "^example\\.com$" },
///     { "name": "test.com", "regex": "^test\\.com$" }
/// ]
/// ```
impl MetadataParser for OfLabels {
    fn count_entries(content: &str) -> Result<usize, ServiceError> {
        let raw: Vec<Label> = serde_json::from_str(content)?;
        Ok(raw.len())
    }

    fn process_content(content: &str) -> Result<(), ServiceError> {
        let labels: Vec<Label> = serde_json::from_str(content)?;

        let mut labels_for_registry: Vec<Arc<dyn Labeler>> = Vec::new();

        for label in labels {
            let mut patterns: Vec<(String, Regex)> = Vec::new();

            for r in &label.patterns {
                if r.name.is_empty() || r.regex.is_empty() {
                    tracing::error!(
                        message = "Invalid pattern: name or regex is empty",
                        name = &r.name,
                        regex = &r.regex
                    );
                    return Err(ServiceError::InvalidJsonPayload(
                        "Invalid pattern: name or regex is empty".to_string(),
                    ));
                }

                let regex = match Regex::new(&r.regex) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(
                            message = "Invalid regex in pattern",
                            name = &r.name,
                            regex = &r.regex,
                            error = %e
                        );
                        return Err(ServiceError::InvalidJsonPayload(format!(
                            "Invalid regex in pattern: {e}"
                        )));
                    }
                };

                patterns.push((r.name.clone(), regex));
            }

            debug!(
                update = "Updating pattern",
                kind = label.kind,
                field = label.field,
                output = label.output,
                count = patterns.len()
            );
            trace!(patterns = ?patterns);

            labels_for_registry.push(Arc::new(RegexLabeler::new(
                label.kind,
                label.field,
                label.output,
                patterns,
            )));
        }

        LABEL_REGISTRY.load(labels_for_registry);

        Ok(())
    }
}

pub struct PolicyStore {
    pub engine: Arc<PolicyEngine>,
    pub allow_upload: bool,
    pub upload_token: Option<String>,

    pub policies: Metadata<OfPolicies>,
    pub labels: Metadata<OfLabels>,
}

impl Default for PolicyStore {
    fn default() -> Self {
        Self {
            engine: Arc::new(
                PolicyEngine::new_from_str("").expect("Failed to initialize policy engine"),
            ),
            allow_upload: false,
            upload_token: None,
            policies: Metadata::<OfPolicies>::new(String::new(), None, None).unwrap(),
            labels: Metadata::<OfLabels>::new(String::new(), None, None).unwrap(),
        }
    }
}

impl PolicyStore {
    /// Create a new PolicyStore initialized with the given DSL string.
    pub fn new() -> Result<Self, ServiceError> {
        Ok(Self {
            engine: Arc::new(
                PolicyEngine::new_from_str("").expect("Failed to initialize policy engine"),
            ),
            allow_upload: false,
            upload_token: None,
            policies: Metadata::<OfPolicies>::new(String::new(), None, None)?,
            labels: Metadata::<OfLabels>::new(String::new(), None, None)?,
        })
    }

    pub fn set_dsl(
        &mut self,
        dsl: &str,
        source: Option<Endpoint>,
        refresh_frequency: Option<u32>,
    ) -> Result<(), ServiceError> {
        let old_metadata = self.policies.clone();
        let source = source.or(old_metadata.source);
        let refresh_frequency = refresh_frequency.or(old_metadata.refresh_frequency);

        let metadata = Metadata::<OfPolicies>::new(dsl.to_string(), source, refresh_frequency)?;

        self.engine = Arc::new(PolicyEngine::new_from_str(dsl)?);
        self.policies = metadata;
        Ok(())
    }

    pub fn set_labels(
        &mut self,
        labels: &str,
        source: Option<Endpoint>,
        refresh_frequency: Option<u32>,
    ) -> Result<(), ServiceError> {
        let old_metadata = self.labels.clone();
        let source = source.or(old_metadata.source);
        let refresh_frequency = refresh_frequency.or(old_metadata.refresh_frequency);

        let metadata = Metadata::<OfLabels>::new(labels.to_string(), source, refresh_frequency)?;
        self.labels = metadata;
        Ok(())
    }
}

pub type SharedPolicyStore = Arc<Mutex<PolicyStore>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Endpoint;
    use std::str::FromStr;

    #[test]
    fn test_metadata_empty() {
        let metadata = Metadata::<OfPolicies>::new(String::new(), None, None).unwrap();
        assert_eq!(metadata.size, 0);
        assert_eq!(metadata.entries, 0);
        assert!(metadata.content.is_empty());
        assert!(metadata.sha256.is_empty());
    }

    #[test]
    fn test_metadata_policies_count() {
        let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"photo.jpg"
);

forbid (
    principal == User::"bob",
    action == Action::"delete",
    resource == Photo::"photo.jpg"
);
"#;
        let metadata = Metadata::<OfPolicies>::new(dsl.to_string(), None, None).unwrap();
        assert_eq!(metadata.entries, 2);
        assert_eq!(metadata.size, dsl.len());
        assert!(!metadata.sha256.is_empty());
    }

    #[test]
    fn test_metadata_with_source() {
        let dsl = "permit (principal, action, resource);";
        let endpoint = Endpoint::from_str("https://example.com/policies").unwrap();
        let metadata =
            Metadata::<OfPolicies>::new(dsl.to_string(), Some(endpoint.clone()), Some(60)).unwrap();

        assert_eq!(metadata.entries, 1);
        assert_eq!(
            metadata.source.unwrap().as_str(),
            "https://example.com/policies"
        );
        assert_eq!(metadata.refresh_frequency, Some(60));
    }

    #[test]
    fn test_metadata_labels_valid() {
        let labels_json = r#"[
    {
        "kind": "Host",
        "field": "name",
        "output": "nameLabels",
        "patterns": [
            {
                "name": "example_domain",
                "regex": "example\\.com$"
            }
        ]
    }
]"#;
        let metadata = Metadata::<OfLabels>::new(labels_json.to_string(), None, None).unwrap();
        assert_eq!(metadata.entries, 1);
        assert!(!metadata.sha256.is_empty());
    }

    #[test]
    fn test_metadata_labels_invalid_json() {
        let invalid_json = "{ not valid json }";
        let result = Metadata::<OfLabels>::new(invalid_json.to_string(), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_metadata_labels_empty_pattern() {
        let labels_json = r#"[
    {
        "kind": "Host",
        "field": "name",
        "output": "nameLabels",
        "patterns": [
            {
                "name": "",
                "regex": "test"
            }
        ]
    }
]"#;
        let result = Metadata::<OfLabels>::new(labels_json.to_string(), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_metadata_labels_invalid_regex() {
        let labels_json = r#"[
    {
        "kind": "Host",
        "field": "name",
        "output": "nameLabels",
        "patterns": [
            {
                "name": "bad_pattern",
                "regex": "[invalid(regex"
            }
        ]
    }
]"#;
        let result = Metadata::<OfLabels>::new(labels_json.to_string(), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_store_default() {
        let store = PolicyStore::default();
        assert!(!store.allow_upload);
        assert!(store.upload_token.is_none());
        assert_eq!(store.policies.entries, 0);
        assert_eq!(store.labels.entries, 0);
    }

    #[test]
    fn test_policy_store_new() {
        let store = PolicyStore::new().unwrap();
        assert!(!store.allow_upload);
        assert!(store.upload_token.is_none());
        assert_eq!(store.policies.entries, 0);
    }

    #[test]
    fn test_policy_store_set_dsl() {
        let mut store = PolicyStore::new().unwrap();
        let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"photo.jpg"
);
"#;
        let result = store.set_dsl(dsl, None, None);
        assert!(result.is_ok());
        assert_eq!(store.policies.entries, 1);
        assert_eq!(store.policies.content, dsl);
    }

    #[test]
    fn test_policy_store_set_dsl_invalid() {
        let mut store = PolicyStore::new().unwrap();
        let invalid_dsl = "this is not valid Cedar DSL";
        let result = store.set_dsl(invalid_dsl, None, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_store_set_labels() {
        let mut store = PolicyStore::new().unwrap();
        let labels_json = r#"[
    {
        "kind": "Host",
        "field": "name",
        "output": "nameLabels",
        "patterns": [
            {
                "name": "example",
                "regex": "example\\.com$"
            }
        ]
    }
]"#;
        let result = store.set_labels(labels_json, None, None);
        assert!(result.is_ok());
        assert_eq!(store.labels.entries, 1);
    }

    #[test]
    fn test_policy_store_preserves_source() {
        let mut store = PolicyStore::new().unwrap();
        let endpoint = Endpoint::from_str("https://example.com/policies").unwrap();

        // Set initial DSL with source
        let dsl1 = "permit (principal, action, resource);";
        store
            .set_dsl(dsl1, Some(endpoint.clone()), Some(60))
            .unwrap();

        assert_eq!(
            store.policies.source.as_ref().unwrap().as_str(),
            "https://example.com/policies"
        );
        assert_eq!(store.policies.refresh_frequency, Some(60));

        // Update DSL without providing source - should preserve it
        let dsl2 = "forbid (principal, action, resource);";
        store.set_dsl(dsl2, None, None).unwrap();

        assert_eq!(
            store.policies.source.as_ref().unwrap().as_str(),
            "https://example.com/policies"
        );
        assert_eq!(store.policies.refresh_frequency, Some(60));
    }

    #[test]
    fn test_metadata_display() {
        let dsl = "permit (principal, action, resource);";
        let endpoint = Endpoint::from_str("https://example.com/api").unwrap();
        let metadata =
            Metadata::<OfPolicies>::new(dsl.to_string(), Some(endpoint), Some(120)).unwrap();

        let display = format!("{}", metadata);
        assert!(display.contains("https://example.com/api"));
        assert!(display.contains("120"));
        assert!(display.contains(&metadata.sha256));
    }
}
