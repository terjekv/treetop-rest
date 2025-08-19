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
