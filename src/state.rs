use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::fmt::{Display, Formatter, Result as FmtResult, Write as FmtWrite};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};
use tracing::{debug, trace};
use treetop_core::{LabelRegistryBuilder, Labeler, PolicyEngine, RegexLabeler};
use utoipa::ToSchema;

use crate::{errors::ServiceError, models::{Endpoint, UserPolicies}};

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

/// Parse labels from JSON and return them as a vector of labelers.
///
/// The format of the JSON is expected to be an array of objects, each with a "kind", "field", "output" and "patterns" field.
pub fn parse_labels(content: &str) -> Result<Vec<Arc<dyn Labeler>>, ServiceError> {
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

    Ok(labels_for_registry)
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
        // Validate that the labels can be parsed
        parse_labels(content)?;
        Ok(())
    }
}

pub struct PolicyStore {
    pub engine: Arc<PolicyEngine>,
    pub allow_upload: bool,
    pub upload_token: Option<String>,

    pub policies: Metadata<OfPolicies>,
    pub labels: Metadata<OfLabels>,
    pub label_registry_labelers: Vec<Arc<dyn Labeler>>,
    list_policies_raw_cache: HashMap<ListPoliciesCacheKey, String>,
    list_policies_raw_lru: VecDeque<ListPoliciesCacheKey>,
    list_policies_json_cache: HashMap<ListPoliciesCacheKey, UserPolicies>,
    list_policies_json_lru: VecDeque<ListPoliciesCacheKey>,
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
            label_registry_labelers: Vec::new(),
            list_policies_raw_cache: HashMap::new(),
            list_policies_raw_lru: VecDeque::new(),
            list_policies_json_cache: HashMap::new(),
            list_policies_json_lru: VecDeque::new(),
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
            label_registry_labelers: Vec::new(),
            list_policies_raw_cache: HashMap::new(),
            list_policies_raw_lru: VecDeque::new(),
            list_policies_json_cache: HashMap::new(),
            list_policies_json_lru: VecDeque::new(),
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

        let mut engine = PolicyEngine::new_from_str(dsl)?;

        // Apply labels to the new engine if we have any
        if !self.label_registry_labelers.is_empty() {
            let mut builder = LabelRegistryBuilder::new();
            for labeler in &self.label_registry_labelers {
                builder = builder.add_labeler(Arc::clone(labeler));
            }
            engine = engine.with_label_registry(builder.build());
        }

        self.engine = Arc::new(engine);
        self.policies = metadata;
        self.clear_list_policies_cache();
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

        // Parse and store the labelers
        self.label_registry_labelers = parse_labels(labels)?;

        // Re-apply labels to the engine
        if !self.label_registry_labelers.is_empty() {
            let mut builder = LabelRegistryBuilder::new();
            for labeler in &self.label_registry_labelers {
                builder = builder.add_labeler(Arc::clone(labeler));
            }
            let mut engine = PolicyEngine::new_from_str(&self.policies.content)?;
            engine = engine.with_label_registry(builder.build());
            self.engine = Arc::new(engine);
        }

        self.labels = metadata;
        self.clear_list_policies_cache();
        Ok(())
    }

    pub fn list_policies_raw(
        &mut self,
        user: String,
        mut groups: Vec<String>,
        mut namespaces: Vec<String>,
    ) -> Result<String, ServiceError> {
        normalize_list_filters(&mut groups, &mut namespaces);
        let key = ListPoliciesCacheKey::new(user, groups, namespaces);
        if let Some(cached) = self.list_policies_raw_cache.get(&key) {
            touch_lru(&mut self.list_policies_raw_lru, &key);
            return Ok(cached.clone());
        }

        let policies = self.list_policies_for_key(&key)?;
        let content = format_policies_raw(&policies);
        cache_insert(
            &mut self.list_policies_raw_cache,
            &mut self.list_policies_raw_lru,
            key,
            content.clone(),
        );
        Ok(content)
    }

    pub fn list_policies_json(
        &mut self,
        user: String,
        mut groups: Vec<String>,
        mut namespaces: Vec<String>,
    ) -> Result<UserPolicies, ServiceError> {
        normalize_list_filters(&mut groups, &mut namespaces);
        let key = ListPoliciesCacheKey::new(user, groups, namespaces);
        if let Some(cached) = self.list_policies_json_cache.get(&key) {
            touch_lru(&mut self.list_policies_json_lru, &key);
            return Ok(cached.clone());
        }

        let policies = self.list_policies_for_key(&key)?;
        let response = UserPolicies::from(policies);
        cache_insert(
            &mut self.list_policies_json_cache,
            &mut self.list_policies_json_lru,
            key,
            response.clone(),
        );
        Ok(response)
    }

    fn list_policies_for_key(
        &self,
        key: &ListPoliciesCacheKey,
    ) -> Result<treetop_core::UserPolicies, ServiceError> {
        let namespace: Vec<&str> = key.namespaces.iter().map(|s| s.as_str()).collect();
        let group_refs: Vec<&str> = key.groups.iter().map(|s| s.as_str()).collect();
        Ok(self
            .engine
            .list_policies_for_user(&key.user, &group_refs, &namespace)?)
    }

    fn clear_list_policies_cache(&mut self) {
        self.list_policies_raw_cache.clear();
        self.list_policies_raw_lru.clear();
        self.list_policies_json_cache.clear();
        self.list_policies_json_lru.clear();
    }
}

pub type SharedPolicyStore = Arc<Mutex<PolicyStore>>;

const LIST_POLICIES_CACHE_LIMIT: usize = 128;

#[derive(Clone, Hash, Eq, PartialEq)]
struct ListPoliciesCacheKey {
    user: String,
    groups: Vec<String>,
    namespaces: Vec<String>,
}

impl ListPoliciesCacheKey {
    fn new(user: String, groups: Vec<String>, namespaces: Vec<String>) -> Self {
        Self {
            user,
            groups,
            namespaces,
        }
    }
}

fn format_policies_raw(policies: &treetop_core::UserPolicies) -> String {
    let mut content = String::new();
    for (index, policy) in policies.policies().iter().enumerate() {
        if index > 0 {
            content.push('\n');
        }
        let _ = write!(content, "{policy}");
    }
    content
}

fn touch_lru(lru: &mut VecDeque<ListPoliciesCacheKey>, key: &ListPoliciesCacheKey) {
    if let Some(pos) = lru.iter().position(|k| k == key) {
        lru.remove(pos);
        lru.push_back(key.clone());
    }
}

fn cache_insert<V>(
    cache: &mut HashMap<ListPoliciesCacheKey, V>,
    lru: &mut VecDeque<ListPoliciesCacheKey>,
    key: ListPoliciesCacheKey,
    value: V,
) {
    if cache.contains_key(&key) {
        cache.insert(key.clone(), value);
        touch_lru(lru, &key);
        return;
    }

    if lru.len() >= LIST_POLICIES_CACHE_LIMIT {
        if let Some(evicted) = lru.pop_front() {
            cache.remove(&evicted);
        }
    }

    lru.push_back(key.clone());
    cache.insert(key, value);
}

fn normalize_list_filters(groups: &mut Vec<String>, namespaces: &mut Vec<String>) {
    groups.sort_unstable();
    groups.dedup();
    namespaces.sort_unstable();
    namespaces.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Endpoint;
    use std::str::FromStr;
    use serde_json::Value;

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
        assert!(store.label_registry_labelers.is_empty());
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

    #[test]
    fn test_list_policies_raw_matches_engine() {
        let mut store = PolicyStore::new().unwrap();
        let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);

permit (
    principal == User::"bob",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;
        store.set_dsl(dsl, None, None).unwrap();

        let expected = store
            .engine
            .list_policies_for_user("alice", &[], &[])
            .unwrap();
        let expected_raw = format_policies_raw(&expected);
        let raw = store
            .list_policies_raw("alice".to_string(), vec![], vec![])
            .unwrap();

        assert_eq!(raw, expected_raw);
    }

    #[test]
    fn test_list_policies_json_matches_engine() {
        let mut store = PolicyStore::new().unwrap();
        let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);

permit (
    principal == User::"bob",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;
        store.set_dsl(dsl, None, None).unwrap();

        let expected = store
            .engine
            .list_policies_for_user("alice", &[], &[])
            .unwrap();
        let expected_json = UserPolicies::from(expected);
        let response = store
            .list_policies_json("alice".to_string(), vec![], vec![])
            .unwrap();

        let expected_value = serde_json::to_value(expected_json).unwrap_or(Value::Null);
        let response_value = serde_json::to_value(response).unwrap_or(Value::Null);
        assert_eq!(response_value, expected_value);
    }

    #[test]
    fn test_list_policies_cache_cleared_on_set_dsl() {
        let mut store = PolicyStore::new().unwrap();
        let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;
        store.set_dsl(dsl, None, None).unwrap();
        let _ = store
            .list_policies_raw("alice".to_string(), vec![], vec![])
            .unwrap();
        let _ = store
            .list_policies_json("alice".to_string(), vec![], vec![])
            .unwrap();

        assert_eq!(store.list_policies_raw_cache.len(), 1);
        assert_eq!(store.list_policies_json_cache.len(), 1);

        let updated = r#"
permit (
    principal == User::"alice",
    action == Action::"edit",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;
        store.set_dsl(updated, None, None).unwrap();

        assert!(store.list_policies_raw_cache.is_empty());
        assert!(store.list_policies_json_cache.is_empty());
    }

    #[test]
    fn test_list_policies_cache_normalizes_groups_and_namespaces() {
        let mut store = PolicyStore::new().unwrap();
        let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;
        store.set_dsl(dsl, None, None).unwrap();

        let _ = store
            .list_policies_raw(
                "alice".to_string(),
                vec!["admins".to_string(), "users".to_string()],
                vec!["Team".to_string(), "Org".to_string()],
            )
            .unwrap();

        let _ = store
            .list_policies_raw(
                "alice".to_string(),
                vec![
                    "users".to_string(),
                    "admins".to_string(),
                    "admins".to_string(),
                ],
                vec!["Org".to_string(), "Org".to_string(), "Team".to_string()],
            )
            .unwrap();

        assert_eq!(store.list_policies_raw_cache.len(), 1);
    }
}
