use std::collections::HashMap;
use std::fmt::Write as _;
use std::hash::Hash;
use std::sync::{Arc, OnceLock, RwLock};

use cedar_policy::EntityUid;
use prometheus_client::encoding::{EncodeLabelSet, prometheus_protobuf, text};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::{Histogram, NativeHistogramConfig};
use prometheus_client::registry::{Registry, Unit};
use treetop_core::metrics::{EvaluationPhases, EvaluationStats, MetricsSink, ReloadStats};

use crate::build_info::build_info;

/// Classic histogram boundaries retained for text-format compatibility.
///
/// The list is a strict superset of the historical Prometheus defaults and adds
/// sub-millisecond resolution from 10 microseconds upward. Native-histogram
/// scrapers use the exponential schema configured separately below.
pub const LATENCY_BUCKETS: &[f64] = &[
    0.000_010, 0.000_025, 0.000_050, 0.000_100, 0.000_250, 0.000_500, 0.001, 0.002_5, 0.005, 0.010,
    0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0,
];

pub const NATIVE_HISTOGRAM_BUCKET_FACTOR: f64 = 1.1;
pub const NATIVE_HISTOGRAM_MAX_BUCKETS: usize = 160;

pub const OPENMETRICS_CONTENT_TYPE: &str =
    "application/openmetrics-text; version=1.0.0; charset=utf-8";
pub const PROMETHEUS_PROTOBUF_CONTENT_TYPE: &str =
    "application/vnd.google.protobuf; proto=io.prometheus.client.MetricFamily; encoding=delimited";

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct HttpRequestLabels {
    method: String,
    path: String,
    status_code: u16,
    client_ip: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct HttpDurationLabels {
    method: String,
    path: String,
    status_code: u16,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ReasonLabels {
    reason: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ActionLabels {
    action: String,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct EvaluationPhaseLabels {
    action: String,
    phase: &'static str,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BuildInfoLabels {
    app_version: String,
    core_version: String,
    cedar_version: String,
}

type DurationFamily<L> = Family<L, Histogram, fn() -> Histogram>;

struct EvaluationPhaseMetric {
    labels: EvaluationPhaseLabels,
    histogram: OnceLock<Histogram>,
}

impl EvaluationPhaseMetric {
    fn new(action: &str, phase: &'static str) -> Self {
        Self {
            labels: EvaluationPhaseLabels {
                action: action.to_owned(),
                phase,
            },
            histogram: OnceLock::new(),
        }
    }
}

struct ActionMetrics {
    labels: ActionLabels,
    evals_total: OnceLock<Counter>,
    evals_allowed: OnceLock<Counter>,
    evals_denied: OnceLock<Counter>,
    eval_duration_seconds: OnceLock<Histogram>,
    phases: [EvaluationPhaseMetric; 5],
}

impl ActionMetrics {
    fn new(action: String) -> Self {
        Self {
            phases: [
                EvaluationPhaseMetric::new(&action, "apply_labels"),
                EvaluationPhaseMetric::new(&action, "construct_entities"),
                EvaluationPhaseMetric::new(&action, "resolve_groups"),
                EvaluationPhaseMetric::new(&action, "cedar_authorize"),
                EvaluationPhaseMetric::new(&action, "overhead"),
            ],
            labels: ActionLabels { action },
            evals_total: OnceLock::new(),
            evals_allowed: OnceLock::new(),
            evals_denied: OnceLock::new(),
            eval_duration_seconds: OnceLock::new(),
        }
    }
}

fn duration_histogram() -> Histogram {
    Histogram::new_classic_and_native(
        LATENCY_BUCKETS.iter().copied(),
        NativeHistogramConfig::new(NATIVE_HISTOGRAM_BUCKET_FACTOR)
            .max_buckets(NATIVE_HISTOGRAM_MAX_BUCKETS),
    )
}

fn duration_family<L>() -> DurationFamily<L>
where
    L: Clone + Hash + Eq,
{
    Family::new_with_constructor(duration_histogram as fn() -> Histogram)
}

fn metric_action_id(action_id: &str) -> String {
    if let Some((type_name, entity_id)) = simple_entity_uid_parts(action_id) {
        let mut encoded = String::with_capacity(type_name.len() + entity_id.len() + 2);
        encoded.push_str(type_name);
        encoded.push_str("::");
        encode_metric_label_component(&mut encoded, entity_id);
        return encoded;
    }

    match action_id.parse::<EntityUid>() {
        Ok(action) => format!(
            "{}::{}",
            action.type_name(),
            metric_label_component(action.id().unescaped())
        ),
        Err(_) => metric_label_component(action_id),
    }
}

/// Split the canonical form emitted by `treetop_core::Action::to_string`
/// without invoking Cedar's general entity-UID parser for the common case.
/// Escaped IDs fall back to Cedar so this optimization cannot reinterpret an
/// escape sequence differently from the policy engine.
fn simple_entity_uid_parts(action_id: &str) -> Option<(&str, &str)> {
    let without_closing_quote = action_id.strip_suffix('"')?;
    let (type_name, entity_id) = without_closing_quote.rsplit_once("::\"")?;

    if !valid_cedar_type_name(type_name)
        || entity_id
            .chars()
            .any(|character| character == '\\' || character == '"' || character.is_control())
    {
        return None;
    }

    Some((type_name, entity_id))
}

fn valid_cedar_type_name(type_name: &str) -> bool {
    type_name.split("::").all(|component| {
        let mut bytes = component.bytes();
        bytes
            .next()
            .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
            && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
            && !matches!(
                component,
                "true"
                    | "false"
                    | "if"
                    | "then"
                    | "else"
                    | "in"
                    | "is"
                    | "like"
                    | "has"
                    | "__cedar"
            )
    })
}

fn metric_label_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());

    encode_metric_label_component(&mut encoded, value);
    encoded
}

fn encode_metric_label_component(encoded: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '%' => encoded.push_str("%25"),
            '"' => encoded.push_str("%22"),
            '\\' => encoded.push_str("%5C"),
            character if character.is_control() => {
                let mut bytes = [0; 4];
                for byte in character.encode_utf8(&mut bytes).bytes() {
                    write!(encoded, "%{byte:02X}").expect("writing to a String cannot fail");
                }
            }
            character => encoded.push(character),
        }
    }
}

pub struct HttpMetrics {
    requests_total: Family<HttpRequestLabels, Counter>,
    request_duration_seconds: DurationFamily<HttpDurationLabels>,
}

impl HttpMetrics {
    pub fn new(registry: &mut Registry) -> Self {
        let requests_total = Family::default();
        let request_duration_seconds = duration_family();

        registry.register(
            "http_requests",
            "Total HTTP requests",
            requests_total.clone(),
        );
        registry.register_with_unit(
            "http_request_duration",
            "Server-side HTTP request handling latency",
            Unit::Seconds,
            request_duration_seconds.clone(),
        );

        Self {
            requests_total,
            request_duration_seconds,
        }
    }

    pub fn observe(
        &self,
        method: &str,
        path: &str,
        status_code: u16,
        client_ip: Option<&str>,
        duration_secs: f64,
    ) {
        self.requests_total
            .get_or_create_owned(&HttpRequestLabels {
                method: method.to_owned(),
                path: path.to_owned(),
                status_code,
                client_ip: client_ip.unwrap_or("").to_owned(),
            })
            .inc();

        self.request_duration_seconds
            .get_or_create_owned(&HttpDurationLabels {
                method: method.to_owned(),
                path: path.to_owned(),
                status_code,
            })
            .observe(duration_secs);
    }
}

static HTTP_METRICS: OnceLock<Arc<HttpMetrics>> = OnceLock::new();

pub fn http_metrics() -> Arc<HttpMetrics> {
    HTTP_METRICS
        .get()
        .expect("HTTP metrics not initialized")
        .clone()
}

pub struct ServiceMetrics {
    schema_reloads_total: Counter,
    schema_validation_failures_total: Family<ReasonLabels, Counter>,
    context_validation_failures_total: Family<ReasonLabels, Counter>,
}

impl ServiceMetrics {
    pub fn new(registry: &mut Registry) -> Self {
        let schema_reloads_total = Counter::default();
        let schema_validation_failures_total = Family::default();
        let context_validation_failures_total = Family::default();

        registry.register(
            "schema_reloads",
            "Total number of schema reloads",
            schema_reloads_total.clone(),
        );
        registry.register(
            "schema_validation_failures",
            "Total schema validation failures",
            schema_validation_failures_total.clone(),
        );
        registry.register(
            "context_validation_failures",
            "Total context validation failures",
            context_validation_failures_total.clone(),
        );

        Self {
            schema_reloads_total,
            schema_validation_failures_total,
            context_validation_failures_total,
        }
    }

    pub fn record_schema_reload(&self) {
        self.schema_reloads_total.inc();
    }

    pub fn record_schema_validation_failure(&self, reason: &str) {
        self.schema_validation_failures_total
            .get_or_create_owned(&ReasonLabels {
                reason: reason.to_owned(),
            })
            .inc();
    }

    pub fn record_context_validation_failure(&self, reason: &str) {
        self.context_validation_failures_total
            .get_or_create_owned(&ReasonLabels {
                reason: reason.to_owned(),
            })
            .inc();
    }
}

static SERVICE_METRICS: OnceLock<Arc<ServiceMetrics>> = OnceLock::new();

pub fn service_metrics() -> Option<Arc<ServiceMetrics>> {
    SERVICE_METRICS.get().cloned()
}

pub fn record_schema_reload() {
    if let Some(metrics) = service_metrics() {
        metrics.record_schema_reload();
    }
}

pub fn record_schema_validation_failure(reason: &str) {
    if let Some(metrics) = service_metrics() {
        metrics.record_schema_validation_failure(reason);
    }
}

pub fn record_context_validation_failure(reason: &str) {
    if let Some(metrics) = service_metrics() {
        metrics.record_context_validation_failure(reason);
    }
}

pub struct PrometheusMetricsSink {
    evals_total: Family<ActionLabels, Counter>,
    evals_allowed: Family<ActionLabels, Counter>,
    evals_denied: Family<ActionLabels, Counter>,
    eval_duration_seconds: DurationFamily<ActionLabels>,
    eval_phase_duration_seconds: DurationFamily<EvaluationPhaseLabels>,
    reloads_total: Counter,
    action_metrics: RwLock<HashMap<String, Arc<ActionMetrics>>>,
}

impl PrometheusMetricsSink {
    pub fn new(registry: &mut Registry) -> Self {
        let evals_total = Family::default();
        let evals_allowed = Family::default();
        let evals_denied = Family::default();
        let eval_duration_seconds = duration_family();
        let eval_phase_duration_seconds = duration_family();
        let reloads_total = Counter::default();

        registry.register(
            "policy_evals",
            "Total policy evaluations",
            evals_total.clone(),
        );
        registry.register(
            "policy_evals_allowed",
            "Allowed policy decisions",
            evals_allowed.clone(),
        );
        registry.register(
            "policy_evals_denied",
            "Denied policy decisions",
            evals_denied.clone(),
        );
        registry.register_with_unit(
            "policy_eval_duration",
            "Total policy evaluation latency including all core phases",
            Unit::Seconds,
            eval_duration_seconds.clone(),
        );
        registry.register_with_unit(
            "policy_eval_phase_duration",
            "Policy evaluation latency partitioned by core phase",
            Unit::Seconds,
            eval_phase_duration_seconds.clone(),
        );
        registry.register(
            "policy_reloads",
            "Total number of policy reloads",
            reloads_total.clone(),
        );

        Self {
            evals_total,
            evals_allowed,
            evals_denied,
            eval_duration_seconds,
            eval_phase_duration_seconds,
            reloads_total,
            action_metrics: RwLock::new(HashMap::new()),
        }
    }

    fn action_metrics(&self, action_id: &str) -> Arc<ActionMetrics> {
        // The Core action ID is stable for a bounded action vocabulary. Cache by
        // that raw value so steady-state observations do not need to reparse a
        // Cedar EntityUid merely to find their canonical Prometheus label.
        if let Some(metrics) = self
            .action_metrics
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(action_id)
        {
            return Arc::clone(metrics);
        }

        let metrics = Arc::new(ActionMetrics::new(metric_action_id(action_id)));
        let mut cached = self
            .action_metrics
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(cached.entry(action_id.to_owned()).or_insert(metrics))
    }

    fn observe_phase(&self, metric: &EvaluationPhaseMetric, duration_ms: f64) {
        metric
            .histogram
            .get_or_init(|| {
                self.eval_phase_duration_seconds
                    .get_or_create_owned(&metric.labels)
            })
            .observe(duration_ms / 1_000.0);
    }
}

impl MetricsSink for PrometheusMetricsSink {
    fn on_evaluation(&self, stats: &EvaluationStats) {
        let metrics = self.action_metrics(&stats.action_id);
        metrics
            .evals_total
            .get_or_init(|| self.evals_total.get_or_create_owned(&metrics.labels))
            .inc();
        if stats.allowed {
            metrics
                .evals_allowed
                .get_or_init(|| self.evals_allowed.get_or_create_owned(&metrics.labels))
                .inc();
        } else {
            metrics
                .evals_denied
                .get_or_init(|| self.evals_denied.get_or_create_owned(&metrics.labels))
                .inc();
        }
        metrics
            .eval_duration_seconds
            .get_or_init(|| {
                self.eval_duration_seconds
                    .get_or_create_owned(&metrics.labels)
            })
            .observe(stats.duration.as_secs_f64());
    }

    fn on_evaluation_phases(&self, stats: &EvaluationStats, phases: &EvaluationPhases) {
        let metrics = self.action_metrics(&stats.action_id);
        self.observe_phase(&metrics.phases[0], phases.apply_labels_ms);
        self.observe_phase(&metrics.phases[1], phases.construct_entities_ms);
        self.observe_phase(&metrics.phases[2], phases.resolve_groups_ms);
        self.observe_phase(&metrics.phases[3], phases.authorize_ms);
        self.observe_phase(&metrics.phases[4], phases.overhead_ms());
    }

    fn on_reload(&self, _stats: &ReloadStats) {
        self.reloads_total.inc();
    }
}

/// Build and register metrics, set the treetop-core sink, and expose build info.
pub fn init_prometheus() -> Result<Arc<Registry>, Box<dyn std::error::Error>> {
    let mut registry = Registry::default();

    let build = build_info();
    let build_info_metric: Family<BuildInfoLabels, Gauge> = Family::default();
    build_info_metric
        .get_or_create_owned(&BuildInfoLabels {
            app_version: build.version.clone(),
            core_version: build.core.clone(),
            cedar_version: build.cedar.to_string(),
        })
        .set(1);
    registry.register(
        "treetop_build_info",
        "Build and component versions",
        build_info_metric,
    );

    let sink = Arc::new(PrometheusMetricsSink::new(&mut registry));
    treetop_core::set_sink(sink);

    let http = Arc::new(HttpMetrics::new(&mut registry));
    let _ = HTTP_METRICS.set(http);

    let service = Arc::new(ServiceMetrics::new(&mut registry));
    let _ = SERVICE_METRICS.set(service);

    Ok(Arc::new(registry))
}

/// Encode all metrics as OpenMetrics 1.0 text, including classic histogram buckets.
pub fn encode_registry_text(registry: &Registry) -> Result<Vec<u8>, std::fmt::Error> {
    let mut body = String::new();
    text::encode(&mut body, registry)?;
    Ok(body.into_bytes())
}

/// Encode all metrics as delimited Prometheus protobuf, including native histograms.
pub fn encode_registry_protobuf(
    registry: &Registry,
) -> Result<Vec<u8>, prometheus_protobuf::EncodeError> {
    prometheus_protobuf::encode_to_vec(registry)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn evaluation_stats() -> EvaluationStats {
        EvaluationStats {
            duration: Duration::from_micros(250),
            allowed: true,
            action_id: r#"Action::"view""#.to_owned(),
            matched_policies: vec!["policy0".to_owned()],
        }
    }

    #[test]
    fn action_labels_are_canonical_and_collision_safe() {
        assert_eq!(metric_action_id(r#"Action::"view""#), "Action::view");
        assert_eq!(
            metric_action_id(r#"Infra::Core::Action::"view:album""#),
            "Infra::Core::Action::view:album"
        );
        assert_eq!(
            metric_action_id(r#"Action::"quote\"and%slash\\""#),
            "Action::quote%22and%25slash%5C"
        );
        assert_eq!(
            metric_action_id("Action::\"line\\nfeed\""),
            "Action::line%0Afeed"
        );
    }

    #[test]
    fn simple_action_label_path_only_accepts_unambiguous_cedar_uids() {
        assert_eq!(
            simple_entity_uid_parts(r#"Action::"view""#),
            Some(("Action", "view"))
        );
        assert_eq!(
            simple_entity_uid_parts(r#"Infra::Core::Action::"view:album""#),
            Some(("Infra::Core::Action", "view:album"))
        );

        for action_id in [
            r#"Action::"quote\"""#,
            "Action::\"line\\nfeed\"",
            r#"bad-type::"view""#,
            r#"if::"view""#,
            r#"Action::view"#,
        ] {
            assert_eq!(simple_entity_uid_parts(action_id), None, "{action_id}");
        }
    }

    #[test]
    fn classic_bucket_layout_is_the_exact_compatibility_superset() {
        assert_eq!(
            LATENCY_BUCKETS,
            &[
                0.000_010, 0.000_025, 0.000_050, 0.000_100, 0.000_250, 0.000_500, 0.001, 0.002_5,
                0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0,
            ]
        );
        for historical in [
            0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0, 10.0,
        ] {
            assert!(LATENCY_BUCKETS.contains(&historical));
        }
    }

    #[test]
    fn classic_histograms_include_sub_millisecond_boundaries() {
        let mut registry = Registry::default();
        let sink = PrometheusMetricsSink::new(&mut registry);
        sink.on_evaluation(&evaluation_stats());

        let text = String::from_utf8(encode_registry_text(&registry).unwrap()).unwrap();

        assert!(
            text.lines().any(|line| {
                line.starts_with("policy_eval_duration_seconds_bucket{")
                    && line.contains("le=\"0.00001\"")
                    && line.contains("action=\"Action::view\"")
            }),
            "{text}"
        );
        assert!(text.lines().any(|line| {
            line.starts_with("policy_eval_duration_seconds_bucket{")
                && line.contains("le=\"0.0005\"")
                && line.contains("action=\"Action::view\"")
        }));
    }

    #[test]
    fn phase_metrics_cover_every_core_phase_and_residual() {
        let mut registry = Registry::default();
        let sink = PrometheusMetricsSink::new(&mut registry);
        let stats = evaluation_stats();
        sink.on_evaluation(&stats);
        sink.on_evaluation_phases(
            &stats,
            &EvaluationPhases {
                apply_labels_ms: 0.01,
                construct_entities_ms: 0.02,
                resolve_groups_ms: 0.03,
                authorize_ms: 0.04,
                total_ms: 0.15,
            },
        );

        let text = String::from_utf8(encode_registry_text(&registry).unwrap()).unwrap();
        for phase in [
            "apply_labels",
            "construct_entities",
            "resolve_groups",
            "cedar_authorize",
            "overhead",
        ] {
            assert!(
                text.contains(&format!("phase=\"{phase}\"")),
                "missing phase {phase} in:\n{text}"
            );
        }
    }

    #[test]
    fn action_metric_handles_are_cached_across_core_callbacks() {
        let mut registry = Registry::default();
        let sink = PrometheusMetricsSink::new(&mut registry);
        let stats = evaluation_stats();
        let phases = EvaluationPhases {
            apply_labels_ms: 0.01,
            construct_entities_ms: 0.02,
            resolve_groups_ms: 0.03,
            authorize_ms: 0.04,
            total_ms: 0.15,
        };

        sink.on_evaluation(&stats);
        sink.on_evaluation_phases(&stats, &phases);
        sink.on_evaluation(&stats);
        sink.on_evaluation_phases(&stats, &phases);

        let cached = sink
            .action_metrics
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let metrics = cached.get(&stats.action_id).unwrap();
        assert_eq!(cached.len(), 1);
        assert_eq!(metrics.evals_total.get().unwrap().get(), 2);
        assert_eq!(metrics.evals_allowed.get().unwrap().get(), 2);
        assert!(metrics.evals_denied.get().is_none());
        assert!(metrics.eval_duration_seconds.get().is_some());
        assert!(
            metrics
                .phases
                .iter()
                .all(|phase| phase.histogram.get().is_some())
        );
    }

    #[test]
    fn protobuf_histograms_include_classic_and_native_buckets() {
        let mut registry = Registry::default();
        let sink = PrometheusMetricsSink::new(&mut registry);
        sink.on_evaluation(&evaluation_stats());

        let families = prometheus_protobuf::encode(&registry).unwrap();
        let family = families
            .iter()
            .find(|family| family.name == "policy_eval_duration_seconds")
            .unwrap();
        let histogram = family.metric[0].histogram.as_ref().unwrap();

        assert_eq!(histogram.bucket.len(), LATENCY_BUCKETS.len() + 1);
        assert!(!histogram.positive_span.is_empty());
        assert!(!histogram.positive_delta.is_empty());
    }
}
