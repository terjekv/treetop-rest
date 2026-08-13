use std::fmt::Write as _;
use std::hash::Hash;
use std::sync::{Arc, OnceLock};

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
    match action_id.parse::<EntityUid>() {
        Ok(action) => format!(
            "{}::{}",
            action.type_name(),
            metric_label_component(action.id().unescaped())
        ),
        Err(_) => metric_label_component(action_id),
    }
}

fn metric_label_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());

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

    encoded
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
        }
    }

    fn observe_phase(&self, action: &str, phase: &'static str, duration_ms: f64) {
        self.eval_phase_duration_seconds
            .get_or_create_owned(&EvaluationPhaseLabels {
                action: action.to_owned(),
                phase,
            })
            .observe(duration_ms / 1_000.0);
    }
}

impl MetricsSink for PrometheusMetricsSink {
    fn on_evaluation(&self, stats: &EvaluationStats) {
        let labels = ActionLabels {
            action: metric_action_id(&stats.action_id),
        };
        self.evals_total.get_or_create_owned(&labels).inc();
        if stats.allowed {
            self.evals_allowed.get_or_create_owned(&labels).inc();
        } else {
            self.evals_denied.get_or_create_owned(&labels).inc();
        }
        self.eval_duration_seconds
            .get_or_create_owned(&labels)
            .observe(stats.duration.as_secs_f64());
    }

    fn on_evaluation_phases(&self, stats: &EvaluationStats, phases: &EvaluationPhases) {
        let action = metric_action_id(&stats.action_id);
        self.observe_phase(&action, "apply_labels", phases.apply_labels_ms);
        self.observe_phase(&action, "construct_entities", phases.construct_entities_ms);
        self.observe_phase(&action, "resolve_groups", phases.resolve_groups_ms);
        self.observe_phase(&action, "cedar_authorize", phases.authorize_ms);
        self.observe_phase(&action, "overhead", phases.overhead_ms());
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
            metric_action_id(r#"Action::"quote\"and%slash\\""#),
            "Action::quote%22and%25slash%5C"
        );
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
