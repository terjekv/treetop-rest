use std::sync::{Arc, OnceLock};

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGaugeVec, Registry,
    TextEncoder,
};
use treetop_core::metrics::{EvaluationStats, MetricsSink, ReloadStats};

use crate::build_info::build_info;

pub struct HttpMetrics {
    requests_total: IntCounterVec,
    request_duration_seconds: HistogramVec,
}

impl HttpMetrics {
    pub fn new(registry: &Registry) -> Result<Self, Box<dyn std::error::Error>> {
        let requests_total = IntCounterVec::new(
            prometheus::Opts::new("http_requests_total", "Total HTTP requests"),
            &["method", "path", "status_code", "client_ip"],
        )?;
        let request_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "http_request_duration_seconds",
                "HTTP request latency in seconds",
            ),
            &["method", "path", "status_code"],
        )?;

        registry.register(Box::new(requests_total.clone()))?;
        registry.register(Box::new(request_duration_seconds.clone()))?;

        Ok(Self {
            requests_total,
            request_duration_seconds,
        })
    }

    pub fn observe(
        &self,
        method: &str,
        path: &str,
        status_code: u16,
        client_ip: Option<&str>,
        duration_secs: f64,
    ) {
        let status = status_code.to_string();
        let ip = client_ip.unwrap_or("");
        let req_labels: [&str; 4] = [method, path, &status, ip];
        self.requests_total.with_label_values(&req_labels).inc();

        let dur_labels: [&str; 3] = [method, path, &status];
        self.request_duration_seconds
            .with_label_values(&dur_labels)
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

pub struct PrometheusMetricsSink {
    evals_total: IntCounterVec,
    evals_allowed: IntCounterVec,
    evals_denied: IntCounterVec,
    eval_duration_seconds: HistogramVec,
    reloads_total: IntCounter,
}

impl PrometheusMetricsSink {
    pub fn new(registry: &Registry) -> Result<Self, Box<dyn std::error::Error>> {
        let evals_total = IntCounterVec::new(
            prometheus::Opts::new("policy_evals_total", "Total policy evaluations"),
            &["principal", "action"],
        )?;
        let evals_allowed = IntCounterVec::new(
            prometheus::Opts::new("policy_evals_allowed_total", "Allowed decisions"),
            &["principal", "action"],
        )?;
        let evals_denied = IntCounterVec::new(
            prometheus::Opts::new("policy_evals_denied_total", "Denied decisions"),
            &["principal", "action"],
        )?;
        let eval_duration_seconds = HistogramVec::new(
            HistogramOpts::new(
                "policy_eval_duration_seconds",
                "Policy evaluation latency in seconds",
            ),
            &["principal", "action"],
        )?;
        let reloads_total =
            IntCounter::new("policy_reloads_total", "Total number of policy reloads")?;

        registry.register(Box::new(evals_total.clone()))?;
        registry.register(Box::new(evals_allowed.clone()))?;
        registry.register(Box::new(evals_denied.clone()))?;
        registry.register(Box::new(eval_duration_seconds.clone()))?;
        registry.register(Box::new(reloads_total.clone()))?;

        Ok(Self {
            evals_total,
            evals_allowed,
            evals_denied,
            eval_duration_seconds,
            reloads_total,
        })
    }
}

impl MetricsSink for PrometheusMetricsSink {
    fn on_evaluation(&self, stats: &EvaluationStats) {
        let labels = [stats.principal_id.clone(), stats.action_id.clone()];
        let label_refs: Vec<&str> = labels.iter().map(String::as_str).collect();
        self.evals_total.with_label_values(&label_refs).inc();
        if stats.allowed {
            self.evals_allowed.with_label_values(&label_refs).inc();
        } else {
            self.evals_denied.with_label_values(&label_refs).inc();
        }
        self.eval_duration_seconds
            .with_label_values(&label_refs)
            .observe(stats.duration.as_secs_f64());
    }

    fn on_reload(&self, _stats: &ReloadStats) {
        self.reloads_total.inc();
    }
}

/// Build and register Prometheus metrics, set treetop-core sink, and expose build info.
pub fn init_prometheus() -> Result<Arc<Registry>, Box<dyn std::error::Error>> {
    let registry = Registry::new();

    // Static build info metric (value = 1), labeled with versions.
    let build = build_info();
    let build_info = IntGaugeVec::new(
        prometheus::Opts::new("treetop_build_info", "Build and component versions"),
        &["app_version", "core_version", "cedar_version"],
    )?;
    registry.register(Box::new(build_info.clone()))?;
    let version_labels = [
        build.version.clone(),
        build.core.clone(),
        build.cedar.to_string(),
    ];
    build_info
        .with_label_values(
            &version_labels
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )
        .set(1);

    // Core metrics sink
    let sink = Arc::new(PrometheusMetricsSink::new(&registry)?);
    treetop_core::set_sink(sink);

    // HTTP metrics
    let http = Arc::new(HttpMetrics::new(&registry)?);
    let _ = HTTP_METRICS.set(http);

    Ok(Arc::new(registry))
}

/// Encode all metrics from the provided registry in Prometheus text format.
pub fn encode_registry(registry: &Registry) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let metric_families = registry.gather();
    let mut buf = Vec::new();
    let encoder = TextEncoder::new();
    encoder.encode(&metric_families, &mut buf)?;
    Ok(buf)
}
