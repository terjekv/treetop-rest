use actix_web::{App, test, web};
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};
use treetop_core::{Action, Principal, Request, Resource, User};
use treetop_rest::handlers;
use treetop_rest::models::AuthorizeRequest;
use treetop_rest::state::PolicyStore;

// Shared metrics registry for all tests
static METRICS_REGISTRY: OnceLock<Arc<prometheus::Registry>> = OnceLock::new();

fn get_metrics_registry() -> Arc<prometheus::Registry> {
    METRICS_REGISTRY
        .get_or_init(|| treetop_rest::metrics::init_prometheus().expect("Failed to init metrics"))
        .clone()
}

/// Helper to create a test app with metrics support
fn create_test_app_with_metrics(
    store: Arc<Mutex<PolicyStore>>,
) -> App<
    impl actix_web::dev::ServiceFactory<
        actix_web::dev::ServiceRequest,
        Config = (),
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
        InitError = (),
    >,
> {
    // Get the shared registry
    let registry = get_metrics_registry();

    App::new()
        .wrap(treetop_rest::middeware::TracingMiddleware::new())
        .app_data(web::Data::new(store))
        .app_data(web::Data::new(registry))
        .configure(handlers::init)
}

/// Helper to create a test policy store with default policies
fn create_test_store() -> Arc<Mutex<PolicyStore>> {
    // Initialize metrics BEFORE creating the policy store/engine
    // This ensures the metrics sink is set up when the engine is created
    let _ = get_metrics_registry();

    let mut store = PolicyStore::new().unwrap();

    let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);

forbid (
    principal == User::"alice",
    action == Action::"edit",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;

    store.set_dsl(dsl, None, None).unwrap();
    Arc::new(Mutex::new(store))
}

#[actix_web::test]
async fn test_metrics_endpoint_exists() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn test_metrics_content_type() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    let content_type = resp.headers().get("content-type").unwrap();
    assert!(content_type.to_str().unwrap().starts_with("text/plain"));
}

#[actix_web::test]
async fn test_metrics_contains_build_info() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    // Check for build info metric
    assert!(
        body_str.contains("treetop_build_info"),
        "Metrics should contain treetop_build_info"
    );
    assert!(
        body_str.contains("app_version"),
        "Build info should have app_version label"
    );
    assert!(
        body_str.contains("core_version"),
        "Build info should have core_version label"
    );
    assert!(
        body_str.contains("cedar_version"),
        "Build info should have cedar_version label"
    );
}

#[actix_web::test]
async fn test_metrics_has_policy_eval_metrics() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    // Perform an evaluation to ensure metrics are generated
    let principal = Principal::User(User::from_str("User::\"alice\"").unwrap());
    let action = Action::from_str("Action::\"view\"").unwrap();
    let resource = Resource::new("Photo", "VacationPhoto94.jpg");

    let check_req = Request {
        principal: principal.clone(),
        action: action.clone(),
        resource: resource.clone(),
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&AuthorizeRequest::single(check_req))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    // Also perform a denied evaluation
    let action_edit = Action::from_str("Action::\"edit\"").unwrap();
    let check_req_denied = Request {
        principal: principal.clone(),
        action: action_edit,
        resource: resource.clone(),
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&AuthorizeRequest::single(check_req_denied))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Now check metrics
    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    // Check for policy evaluation metrics
    assert!(
        body_str.contains("policy_evals_total"),
        "Metrics should contain policy_evals_total"
    );
    assert!(
        body_str.contains("policy_evals_allowed_total"),
        "Metrics should contain policy_evals_allowed_total"
    );
    assert!(
        body_str.contains("policy_evals_denied_total"),
        "Metrics should contain policy_evals_denied_total"
    );
    assert!(
        body_str.contains("policy_eval_duration_seconds"),
        "Metrics should contain policy_eval_duration_seconds"
    );
    assert!(
        body_str.contains("policy_reloads_total"),
        "Metrics should contain policy_reloads_total"
    );
}

#[actix_web::test]
async fn test_metrics_updated_after_evaluation() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    // Perform an authorization check (alice viewing photo - should be allowed)
    let principal = Principal::User(User::from_str("User::\"alice\"").unwrap());
    let action = Action::from_str("Action::\"view\"").unwrap();
    let resource = Resource::new("Photo", "VacationPhoto94.jpg");

    let check_req = Request {
        principal,
        action,
        resource,
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&AuthorizeRequest::single(check_req))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Get metrics and verify they contain our specific evaluation
    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    // In a parallel test environment, we can't rely on exact counts
    // Instead, verify that the metrics exist and contain our specific labels
    // The metrics should have labels for principal and action
    assert!(
        body_str.contains("policy_evals_total"),
        "Metrics should contain policy_evals_total"
    );
    assert!(
        body_str.contains("policy_evals_allowed_total"),
        "Metrics should contain policy_evals_allowed_total"
    );

    // Verify that metrics with our specific labels exist
    // In Prometheus format, labels use escaped quotes like: principal="User::\"alice\""
    let has_alice_view = body_str.lines().any(|line| {
        line.contains("policy_evals_total")
            && line.contains("Action::")
            && line.contains("view")
            && !line.starts_with('#')
    });

    assert!(
        has_alice_view,
        "Metrics should contain an evaluation for Action::view"
    );
}

#[actix_web::test]
async fn test_metrics_tracks_allowed_and_denied() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    // Perform an allowed evaluation (alice viewing photo)
    let principal_alice = Principal::User(User::from_str("User::\"alice\"").unwrap());
    let action_view = Action::from_str("Action::\"view\"").unwrap();
    let resource = Resource::new("Photo", "VacationPhoto94.jpg");

    let check_req = Request {
        principal: principal_alice.clone(),
        action: action_view,
        resource: resource.clone(),
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&AuthorizeRequest::single(check_req))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Perform a denied evaluation (alice editing photo - explicitly forbidden)
    let action_edit = Action::from_str("Action::\"edit\"").unwrap();
    let check_req_denied = Request {
        principal: principal_alice,
        action: action_edit,
        resource,
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&AuthorizeRequest::single(check_req_denied))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Check metrics
    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    // Both allowed and denied should have non-zero values
    let allowed_count = extract_metric_value(body_str, "policy_evals_allowed_total");
    let denied_count = extract_metric_value(body_str, "policy_evals_denied_total");

    assert!(
        allowed_count > 0.0,
        "Should have at least one allowed evaluation"
    );
    assert!(
        denied_count > 0.0,
        "Should have at least one denied evaluation"
    );
}

#[actix_web::test]
async fn test_metrics_prometheus_format() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    // Perform an evaluation to ensure counter metrics are present
    let principal = Principal::User(User::from_str("User::\"alice\"").unwrap());
    let action = Action::from_str("Action::\"view\"").unwrap();
    let resource = Resource::new("Photo", "VacationPhoto94.jpg");

    let check_req = Request {
        principal,
        action,
        resource,
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&AuthorizeRequest::single(check_req))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Now check metrics format
    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;

    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    // Verify Prometheus format characteristics
    assert!(
        body_str.contains("# HELP"),
        "Prometheus metrics should contain HELP comments"
    );
    assert!(
        body_str.contains("# TYPE"),
        "Prometheus metrics should contain TYPE comments"
    );

    // Verify metric types
    assert!(
        body_str.contains("# TYPE policy_evals_total counter"),
        "policy_evals_total should be a counter"
    );
    assert!(
        body_str.contains("# TYPE policy_eval_duration_seconds histogram"),
        "policy_eval_duration_seconds should be a histogram"
    );

    // Verify HTTP metrics types
    assert!(
        body_str.contains("# TYPE http_requests_total counter"),
        "http_requests_total should be a counter"
    );
    assert!(
        body_str.contains("# TYPE http_request_duration_seconds histogram"),
        "http_request_duration_seconds should be a histogram"
    );
}

#[actix_web::test]
async fn test_http_metrics_after_health_request() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    // Hit health endpoint to generate HTTP metrics
    let req = test::TestRequest::get().uri("/api/v1/health").to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Get metrics
    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    assert!(
        body_str.contains("http_requests_total"),
        "HTTP request counter should be present"
    );
    assert!(
        body_str.contains("http_request_duration_seconds"),
        "HTTP request duration histogram should be present"
    );
}

#[actix_web::test]
async fn test_metrics_has_histogram_buckets() {
    let store = create_test_store();
    let app = test::init_service(create_test_app_with_metrics(store)).await;

    // Perform an evaluation to generate histogram data
    let principal = Principal::User(User::from_str("User::\"alice\"").unwrap());
    let action = Action::from_str("Action::\"view\"").unwrap();
    let resource = Resource::new("Photo", "VacationPhoto94.jpg");

    let check_req = Request {
        principal,
        action,
        resource,
    };

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .set_json(&AuthorizeRequest::single(check_req))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Get metrics
    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    // Verify histogram has buckets
    assert!(
        body_str.contains("policy_eval_duration_seconds_bucket"),
        "Duration histogram should have buckets"
    );
    assert!(
        body_str.contains("policy_eval_duration_seconds_sum"),
        "Duration histogram should have sum"
    );
    assert!(
        body_str.contains("policy_eval_duration_seconds_count"),
        "Duration histogram should have count"
    );
}

#[actix_web::test]
async fn test_http_metrics_include_client_ip_label() {
    let store = create_test_store();
    // Build an app that trusts IP headers so x-forwarded-for is used
    let registry = get_metrics_registry();
    let app = test::init_service(
        App::new()
            .wrap(treetop_rest::middeware::TracingMiddleware::new_with_trust(
                true,
            ))
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(registry.clone()))
            .configure(handlers::init),
    )
    .await;

    // Send a request with a specific client IP
    let req = test::TestRequest::get()
        .uri("/api/v1/health")
        .insert_header(("x-forwarded-for", "203.0.113.10"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Fetch metrics and verify the client_ip label is present with our value
    let req = test::TestRequest::get().uri("/metrics").to_request();
    let resp = test::call_service(&app, req).await;
    let body = test::read_body(resp).await;
    let body_str = std::str::from_utf8(&body).unwrap();

    let has_client_ip = body_str.lines().any(|line| {
        line.starts_with("http_requests_total")
            && line.contains("client_ip=\"203.0.113.10\"")
            && !line.starts_with('#')
    });
    assert!(
        has_client_ip,
        "HTTP metrics should include client_ip label with the forwarded IP"
    );
}

/// Helper function to extract a metric value from Prometheus text format
/// This is a simple parser that finds the first occurrence of the metric name
/// and extracts its value (works for counters without labels at the end)
fn extract_metric_value(metrics: &str, metric_name: &str) -> f64 {
    for line in metrics.lines() {
        // Skip comments
        if line.starts_with('#') {
            continue;
        }
        // Look for lines starting with the metric name
        if line.starts_with(metric_name) {
            // Split by whitespace and get the last part (the value)
            if let Some(value_str) = line.split_whitespace().last()
                && let Ok(value) = value_str.parse::<f64>()
            {
                return value;
            }
        }
    }
    0.0
}
