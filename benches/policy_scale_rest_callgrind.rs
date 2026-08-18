use std::sync::{Arc, Once, RwLock};

use actix_http::Request as HttpRequest;
use actix_service::boxed::{BoxService, service as box_service};
use actix_web::body::BoxBody;
use actix_web::dev::ServiceResponse;
use actix_web::{App, test, web};
use cedar_policy::SchemaFragment;
use gungraun::{library_benchmark, library_benchmark_group, main};
use serde_json::{Value, json};
use treetop_core::bench_helpers::policy_scale::{
    REVIEWERS_GROUP, ScaleCorpus, TARGET_USER, allow_request, forbid_request, group_request,
    no_match_request,
};
use treetop_rest::config::SchemaValidationMode;
use treetop_rest::handlers;
use treetop_rest::middleware::TracingMiddleware;
use treetop_rest::parallel::ParallelConfig;
use treetop_rest::state::PolicyStore;

const POLICY_COUNT: usize = 1_000;

fn schema_json(corpus: &ScaleCorpus) -> String {
    SchemaFragment::from_cedarschema_str(&corpus.schema_text)
        .expect("shared scale schema should parse")
        .0
        .to_json_string()
        .expect("shared scale schema should serialize as JSON")
}

fn build_store(corpus: &ScaleCorpus) -> PolicyStore {
    let mut store = PolicyStore::new().expect("policy store should initialize");
    store.set_schema_validation_mode(SchemaValidationMode::Strict);
    store
        .set_schema(&schema_json(corpus), None, None)
        .expect("shared scale schema should load");
    store
        .set_dsl(&corpus.policy_text, None, None)
        .expect("shared scale policies should load");
    store
}

fn init_metrics_once() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = treetop_rest::metrics::init_prometheus();
    });
}

type ReloadContext = (PolicyStore, String);

fn setup_reload() -> ReloadContext {
    let initial = ScaleCorpus::new(POLICY_COUNT, 0);
    let replacement = ScaleCorpus::new(POLICY_COUNT, 1);
    (build_store(&initial), replacement.policy_text)
}

fn teardown_reload(_: ReloadContext) {}

#[library_benchmark(setup = setup_reload, teardown = teardown_reload)]
fn policy_store_reload((mut store, replacement): ReloadContext) -> ReloadContext {
    store
        .set_dsl(&replacement, None, None)
        .expect("shared replacement corpus should load");
    (store, replacement)
}

type BoxedApp = BoxService<HttpRequest, ServiceResponse<BoxBody>, actix_web::Error>;
type HttpContext = (BoxedApp, HttpRequest);
type HttpResult = (BoxedApp, ServiceResponse<BoxBody>);

fn request_body(requests: impl IntoIterator<Item = treetop_core::Request>) -> Value {
    json!({ "requests": requests.into_iter().collect::<Vec<_>>() })
}

fn build_authorize_context(uri: &str, body: Value) -> HttpContext {
    init_metrics_once();
    let corpus = ScaleCorpus::new(POLICY_COUNT, 0);
    let store = Arc::new(RwLock::new(build_store(&corpus)));
    let parallel = ParallelConfig::new(1, 1, Some(usize::MAX));
    let app = futures::executor::block_on(test::init_service(
        App::new()
            .wrap(TracingMiddleware::new())
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    ));
    let request = test::TestRequest::post()
        .uri(uri)
        .insert_header(("x-forwarded-for", "127.0.0.1"))
        .set_json(body)
        .to_request();
    (box_service(app), request)
}

fn setup_allow_brief() -> HttpContext {
    build_authorize_context("/api/v1/authorize", request_body([allow_request()]))
}

fn setup_forbid_full() -> HttpContext {
    build_authorize_context(
        "/api/v1/authorize?detail=full",
        request_body([forbid_request()]),
    )
}

fn setup_mixed_batch() -> HttpContext {
    build_authorize_context(
        "/api/v1/authorize",
        request_body([
            allow_request(),
            forbid_request(),
            group_request(),
            no_match_request(),
            allow_request(),
            forbid_request(),
            group_request(),
            no_match_request(),
        ]),
    )
}

fn setup_cached_policy_list() -> HttpContext {
    init_metrics_once();
    let corpus = ScaleCorpus::new(POLICY_COUNT, 0);
    let store = build_store(&corpus);
    store
        .list_policies_json(
            TARGET_USER.to_owned(),
            vec![REVIEWERS_GROUP.to_owned()],
            Vec::new(),
        )
        .expect("shared target policy list should prime");
    let store = Arc::new(RwLock::new(store));
    let app = futures::executor::block_on(test::init_service(
        App::new()
            .wrap(TracingMiddleware::new())
            .app_data(web::Data::new(store))
            .route(
                "/api/v1/policies/{user}",
                web::get().to(handlers::list_policies),
            ),
    ));
    let uri = format!("/api/v1/policies/{TARGET_USER}?groups={REVIEWERS_GROUP}");
    let request = test::TestRequest::get()
        .uri(&uri)
        .insert_header(("x-forwarded-for", "127.0.0.1"))
        .to_request();
    (box_service(app), request)
}

fn teardown_http(_: HttpResult) {}

#[library_benchmark(setup = setup_allow_brief, teardown = teardown_http)]
fn authorize_allow_brief((app, request): HttpContext) -> HttpResult {
    let response = futures::executor::block_on(test::call_service(&app, request));
    (app, response)
}

#[library_benchmark(setup = setup_forbid_full, teardown = teardown_http)]
fn authorize_forbid_full((app, request): HttpContext) -> HttpResult {
    let response = futures::executor::block_on(test::call_service(&app, request));
    (app, response)
}

#[library_benchmark(setup = setup_mixed_batch, teardown = teardown_http)]
fn authorize_mixed_batch_8((app, request): HttpContext) -> HttpResult {
    let response = futures::executor::block_on(test::call_service(&app, request));
    (app, response)
}

#[library_benchmark(setup = setup_cached_policy_list, teardown = teardown_http)]
fn list_target_policies_cached((app, request): HttpContext) -> HttpResult {
    let response = futures::executor::block_on(test::call_service(&app, request));
    (app, response)
}

library_benchmark_group!(
    name = policy_scale_rest;
    benchmarks =
        policy_store_reload,
        authorize_allow_brief,
        authorize_forbid_full,
        authorize_mixed_batch_8,
        list_target_policies_cached
);

main!(library_benchmark_groups = policy_scale_rest);
