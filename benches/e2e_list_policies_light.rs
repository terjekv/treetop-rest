use actix_http::Request as HttpRequest;
use actix_service::boxed::{service as box_service, BoxService};
use actix_web::body::BoxBody;
use actix_web::dev::ServiceResponse;
use actix_web::{test, web, App};
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::str::FromStr;
use std::sync::{Arc, Mutex, Once};
use treetop_rest::config::ClientAllowlist;
use treetop_rest::handlers;
use treetop_rest::middeware::{ClientAllowlistMiddleware, TracingMiddleware};
use treetop_rest::state::PolicyStore;

const DSL: &str = r#"
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

fn init_metrics_once() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = treetop_rest::metrics::init_prometheus();
    });
}

fn build_store() -> Arc<Mutex<PolicyStore>> {
    let mut store = PolicyStore::new().unwrap();
    store.set_dsl(DSL, None, None).unwrap();
    Arc::new(Mutex::new(store))
}

type BoxedApp = BoxService<HttpRequest, ServiceResponse<BoxBody>, actix_web::Error>;
type BenchCtx = (BoxedApp, HttpRequest);

fn setup_list_light() -> BenchCtx {
    init_metrics_once();
    let store = build_store();
    let allowlist = ClientAllowlist::from_str("*").unwrap();

    let app = futures::executor::block_on(test::init_service(
        App::new()
            .wrap(ClientAllowlistMiddleware::new_with_trust(allowlist, true))
            .wrap(TracingMiddleware::new_with_trust(true))
            .app_data(web::Data::new(store))
            .route("/api/v1/policies/{user}", web::get().to(handlers::list_policies)),
    ));
    let app = box_service(app);

    let req = test::TestRequest::get()
        .uri("/api/v1/policies/alice")
        .insert_header(("x-forwarded-for", "10.0.0.42"))
        .to_request();

    (app, req)
}

#[library_benchmark(setup = setup_list_light)]
fn e2e_list_policies_light((app, req): BenchCtx) {
    let _ = futures::executor::block_on(test::call_service(&app, req));
}

library_benchmark_group!(
    name = e2e_list_policies_light_group;
    benchmarks = e2e_list_policies_light
);

main!(library_benchmark_groups = e2e_list_policies_light_group);
