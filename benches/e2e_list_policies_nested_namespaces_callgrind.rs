use actix_http::Request as HttpRequest;
use actix_service::boxed::{BoxService, service as box_service};
use actix_web::body::BoxBody;
use actix_web::dev::ServiceResponse;
use actix_web::{App, test, web};
use gungraun::{library_benchmark, library_benchmark_group, main};
use std::sync::{Arc, Once, RwLock};
use treetop_rest::handlers;
use treetop_rest::middleware::TracingMiddleware;
use treetop_rest::state::PolicyStore;

const DSL: &str = r#"
permit (
    principal == Org::Dept::Team::User::"alice",
    action == Org::Dept::Team::Action::"view",
    resource == Org::Dept::Team::Photo::"VacationPhoto94.jpg"
);

permit (
    principal == Org::Dept::Team::User::"bob",
    action == Org::Dept::Team::Action::"view",
    resource == Org::Dept::Team::Photo::"VacationPhoto94.jpg"
);
"#;

fn init_metrics_once() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = treetop_rest::metrics::init_prometheus();
    });
}

fn build_store() -> Arc<RwLock<PolicyStore>> {
    let mut store = PolicyStore::new().unwrap();
    store.set_dsl(DSL, None, None).unwrap();
    Arc::new(RwLock::new(store))
}

type BoxedApp = BoxService<HttpRequest, ServiceResponse<BoxBody>, actix_web::Error>;
type BenchCtx = (BoxedApp, HttpRequest);
type BenchResult = (BoxedApp, ServiceResponse<BoxBody>);

fn setup_list_nested() -> BenchCtx {
    init_metrics_once();
    let store = build_store();
    let app = futures::executor::block_on(test::init_service(
        App::new()
            .wrap(TracingMiddleware::new())
            .app_data(web::Data::new(store))
            .route(
                "/api/v1/policies/{user}",
                web::get().to(handlers::list_policies),
            ),
    ));
    let app = box_service(app);

    let req = test::TestRequest::get()
        .uri("/api/v1/policies/alice?namespaces[]=Org&namespaces[]=Dept&namespaces[]=Team")
        .insert_header(("x-forwarded-for", "10.0.0.42"))
        .to_request();

    (app, req)
}

fn teardown(_: BenchResult) {}

#[library_benchmark(setup = setup_list_nested, teardown = teardown)]
fn e2e_list_policies_nested_namespaces((app, req): BenchCtx) -> BenchResult {
    let response = futures::executor::block_on(test::call_service(&app, req));
    (app, response)
}

library_benchmark_group!(
    name = e2e_list_policies_nested_namespaces_group;
    benchmarks = e2e_list_policies_nested_namespaces
);

main!(library_benchmark_groups = e2e_list_policies_nested_namespaces_group);
