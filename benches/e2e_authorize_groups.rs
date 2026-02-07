use actix_http::Request as HttpRequest;
use actix_service::boxed::{service as box_service, BoxService};
use actix_web::body::BoxBody;
use actix_web::dev::ServiceResponse;
use actix_web::{test, web, App};
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::str::FromStr;
use std::sync::{Arc, Mutex, Once};
use treetop_core::{Action, Principal, Request, Resource, User};
use treetop_rest::config::ClientAllowlist;
use treetop_rest::handlers;
use treetop_rest::middeware::{ClientAllowlistMiddleware, TracingMiddleware};
use treetop_rest::models::AuthorizeRequest;
use treetop_rest::parallel::ParallelConfig;
use treetop_rest::state::PolicyStore;

const DSL: &str = r#"
permit (
    principal in DNS::Group::"admins",
    action in
        [DNS::Action::"create_host",
         DNS::Action::"delete_host",
         DNS::Action::"view_host",
         DNS::Action::"edit_host"],
    resource is Host
);

permit (
    principal in DNS::Group::"users",
    action == DNS::Action::"view_host",
    resource is Host
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

fn build_request() -> AuthorizeRequest {
    let request = Request {
        principal: Principal::User(User::from_str(r#"DNS::User::"alice"[admins]"#).unwrap()),
        action: Action::from_str(r#"DNS::Action::"create_host""#).unwrap(),
        resource: Resource::new("Host", "example"),
    };
    AuthorizeRequest::single(request)
}

type BoxedApp = BoxService<HttpRequest, ServiceResponse<BoxBody>, actix_web::Error>;
type BenchCtx = (BoxedApp, HttpRequest);

fn setup_groups() -> BenchCtx {
    init_metrics_once();
    let store = build_store();
    let parallel = ParallelConfig::new(1, 1, Some(usize::MAX));
    let allowlist = ClientAllowlist::from_str("*").unwrap();

    let app = futures::executor::block_on(test::init_service(
        App::new()
            .wrap(ClientAllowlistMiddleware::new_with_trust(allowlist, true))
            .wrap(TracingMiddleware::new_with_trust(true))
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    ));
    let app = box_service(app);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize")
        .insert_header(("x-forwarded-for", "10.0.0.42"))
        .set_json(build_request())
        .to_request();

    (app, req)
}

#[library_benchmark(setup = setup_groups)]
fn e2e_authorize_groups((app, req): BenchCtx) {
    let _ = futures::executor::block_on(test::call_service(&app, req));
}

library_benchmark_group!(name = e2e_authorize_groups_group; benchmarks = e2e_authorize_groups);

main!(library_benchmark_groups = e2e_authorize_groups_group);
