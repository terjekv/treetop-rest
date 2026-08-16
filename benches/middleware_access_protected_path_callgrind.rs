use actix_http::Request as HttpRequest;
use actix_service::boxed::{BoxService, service as box_service};
use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::ServiceResponse;
use actix_web::{App, Error, HttpResponse, test, web};
use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_rest::config::AdmissionConfig;
use treetop_rest::middleware::AccessControlMiddleware;

const TOKEN: &str = "benchmark-token";

type BoxedApp = BoxService<HttpRequest, ServiceResponse<EitherBody<BoxBody>>, Error>;
type BenchCtx = (BoxedApp, HttpRequest);
type BenchResult = (BoxedApp, ServiceResponse<EitherBody<BoxBody>>);

fn setup(path: &str) -> BenchCtx {
    let config = AdmissionConfig::parse(None, Some(TOKEN), None).unwrap();
    let app = futures::executor::block_on(test::init_service(
        App::new().wrap(AccessControlMiddleware::new(config)).route(
            "/api/v1/test",
            web::get().to(|| async { HttpResponse::Ok().finish() }),
        ),
    ));
    let app = box_service(app);
    let req = test::TestRequest::get()
        .uri(path)
        .insert_header(("authorization", format!("Bearer {TOKEN}")))
        .to_request();
    (app, req)
}

fn setup_canonical() -> BenchCtx {
    setup("/api/v1/test")
}

fn setup_percent_encoded() -> BenchCtx {
    setup("/%61pi/v1/test")
}

fn teardown(_: BenchResult) {}

#[library_benchmark(setup = setup_canonical, teardown = teardown)]
fn canonical_protected_path((app, req): BenchCtx) -> BenchResult {
    let response = futures::executor::block_on(test::call_service(&app, req));
    (app, response)
}

#[library_benchmark(setup = setup_percent_encoded, teardown = teardown)]
fn percent_encoded_protected_path((app, req): BenchCtx) -> BenchResult {
    let response = futures::executor::block_on(test::call_service(&app, req));
    (app, response)
}

library_benchmark_group!(
    name = middleware_access_protected_path;
    benchmarks = canonical_protected_path, percent_encoded_protected_path
);

main!(library_benchmark_groups = middleware_access_protected_path);
