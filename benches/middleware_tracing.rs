use actix_service::boxed::{BoxService, service as box_service};
use actix_service::{Service, Transform, fn_service};
use actix_web::body::BoxBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::test::TestRequest;
use actix_web::{Error, HttpResponse};
use futures::executor::block_on;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::sync::Once;
use treetop_rest::middleware::TracingMiddleware;

fn init_metrics() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = treetop_rest::metrics::init_prometheus();
    });
}

type BoxedService = BoxService<ServiceRequest, ServiceResponse<BoxBody>, Error>;
type BenchCtx = (BoxedService, ServiceRequest);

fn setup_tracing() -> BenchCtx {
    init_metrics();
    let middleware = TracingMiddleware::new_with_trust(true);
    let service = fn_service(|req: ServiceRequest| async move {
        Ok(req.into_response(HttpResponse::Ok().finish()))
    });
    let service = block_on(middleware.new_transform(service)).unwrap();
    let service = box_service(service);
    let req = TestRequest::get()
        .insert_header(("x-forwarded-for", "10.0.0.42"))
        .to_srv_request();
    (service, req)
}

#[library_benchmark(setup = setup_tracing)]
fn tracing_middleware_call((service, req): BenchCtx) {
    let _ = block_on(service.call(req));
}

library_benchmark_group!(name = middleware_tracing; benchmarks = tracing_middleware_call);

main!(library_benchmark_groups = middleware_tracing);
