use actix_service::{fn_service, Service, Transform};
use actix_web::dev::ServiceRequest;
use actix_web::test::TestRequest;
use actix_web::HttpResponse;
use futures::executor::block_on;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::sync::Once;
use treetop_rest::middeware::TracingMiddleware;

fn init_metrics() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = treetop_rest::metrics::init_prometheus();
    });
}

#[library_benchmark]
fn tracing_middleware_call() {
    init_metrics();
    let middleware = TracingMiddleware::new_with_trust(true);
    let service = fn_service(|req: ServiceRequest| async move {
        Ok(req.into_response(HttpResponse::Ok().finish()))
    });
    let service = block_on(middleware.new_transform(service)).unwrap();
    let req = TestRequest::get()
        .insert_header(("x-forwarded-for", "10.0.0.42"))
        .to_srv_request();
    let _ = block_on(service.call(req));
}

library_benchmark_group!(name = middleware_tracing; benchmarks = tracing_middleware_call);

main!(library_benchmark_groups = middleware_tracing);
