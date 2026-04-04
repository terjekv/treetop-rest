use actix_web::test::TestRequest;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use treetop_rest::middleware::extract_client_ip_for_bench;

#[library_benchmark]
fn extract_ip_trusted_header() {
    let req = TestRequest::get()
        .insert_header(("x-forwarded-for", "10.0.0.42"))
        .to_srv_request();
    let _ = extract_client_ip_for_bench(&req, true);
}

library_benchmark_group!(name = middleware_ip_trusted_header; benchmarks = extract_ip_trusted_header);

main!(library_benchmark_groups = middleware_ip_trusted_header);
