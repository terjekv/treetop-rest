use actix_web::{dev::ServiceRequest, test::TestRequest};
use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use std::net::SocketAddr;
use treetop_rest::middleware::resolve_client_ip_for_bench;

fn setup() -> ServiceRequest {
    let peer: SocketAddr = "10.0.0.42:1234".parse().unwrap();
    TestRequest::get().peer_addr(peer).to_srv_request()
}

fn teardown(_: ServiceRequest) {}

#[library_benchmark(setup = setup, teardown = teardown)]
fn extract_ip_peer_addr_only(req: ServiceRequest) -> ServiceRequest {
    black_box(resolve_client_ip_for_bench(&req, &[]));
    req
}

library_benchmark_group!(name = middleware_ip_peer_addr; benchmarks = extract_ip_peer_addr_only);

main!(library_benchmark_groups = middleware_ip_peer_addr);
