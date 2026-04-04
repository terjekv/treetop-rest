use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::net::SocketAddr;
use treetop_rest::middleware::extract_client_ip_for_bench;
use actix_web::test::TestRequest;

#[library_benchmark]
fn extract_ip_peer_addr_only() {
    let peer: SocketAddr = "10.0.0.42:1234".parse().unwrap();
    let req = TestRequest::get().peer_addr(peer).to_srv_request();
    let _ = extract_client_ip_for_bench(&req, false);
}

library_benchmark_group!(name = middleware_ip_peer_addr; benchmarks = extract_ip_peer_addr_only);

main!(library_benchmark_groups = middleware_ip_peer_addr);
