use actix_web::test::TestRequest;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::net::SocketAddr;
use std::str::FromStr;
use treetop_rest::config::ClientAllowlist;
use treetop_rest::middeware::extract_client_ip_for_bench;

#[library_benchmark]
fn extract_ip_trusted_header() {
    let req = TestRequest::get()
        .insert_header(("x-forwarded-for", "10.0.0.42"))
        .to_srv_request();
    let _ = extract_client_ip_for_bench(&req, true);
}

#[library_benchmark]
fn extract_ip_peer_addr_only() {
    let peer: SocketAddr = "10.0.0.42:1234".parse().unwrap();
    let req = TestRequest::get().peer_addr(peer).to_srv_request();
    let _ = extract_client_ip_for_bench(&req, false);
}

#[library_benchmark]
fn allowlist_ipv4_hit() {
    let allowlist = ClientAllowlist::from_str("10.0.0.0/24").unwrap();
    let ip = "10.0.0.42".parse().unwrap();
    let _ = allowlist.allows(ip);
}

#[library_benchmark]
fn allowlist_ipv4_miss() {
    let allowlist = ClientAllowlist::from_str("10.0.0.0/24").unwrap();
    let ip = "192.168.1.10".parse().unwrap();
    let _ = allowlist.allows(ip);
}

library_benchmark_group!(
    name = middleware_ip;
    benchmarks = extract_ip_trusted_header,
        extract_ip_peer_addr_only,
        allowlist_ipv4_hit,
        allowlist_ipv4_miss
);

main!(library_benchmark_groups = middleware_ip);
