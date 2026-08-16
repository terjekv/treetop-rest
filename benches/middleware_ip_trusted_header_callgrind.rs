use actix_web::{dev::ServiceRequest, test::TestRequest};
use gungraun::{library_benchmark, library_benchmark_group, main};
use ipnet::IpNet;
use std::net::SocketAddr;
use std::str::FromStr;
use treetop_rest::middleware::resolve_client_ip_for_bench;

type BenchCtx = (ServiceRequest, [IpNet; 1]);

fn setup() -> BenchCtx {
    let peer: SocketAddr = "192.0.2.10:443".parse().unwrap();
    let req = TestRequest::get()
        .peer_addr(peer)
        .insert_header(("x-forwarded-for", "10.0.0.42"))
        .to_srv_request();
    let trusted = [IpNet::from_str("192.0.2.0/24").unwrap()];
    (req, trusted)
}

#[library_benchmark(setup = setup)]
fn extract_ip_trusted_header((req, trusted): BenchCtx) {
    let _ = resolve_client_ip_for_bench(&req, &trusted);
}

library_benchmark_group!(name = middleware_ip_trusted_header; benchmarks = extract_ip_trusted_header);

main!(library_benchmark_groups = middleware_ip_trusted_header);
