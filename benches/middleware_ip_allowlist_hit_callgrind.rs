use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use std::net::IpAddr;
use std::str::FromStr;
use treetop_rest::config::ClientAllowlist;

type BenchCtx = (ClientAllowlist, IpAddr);

fn setup() -> BenchCtx {
    let allowlist = ClientAllowlist::from_str("10.0.0.0/24").unwrap();
    let ip = "10.0.0.42".parse().unwrap();
    (allowlist, ip)
}

fn teardown(_: BenchCtx) {}

#[library_benchmark(setup = setup, teardown = teardown)]
fn allowlist_ipv4_hit((allowlist, ip): BenchCtx) -> BenchCtx {
    black_box(allowlist.allows(ip));
    (allowlist, ip)
}

library_benchmark_group!(name = middleware_ip_allowlist_hit; benchmarks = allowlist_ipv4_hit);

main!(library_benchmark_groups = middleware_ip_allowlist_hit);
