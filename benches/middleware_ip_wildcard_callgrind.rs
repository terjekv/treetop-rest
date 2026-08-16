use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use std::net::IpAddr;
use treetop_rest::config::ClientAllowlist;

type BenchCtx = (ClientAllowlist, IpAddr);

fn setup() -> BenchCtx {
    (ClientAllowlist::Any, "203.0.113.42".parse().unwrap())
}

fn teardown(_: BenchCtx) {}

#[library_benchmark(setup = setup, teardown = teardown)]
fn allowlist_wildcard((allowlist, ip): BenchCtx) -> BenchCtx {
    black_box(allowlist.allows(ip));
    (allowlist, ip)
}

library_benchmark_group!(name = middleware_ip_wildcard; benchmarks = allowlist_wildcard);

main!(library_benchmark_groups = middleware_ip_wildcard);
