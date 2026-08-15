use gungraun::{library_benchmark, library_benchmark_group, main};
use std::net::IpAddr;
use treetop_rest::config::ClientAllowlist;

fn setup() -> (ClientAllowlist, IpAddr) {
    (ClientAllowlist::Any, "203.0.113.42".parse().unwrap())
}

#[library_benchmark(setup = setup)]
fn allowlist_wildcard((allowlist, ip): (ClientAllowlist, IpAddr)) {
    let _ = allowlist.allows(ip);
}

library_benchmark_group!(name = middleware_ip_wildcard; benchmarks = allowlist_wildcard);

main!(library_benchmark_groups = middleware_ip_wildcard);
