use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::str::FromStr;
use treetop_rest::config::ClientAllowlist;

#[library_benchmark]
fn allowlist_ipv4_hit() {
    let allowlist = ClientAllowlist::from_str("10.0.0.0/24").unwrap();
    let ip = "10.0.0.42".parse().unwrap();
    let _ = allowlist.allows(ip);
}

library_benchmark_group!(name = middleware_ip_allowlist_hit; benchmarks = allowlist_ipv4_hit);

main!(library_benchmark_groups = middleware_ip_allowlist_hit);
