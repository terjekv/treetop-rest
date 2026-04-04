use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::str::FromStr;
use treetop_rest::config::ClientAllowlist;

#[library_benchmark]
fn allowlist_ipv4_miss() {
    let allowlist = ClientAllowlist::from_str("10.0.0.0/24").unwrap();
    let ip = "192.168.1.10".parse().unwrap();
    let _ = allowlist.allows(ip);
}

library_benchmark_group!(name = middleware_ip_allowlist_miss; benchmarks = allowlist_ipv4_miss);

main!(library_benchmark_groups = middleware_ip_allowlist_miss);
