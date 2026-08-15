use gungraun::{library_benchmark, library_benchmark_group, main};
use std::str::FromStr;
use treetop_rest::config::ClientAllowlist;

fn setup() -> (ClientAllowlist, std::net::IpAddr) {
    let allowlist = ClientAllowlist::from_str("10.0.0.0/24").unwrap();
    let ip = "192.168.1.10".parse().unwrap();
    (allowlist, ip)
}

#[library_benchmark(setup = setup)]
fn allowlist_ipv4_miss((allowlist, ip): (ClientAllowlist, std::net::IpAddr)) {
    let _ = allowlist.allows(ip);
}

library_benchmark_group!(name = middleware_ip_allowlist_miss; benchmarks = allowlist_ipv4_miss);

main!(library_benchmark_groups = middleware_ip_allowlist_miss);
