use gungraun::{library_benchmark, library_benchmark_group, main};
use std::str::FromStr;
use treetop_rest::config::ClientAllowlist;

fn teardown(_: ClientAllowlist) {}

#[library_benchmark(teardown = teardown)]
fn parse_ipv4_and_ipv6_allowlist() -> ClientAllowlist {
    ClientAllowlist::from_str("10.0.0.0/24,2001:db8::/32").unwrap()
}

library_benchmark_group!(
    name = middleware_ip_allowlist_parse;
    benchmarks = parse_ipv4_and_ipv6_allowlist
);

main!(library_benchmark_groups = middleware_ip_allowlist_parse);
