use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_rest::state::{Metadata, OfPolicies};

const DSL_DNS: &str = include_str!("../testdata/dns.cedar");

fn teardown(_: Metadata<OfPolicies>) {}

#[library_benchmark(teardown = teardown)]
fn metadata_policies_dns() -> Metadata<OfPolicies> {
    Metadata::<OfPolicies>::new(DSL_DNS.to_string(), None, None).unwrap()
}

library_benchmark_group!(name = policy_store_metadata_dns; benchmarks = metadata_policies_dns);

main!(library_benchmark_groups = policy_store_metadata_dns);
