use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use treetop_rest::state::{Metadata, OfPolicies};

const DSL_DNS: &str = include_str!("../testdata/dns.cedar");

#[library_benchmark]
fn metadata_policies_dns() {
    let _ = Metadata::<OfPolicies>::new(DSL_DNS.to_string(), None, None).unwrap();
}

library_benchmark_group!(name = policy_store_metadata_dns; benchmarks = metadata_policies_dns);

main!(library_benchmark_groups = policy_store_metadata_dns);
