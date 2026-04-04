use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use treetop_rest::state::{Metadata, OfPolicies};

const DSL_DEFAULT: &str = include_str!("../testdata/default.cedar");

#[library_benchmark]
fn metadata_policies_default() {
    let _ = Metadata::<OfPolicies>::new(DSL_DEFAULT.to_string(), None, None).unwrap();
}

library_benchmark_group!(name = policy_store_metadata_default; benchmarks = metadata_policies_default);

main!(library_benchmark_groups = policy_store_metadata_default);
