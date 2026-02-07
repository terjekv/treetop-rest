use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::str::FromStr;
use treetop_rest::models::Endpoint;
use treetop_rest::state::{Metadata, OfPolicies, PolicyStore};

const DSL_DEFAULT: &str = include_str!("../testdata/default.cedar");
const DSL_DNS: &str = include_str!("../testdata/dns.cedar");

#[library_benchmark]
fn metadata_policies_default() {
    let _ = Metadata::<OfPolicies>::new(DSL_DEFAULT.to_string(), None, None).unwrap();
}

#[library_benchmark]
fn metadata_policies_dns() {
    let _ = Metadata::<OfPolicies>::new(DSL_DNS.to_string(), None, None).unwrap();
}

#[library_benchmark]
fn policy_store_set_dsl_default() {
    let mut store = PolicyStore::new().unwrap();
    store.set_dsl(DSL_DEFAULT, None, None).unwrap();
}

#[library_benchmark]
fn policy_store_set_dsl_with_source() {
    let mut store = PolicyStore::new().unwrap();
    let endpoint = Endpoint::from_str("https://example.com/policies").unwrap();
    store.set_dsl(DSL_DNS, Some(endpoint), Some(60)).unwrap();
}

library_benchmark_group!(
    name = policy_store;
    benchmarks = metadata_policies_default,
        metadata_policies_dns,
        policy_store_set_dsl_default,
        policy_store_set_dsl_with_source
);

main!(library_benchmark_groups = policy_store);
