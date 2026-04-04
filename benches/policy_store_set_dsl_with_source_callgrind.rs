use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::str::FromStr;
use treetop_rest::models::Endpoint;
use treetop_rest::state::PolicyStore;

const DSL_DNS: &str = include_str!("../testdata/dns.cedar");

fn setup_store_with_source() -> (PolicyStore, Endpoint) {
    let store = PolicyStore::new().unwrap();
    let endpoint = Endpoint::from_str("https://example.com/policies").unwrap();
    (store, endpoint)
}

#[library_benchmark(setup = setup_store_with_source)]
fn policy_store_set_dsl_with_source((mut store, endpoint): (PolicyStore, Endpoint)) {
    store.set_dsl(DSL_DNS, Some(endpoint), Some(60)).unwrap();
}

library_benchmark_group!(name = policy_store_set_dsl_with_source_group; benchmarks = policy_store_set_dsl_with_source);

main!(library_benchmark_groups = policy_store_set_dsl_with_source_group);
