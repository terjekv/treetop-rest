use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use treetop_rest::state::{PolicyStore, parse_labels};

const LABELS_JSON: &str = include_str!("../testdata/labels.json");
const DSL_DEFAULT: &str = include_str!("../testdata/default.cedar");

#[library_benchmark]
fn parse_labels_only() {
    let _ = parse_labels(LABELS_JSON).unwrap();
}

fn setup_store_with_policies() -> PolicyStore {
    let mut store = PolicyStore::new().unwrap();
    store.set_dsl(DSL_DEFAULT, None, None).unwrap();
    store
}

#[library_benchmark(setup = setup_store_with_policies)]
fn policy_store_set_labels(mut store: PolicyStore) {
    store.set_labels(LABELS_JSON, None, None).unwrap();
}

library_benchmark_group!(
    name = labels;
    benchmarks = parse_labels_only, policy_store_set_labels
);

main!(library_benchmark_groups = labels);
