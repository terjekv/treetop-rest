use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_rest::state::PolicyStore;

const LABELS_JSON: &str = include_str!("../testdata/labels.json");
const DSL_DEFAULT: &str = include_str!("../testdata/default.cedar");

fn setup_store_with_policies() -> PolicyStore {
    let mut store = PolicyStore::new().unwrap();
    store.set_dsl(DSL_DEFAULT, None, None).unwrap();
    store
}

fn teardown_store(_: PolicyStore) {}

#[library_benchmark(setup = setup_store_with_policies, teardown = teardown_store)]
fn policy_store_set_labels(mut store: PolicyStore) -> PolicyStore {
    store.set_labels(LABELS_JSON, None, None).unwrap();
    store
}

library_benchmark_group!(
    name = labels_policy_store;
    benchmarks = policy_store_set_labels
);

main!(library_benchmark_groups = labels_policy_store);
