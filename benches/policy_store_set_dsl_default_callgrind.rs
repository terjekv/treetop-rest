use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_rest::state::PolicyStore;

const DSL_DEFAULT: &str = include_str!("../testdata/default.cedar");

fn setup_store_default() -> PolicyStore {
    PolicyStore::new().unwrap()
}

fn teardown_store(_: PolicyStore) {}

#[library_benchmark(setup = setup_store_default, teardown = teardown_store)]
fn policy_store_set_dsl_default(mut store: PolicyStore) -> PolicyStore {
    store.set_dsl(DSL_DEFAULT, None, None).unwrap();
    store
}

library_benchmark_group!(name = policy_store_set_dsl_default_group; benchmarks = policy_store_set_dsl_default);

main!(library_benchmark_groups = policy_store_set_dsl_default_group);
