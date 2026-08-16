use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use treetop_rest::config::AdmissionConfig;

fn setup() -> AdmissionConfig {
    AdmissionConfig::default()
}

fn teardown(_: AdmissionConfig) {}

#[library_benchmark(setup = setup, teardown = teardown)]
fn access_disabled(config: AdmissionConfig) -> AdmissionConfig {
    black_box(config.enabled());
    config
}

library_benchmark_group!(name = middleware_access_disabled; benchmarks = access_disabled);

main!(library_benchmark_groups = middleware_access_disabled);
