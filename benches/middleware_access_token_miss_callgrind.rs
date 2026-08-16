use gungraun::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;
use treetop_rest::config::AdmissionConfig;

fn setup() -> AdmissionConfig {
    AdmissionConfig::parse(None, Some("benchmark-token"), None).unwrap()
}

fn teardown(_: AdmissionConfig) {}

#[library_benchmark(setup = setup, teardown = teardown)]
fn access_token_miss(config: AdmissionConfig) -> AdmissionConfig {
    black_box(config.access_tokens.matches("different-token"));
    config
}

library_benchmark_group!(name = middleware_access_token_miss; benchmarks = access_token_miss);

main!(library_benchmark_groups = middleware_access_token_miss);
