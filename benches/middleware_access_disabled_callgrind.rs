use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_rest::config::AdmissionConfig;

fn setup() -> AdmissionConfig {
    AdmissionConfig::default()
}

#[library_benchmark(setup = setup)]
fn access_disabled(config: AdmissionConfig) {
    let _ = config.enabled();
}

library_benchmark_group!(name = middleware_access_disabled; benchmarks = access_disabled);

main!(library_benchmark_groups = middleware_access_disabled);
