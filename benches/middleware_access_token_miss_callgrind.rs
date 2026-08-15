use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_rest::config::AdmissionConfig;

fn setup() -> AdmissionConfig {
    AdmissionConfig::parse(None, Some("benchmark-token"), None).unwrap()
}

#[library_benchmark(setup = setup)]
fn access_token_miss(config: AdmissionConfig) {
    let _ = config.access_tokens.matches("different-token");
}

library_benchmark_group!(name = middleware_access_token_miss; benchmarks = access_token_miss);

main!(library_benchmark_groups = middleware_access_token_miss);
