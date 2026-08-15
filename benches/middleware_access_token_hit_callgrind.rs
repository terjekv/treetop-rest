use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_rest::config::AdmissionConfig;

fn setup() -> AdmissionConfig {
    AdmissionConfig::parse(None, Some("benchmark-token"), None).unwrap()
}

#[library_benchmark(setup = setup)]
fn access_token_hit(config: AdmissionConfig) {
    let _ = config.access_tokens.matches("benchmark-token");
}

library_benchmark_group!(name = middleware_access_token_hit; benchmarks = access_token_hit);

main!(library_benchmark_groups = middleware_access_token_hit);
