mod authorize_batch;

use authorize_batch::common::bench_brief;
use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_rest::metrics::init_prometheus;

struct MetricsEnabled;

fn setup_metrics() -> MetricsEnabled {
    init_prometheus().expect("Prometheus metrics should initialize");
    MetricsEnabled
}

#[library_benchmark(setup = setup_metrics)]
fn authorize_batch_metrics_128(_: MetricsEnabled) {
    bench_brief(128);
}

library_benchmark_group!(
    name = authorize_batch_metrics_128_group;
    benchmarks = authorize_batch_metrics_128
);

main!(library_benchmark_groups = authorize_batch_metrics_128_group);
