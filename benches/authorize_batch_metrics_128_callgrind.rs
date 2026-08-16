mod authorize_batch;

use authorize_batch::common::{BatchContext, setup_batch, teardown_batch};
use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_rest::metrics::init_prometheus;
use treetop_rest::models::AuthorizeDecisionBrief;

fn setup_metrics() -> BatchContext {
    init_prometheus().expect("Prometheus metrics should initialize");
    setup_batch(128)
}

#[library_benchmark(setup = setup_metrics, teardown = teardown_batch)]
fn authorize_batch_metrics_128(context: BatchContext) -> BatchContext {
    context.evaluate(AuthorizeDecisionBrief::from);
    context
}

library_benchmark_group!(
    name = authorize_batch_metrics_128_group;
    benchmarks = authorize_batch_metrics_128
);

main!(library_benchmark_groups = authorize_batch_metrics_128_group);
