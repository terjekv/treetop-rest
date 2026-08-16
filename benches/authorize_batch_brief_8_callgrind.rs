mod authorize_batch;

use authorize_batch::common::{BatchContext, setup_batch, teardown_batch};
use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_rest::models::AuthorizeDecisionBrief;

fn setup() -> BatchContext {
    setup_batch(8)
}

#[library_benchmark(setup = setup, teardown = teardown_batch)]
fn authorize_brief_8(context: BatchContext) -> BatchContext {
    context.evaluate(AuthorizeDecisionBrief::from);
    context
}

library_benchmark_group!(name = authorize_batch_brief_8; benchmarks = authorize_brief_8);

main!(library_benchmark_groups = authorize_batch_brief_8);
