mod authorize_batch;

use authorize_batch::common::{BatchContext, setup_batch, teardown_batch};
use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_rest::models::AuthorizeDecisionDetailed;

fn setup() -> BatchContext {
    setup_batch(8)
}

#[library_benchmark(setup = setup, teardown = teardown_batch)]
fn authorize_detailed_8(context: BatchContext) -> BatchContext {
    context.evaluate(AuthorizeDecisionDetailed::from);
    context
}

library_benchmark_group!(name = authorize_batch_detailed_8; benchmarks = authorize_detailed_8);

main!(library_benchmark_groups = authorize_batch_detailed_8);
