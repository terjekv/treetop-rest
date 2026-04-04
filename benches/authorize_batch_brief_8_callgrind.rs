mod authorize_batch;

use authorize_batch::common::bench_brief;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};

#[library_benchmark]
fn authorize_brief_8() {
    bench_brief(8);
}

library_benchmark_group!(name = authorize_batch_brief_8; benchmarks = authorize_brief_8);

main!(library_benchmark_groups = authorize_batch_brief_8);
