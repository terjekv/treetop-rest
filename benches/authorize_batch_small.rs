mod authorize_batch;

use authorize_batch::common::{bench_brief, bench_detailed};
use iai_callgrind::{library_benchmark, library_benchmark_group, main};

#[library_benchmark]
fn authorize_brief_8() {
    bench_brief(8);
}

#[library_benchmark]
fn authorize_brief_32() {
    bench_brief(32);
}

#[library_benchmark]
fn authorize_detailed_8() {
    bench_detailed(8);
}

#[library_benchmark]
fn authorize_detailed_32() {
    bench_detailed(32);
}

library_benchmark_group!(
    name = authorize_batch_small;
    benchmarks = authorize_brief_8,
        authorize_brief_32,
        authorize_detailed_8,
        authorize_detailed_32
);

main!(library_benchmark_groups = authorize_batch_small);
