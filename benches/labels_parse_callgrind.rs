use gungraun::{library_benchmark, library_benchmark_group, main};
use std::sync::Arc;
use treetop_core::Labeler;
use treetop_rest::state::parse_labels;

const LABELS_JSON: &str = include_str!("../testdata/labels.json");

type ParsedLabels = Vec<Arc<dyn Labeler>>;

fn teardown(_: ParsedLabels) {}

#[library_benchmark(teardown = teardown)]
fn parse_labels_only() -> ParsedLabels {
    parse_labels(LABELS_JSON).unwrap()
}

library_benchmark_group!(name = labels_parse; benchmarks = parse_labels_only);

main!(library_benchmark_groups = labels_parse);
