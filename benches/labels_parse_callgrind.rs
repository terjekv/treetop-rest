use gungraun::{library_benchmark, library_benchmark_group, main};
use treetop_rest::state::parse_labels;

const LABELS_JSON: &str = include_str!("../testdata/labels.json");

#[library_benchmark]
fn parse_labels_only() {
    let _ = parse_labels(LABELS_JSON).unwrap();
}

library_benchmark_group!(name = labels_parse; benchmarks = parse_labels_only);

main!(library_benchmark_groups = labels_parse);
