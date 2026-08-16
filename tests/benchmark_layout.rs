use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

#[test]
fn benchmark_targets_follow_callgrind_discovery_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    assert!(
        manifest
            .lines()
            .any(|line| line.trim() == "autobenches = false"),
        "explicit benchmark registration requires autobenches = false"
    );

    let mut declared = BTreeSet::new();
    for block in manifest.split("[[bench]]").skip(1) {
        let block = block.split("\n[[").next().unwrap();
        let name = string_value(block, "name").expect("every [[bench]] must declare a name");
        assert!(
            name.ends_with("_callgrind"),
            "benchmark target {name} must use the _callgrind suffix"
        );
        assert!(
            block.lines().any(|line| line.trim() == "harness = false"),
            "benchmark target {name} must set harness = false"
        );
        assert!(
            declared.insert(name.to_string()),
            "duplicate benchmark {name}"
        );
    }

    let discovered = fs::read_dir(root.join("benches"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|ext| ext == "rs"))
        .map(|path| {
            let source = fs::read_to_string(&path).unwrap();
            assert!(
                source.contains("teardown ="),
                "benchmark {} must move fixture and result destruction into teardown",
                path.display()
            );
            let stem = path.file_stem().unwrap().to_str().unwrap().to_string();
            assert!(
                stem.ends_with("_callgrind"),
                "top-level benchmark {} must use the _callgrind suffix",
                path.display()
            );
            stem
        })
        .collect::<BTreeSet<_>>();

    assert_eq!(
        declared, discovered,
        "Cargo benchmark targets must exactly match top-level benches/*_callgrind.rs files"
    );
}

fn string_value<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    block.lines().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        (candidate.trim() == key)
            .then(|| value.trim().strip_prefix('"')?.strip_suffix('"'))
            .flatten()
    })
}
