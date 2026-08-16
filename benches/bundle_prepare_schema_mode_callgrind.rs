use gungraun::{library_benchmark, library_benchmark_group, main};
use std::fs;
use std::hint::black_box;
use treetop_bundle::{
    ArchiveLimits, BundleArchive, BundleBuilder, SignaturePolicy, TrustStore, ValidatedBundle,
};
use treetop_rest::config::SchemaValidationMode;
use treetop_rest::state::PolicyStore;

fn setup() -> ValidatedBundle {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    fs::write(
        root.join("policy.cedar"),
        concat!(
            "@id(\"benchmark.allow\")\n",
            "permit (principal, action == Benchmark::Action::\"read\", resource);"
        ),
    )
    .unwrap();
    fs::write(
        root.join("treetop-module.toml"),
        r#"
format_version = 1
name = "benchmark"
namespace = "Benchmark"
policies = ["policy.cedar"]
"#,
    )
    .unwrap();
    let manifest = root.join("treetop-bundle.toml");
    fs::write(
        &manifest,
        r#"
format_version = 1
name = "benchmark"

[[modules]]
manifest = "treetop-module.toml"
role = "ordinary"
"#,
    )
    .unwrap();

    let bytes = BundleBuilder::from_manifest(&manifest)
        .unwrap()
        .build(None)
        .unwrap()
        .into_bytes();
    BundleArchive::from_bytes(bytes)
        .validate(
            SignaturePolicy::AllowUnsigned,
            &TrustStore::new(),
            ArchiveLimits::new(10 * 1024 * 1024, 50 * 1024 * 1024).unwrap(),
        )
        .unwrap()
}

#[library_benchmark(setup = setup)]
fn prepare_schema_free_permissive(validated: ValidatedBundle) {
    black_box(
        PolicyStore::prepare_bundle(&validated, None, None, SchemaValidationMode::Permissive)
            .unwrap(),
    );
}

#[library_benchmark(setup = setup)]
fn reject_schema_free_strict(validated: ValidatedBundle) {
    black_box(
        PolicyStore::prepare_bundle(&validated, None, None, SchemaValidationMode::Strict)
            .err()
            .unwrap(),
    );
}

library_benchmark_group!(
    name = bundle_prepare_schema_mode;
    benchmarks = prepare_schema_free_permissive, reject_schema_free_strict
);

main!(library_benchmark_groups = bundle_prepare_schema_mode);
