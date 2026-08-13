use std::path::Path;

use cargo_metadata::MetadataCommand;
use serde_json::Value;
use vergen::{Build, Cargo, Emitter, Rustc};
use vergen_gitcl::Gitcl;

fn dependency_vcs_sha(package_name: &str) -> Option<String> {
    let metadata = MetadataCommand::new().exec().ok()?;
    let package = metadata
        .packages
        .iter()
        .find(|package| package.name.as_str() == package_name)?;
    let manifest_dir = Path::new(package.manifest_path.as_str()).parent()?;
    let vcs_path = manifest_dir.join(".cargo_vcs_info.json");
    let vcs: Value = serde_json::from_str(&std::fs::read_to_string(vcs_path).ok()?).ok()?;

    vcs.pointer("/git/sha1")?.as_str().map(str::to_owned)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if let Some(core_sha) = dependency_vcs_sha("treetop-core") {
        println!("cargo:rustc-env=TREETOP_CORE_GIT_SHA={core_sha}");
    }

    let git = Gitcl::builder()
        .describe(true, true, None)
        .sha(false)
        .branch(true)
        .dirty(true)
        .build();
    let cargo = Cargo::builder()
        .dependencies(true)
        .features(true)
        .target_triple(true)
        .build();

    let rustc = Rustc::builder().host_triple(true).semver(true).build();
    let build = Build::builder()
        .build_date(true)
        .build_timestamp(true)
        .build();

    Emitter::default()
        .add_instructions(&git)?
        .add_instructions(&cargo)?
        .add_instructions(&rustc)?
        .add_instructions(&build)?
        .emit()?;

    Ok(())
}
