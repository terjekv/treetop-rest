use utoipa::OpenApi;

#[test]
fn docs_openapi_json_matches_generated_spec() {
    let generated = serde_json::to_string_pretty(&treetop_rest::handlers::ApiDoc::openapi())
        .expect("OpenAPI spec should serialize");
    let checked_in = include_str!("../docs/openapi.json").trim_end();

    assert_eq!(
        checked_in, generated,
        "docs/openapi.json is stale; run `cargo run --example openapi > docs/openapi.json`"
    );
}
