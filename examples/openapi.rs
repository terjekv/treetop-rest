fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(treetop_rest::handlers::openapi_document())
            .expect("OpenAPI spec should serialize")
    );
}
