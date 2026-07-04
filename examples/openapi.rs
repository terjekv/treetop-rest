use utoipa::OpenApi;

fn main() {
    let spec = treetop_rest::handlers::ApiDoc::openapi();
    println!(
        "{}",
        serde_json::to_string_pretty(&spec).expect("OpenAPI spec should serialize")
    );
}
