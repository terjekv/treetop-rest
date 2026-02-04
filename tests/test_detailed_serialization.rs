use actix_web::{App, test, web};
use std::sync::{Arc, Mutex};
use std::str::FromStr;
use treetop_core::{Action, Principal, Request, Resource, User};
use treetop_rest::handlers;
use treetop_rest::models::AuthorizeRequest;
use treetop_rest::parallel::ParallelConfig;
use treetop_rest::state::PolicyStore;

#[actix_web::test]
async fn test_detailed_response_serialization() {
    let mut store = PolicyStore::new().unwrap();
    let dsl = r#"
permit (
    principal == User::"alice",
    action == Action::"view",
    resource == Photo::"VacationPhoto94.jpg"
);
"#;
    store.set_dsl(dsl, None, None).unwrap();
    let store = Arc::new(Mutex::new(store));
    
    let parallel = ParallelConfig::new(1, 1, None);
    
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store))
            .app_data(web::Data::new(parallel))
            .route("/api/v1/authorize", web::post().to(handlers::authorize)),
    )
    .await;

    let request = Request {
        principal: Principal::User(User::from_str("alice").unwrap()),
        action: Action::from_str("view").unwrap(),
        resource: Resource::new("Photo", "VacationPhoto94.jpg"),
    };

    let auth_request = AuthorizeRequest::new().add_with_id("check-1", request);

    let req = test::TestRequest::post()
        .uri("/api/v1/authorize?detail=full")
        .set_json(&auth_request)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    let body = test::read_body(resp).await;
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    
    println!("=== DETAILED RESPONSE ===");
    println!("{}", body_str);
    
    // Also print formatted JSON
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body_str) {
        println!("\n=== FORMATTED ===");
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    }
}
