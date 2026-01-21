use actix_web::{App, HttpResponse, http::StatusCode, test, web};
use std::str::FromStr;
use treetop_rest::config::ClientAllowlist;
use treetop_rest::middeware::ClientAllowlistMiddleware;

async fn ok_handler() -> HttpResponse {
    HttpResponse::Ok().finish()
}

#[actix_web::test]
async fn allows_whitelisted_ipv4() {
    let app = test::init_service(
        App::new()
            .wrap(ClientAllowlistMiddleware::new_with_trust(
                ClientAllowlist::from_str("10.0.0.0/24").unwrap(),
                true,
            ))
            .route("/", web::get().to(ok_handler)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/")
        .insert_header(("x-forwarded-for", "10.0.0.42"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn rejects_non_whitelisted_ipv4() {
    let app = test::init_service(
        App::new()
            .wrap(ClientAllowlistMiddleware::new_with_trust(
                ClientAllowlist::from_str("10.0.0.0/24").unwrap(),
                true,
            ))
            .route("/", web::get().to(ok_handler)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/")
        .insert_header(("x-forwarded-for", "192.168.1.10"))
        .to_request();

    let resp = test::try_call_service(&app, req).await;
    assert!(resp.is_err());
    let err = resp.unwrap_err();
    assert_eq!(err.error_response().status(), StatusCode::FORBIDDEN);
}

#[actix_web::test]
async fn allows_ipv6_in_range() {
    let app = test::init_service(
        App::new()
            .wrap(ClientAllowlistMiddleware::new_with_trust(
                ClientAllowlist::from_str("2001:db8::/32").unwrap(),
                true,
            ))
            .route("/", web::get().to(ok_handler)),
    )
    .await;
    let req = test::TestRequest::get()
        .uri("/")
        .insert_header(("x-forwarded-for", "2001:db8::1"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[actix_web::test]
async fn ignores_headers_when_trust_disabled() {
    let app = test::init_service(
        App::new()
            .wrap(ClientAllowlistMiddleware::new_with_trust(
                ClientAllowlist::from_str("10.0.0.0/24").unwrap(),
                false,
            ))
            .route("/", web::get().to(ok_handler)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/")
        .insert_header(("x-forwarded-for", "10.0.0.42"))
        .to_request();

    let resp = test::try_call_service(&app, req).await;
    assert!(resp.is_err());
}
