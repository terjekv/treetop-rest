use crate::errors::ServiceError;
use crate::models::{
    CheckRequest, CheckResponse, PoliciesDownload, PoliciesMetadata, build_request,
};
use crate::state::SharedPolicyStore;
use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use treetop_core::UserPolicies;

#[derive(Deserialize)]
struct Upload {
    policies: String,
}

/// Configure routes for the service.
pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/status", web::get().to(get_status))
        .route("/api/v1/check", web::post().to(check))
        .route("/api/v1/policies", web::get().to(get_policies))
        .route("/api/v1/policies", web::post().to(upload_policies))
        .route("/api/v1/policies/{user}", web::get().to(list_policies));
}

pub async fn check(
    store: web::Data<SharedPolicyStore>,
    req: web::Json<CheckRequest>,
) -> Result<web::Json<CheckResponse>, ServiceError> {
    let store = store.lock().map_err(|_| ServiceError::LockPoison)?;
    let request = build_request(&req)?;
    match store.engine.evaluate(&request) {
        Ok(decision) => Ok(web::Json(CheckResponse { decision })),
        Err(e) => Err(ServiceError::EvaluationError(e.to_string())),
    }
}

pub async fn get_policies(
    query: web::Query<HashMap<String, String>>,
    store: web::Data<SharedPolicyStore>,
) -> Result<HttpResponse, ServiceError> {
    let format = query.get("format").map(String::as_str).unwrap_or("json");
    let store = store.lock().map_err(|_| ServiceError::LockPoison)?;

    if format.eq_ignore_ascii_case("raw") {
        Ok(HttpResponse::Ok()
            .content_type("text/plain")
            .body(store.dsl.clone()))
    } else {
        Ok(HttpResponse::Ok().json(PoliciesDownload {
            policies: store.dsl.clone(),
            sha256: store.sha256.clone(),
            uploaded_at: store.uploaded_at,
        }))
    }
}

pub async fn upload_policies(
    req: HttpRequest,
    body: web::Bytes,
    store: web::Data<SharedPolicyStore>,
) -> Result<web::Json<PoliciesMetadata>, ServiceError> {
    let content_type = req.content_type();
    let dsl_string = if content_type.starts_with("application/json") {
        let upload: Upload =
            serde_json::from_slice(&body).map_err(|_| ServiceError::InvalidJsonPayload)?;
        upload.policies
    } else {
        String::from_utf8(body.to_vec()).map_err(|_| ServiceError::InvalidTextPayload)?
    };

    let mut hasher = Sha256::new();
    hasher.update(dsl_string.as_bytes());
    let sha256 = format!("{:x}", hasher.finalize());

    let new_engine = treetop_core::PolicyEngine::new_from_str(&dsl_string)
        .map_err(|e| ServiceError::CompileError(e.to_string()))?;

    let mut guard = store.lock().map_err(|_| ServiceError::LockPoison)?;
    guard.engine = Arc::new(new_engine);
    guard.dsl = dsl_string.clone();
    guard.sha256 = sha256.clone();
    guard.uploaded_at = chrono::Utc::now();
    guard.size = dsl_string.len();

    Ok(web::Json(PoliciesMetadata {
        sha256,
        uploaded_at: guard.uploaded_at,
        size: guard.size,
    }))
}

pub async fn list_policies(
    store: web::Data<SharedPolicyStore>,
    user: web::Path<String>,
) -> Result<web::Json<UserPolicies>, ServiceError> {
    let store = store.lock().map_err(|_| ServiceError::LockPoison)?;
    println!("Listing policies for user: {}", user);
    let policies = store
        .engine
        .list_policies_for_user(&user, vec![])
        .map_err(|e| ServiceError::ListPoliciesError(e.to_string()))?;
    Ok(web::Json(policies))
}

pub async fn get_status(
    store: web::Data<SharedPolicyStore>,
) -> Result<web::Json<PoliciesMetadata>, ServiceError> {
    let guard = store.lock().map_err(|_| ServiceError::LockPoison)?;
    Ok(web::Json(PoliciesMetadata {
        sha256: guard.sha256.clone(),
        uploaded_at: guard.uploaded_at,
        size: guard.size,
    }))
}
