use crate::errors::ServiceError;
use crate::models::{
    CheckRequest, CheckResponse, PoliciesDownload, PoliciesMetadata, build_request,
};
use crate::state::SharedPolicyStore;
use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use serde::Deserialize;
use std::collections::HashMap;
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
            sha256: store.policies_sha256.clone(),
            uploaded_at: store.policies_timestamp,
        }))
    }
}

pub async fn upload_policies(
    req: HttpRequest,
    body: web::Bytes,
    store: web::Data<SharedPolicyStore>,
) -> Result<web::Json<PoliciesMetadata>, ServiceError> {
    // Check that upload is allowed, and if it is, check that the upload token is set in the headers
    let mut guard = store.lock().map_err(|_| ServiceError::LockPoison)?;
    if !guard.policies_allow_upload {
        return Err(ServiceError::UploadNotAllowed);
    }

    if let Some(upload_token) = guard.upload_token.as_ref() {
        if req
            .headers()
            .get("X-Upload-Token")
            .is_none_or(|h| h.to_str().unwrap_or("") != upload_token)
        {
            return Err(ServiceError::InvalidUploadToken);
        }
    } else {
        return Err(ServiceError::UploadTokenNotSet);
    }

    let content_type = req.content_type();
    let dsl_string = if content_type.starts_with("application/json") {
        let upload: Upload =
            serde_json::from_slice(&body).map_err(|_| ServiceError::InvalidJsonPayload)?;
        upload.policies
    } else {
        String::from_utf8(body.to_vec()).map_err(|_| ServiceError::InvalidTextPayload)?
    };

    guard.update_dsl(&dsl_string)?;

    Ok(web::Json(PoliciesMetadata {
        policies_sha256: guard.policies_sha256.clone(),
        policies_uploaded_at: guard.policies_timestamp,
        policies_size: guard.policies_size,
        policies_allow_upload: guard.policies_allow_upload,
        policies_url: guard.policies_url.clone(),
        policies_refresh_frequency: guard.policies_refresh_frequency,
        host_labels_url: guard.host_labels_url.clone(),
        host_labels_refresh_frequency: guard.host_labels_refresh_frequency,
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
        policies_sha256: guard.policies_sha256.clone(),
        policies_uploaded_at: guard.policies_timestamp,
        policies_size: guard.policies_size,
        policies_allow_upload: guard.policies_allow_upload,
        policies_url: guard.policies_url.clone(),
        policies_refresh_frequency: guard.policies_refresh_frequency,
        host_labels_url: guard.host_labels_url.clone(),
        host_labels_refresh_frequency: guard.host_labels_refresh_frequency,
    }))
}
