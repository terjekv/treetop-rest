use crate::build_info::build_info;
use crate::errors::ServiceError;
use crate::models::{
    BatchCheckDetailedResponse, BatchCheckRequest, BatchCheckResponse, BatchResult, CheckResponse,
    CheckResponseBrief, IndexedResult, PoliciesDownload, PoliciesMetadata, UserPolicies,
};
use crate::state::SharedPolicyStore;

use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use prometheus::Registry;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use treetop_core::{PolicyVersion, Request};
use utoipa::{OpenApi, ToSchema};

#[derive(Deserialize, ToSchema)]
struct Upload {
    policies: String,
}

/// Configure routes for the service.
pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/status", web::get().to(get_status))
        .route("/api/v1/health", web::get().to(health))
        .route("/api/v1/version", web::get().to(version))
        .route("/api/v1/check", web::post().to(check))
        .route("/api/v1/check_detailed", web::post().to(check_detailed))
        .route("/api/v1/batch_check", web::post().to(batch_check))
        .route(
            "/api/v1/batch_check_detailed",
            web::post().to(batch_check_detailed),
        )
        .route("/api/v1/policies", web::get().to(get_policies))
        .route("/api/v1/policies", web::post().to(upload_policies))
        .route("/api/v1/policies/{user}", web::get().to(list_policies))
        .route("/metrics", web::get().to(metrics));
}

#[derive(OpenApi)]
#[openapi(
    tags(
        (name = "Treetop REST API", description = "API for Treetop policy management and evaluation")
    ),
    paths(
        check,
        check_detailed,
        batch_check,
        batch_check_detailed,
        get_policies,
        upload_policies,
        list_policies,
        get_status,
        health,
        version,
        metrics,
    ),
)]
pub struct ApiDoc;

#[derive(Serialize, ToSchema)]
pub struct HealthOK {}

#[utoipa::path(
        post,
        path = "/api/v1/health",
        responses(
            (status = 200, description = "All systems OK", body = HealthOK),
        ),
    )]
pub async fn health() -> Result<web::Json<HealthOK>, ServiceError> {
    Ok(web::Json(HealthOK {}))
}

#[derive(Serialize, ToSchema, Deserialize)]
pub struct Core {
    pub version: String,
    pub cedar: String,
}

#[derive(Serialize, ToSchema, Deserialize)]
pub struct VersionInfo {
    pub version: String,
    pub core: Core,
    pub policies: PolicyVersion,
}

#[utoipa::path(
        post,
        path = "/api/v1/version",
        responses(
            (status = 200, description = "Version information", body = VersionInfo),
        ),
    )]
pub async fn version(
    store: web::Data<SharedPolicyStore>,
) -> Result<web::Json<VersionInfo>, ServiceError> {
    let build_info = build_info();
    Ok(web::Json(VersionInfo {
        version: build_info.version.clone(),
        core: Core {
            version: build_info.core.clone(),
            cedar: build_info.cedar.to_string(),
        },
        policies: store.lock()?.engine.current_version(),
    }))
}

#[utoipa::path(
        post,
        path = "/api/v1/check",
        responses(
            (status = 200, description = "Check performed successfully", body = CheckResponseBrief),
            (status = 400, description = "Bad request", body = ServiceError),
            (status = 500, description = "Internal server error", body = ServiceError)
        ),
    )]
pub async fn check(
    store: web::Data<SharedPolicyStore>,
    req: web::Json<Request>,
) -> Result<web::Json<CheckResponseBrief>, ServiceError> {
    let store = store.lock()?;
    match store.engine.evaluate(&req) {
        Ok(full_decision) => Ok(web::Json(full_decision.into())),
        Err(e) => Err(ServiceError::EvaluationError(e.to_string())),
    }
}

#[utoipa::path(
        post,
        path = "/api/v1/check_detailed",
        responses(
            (status = 200, description = "Check performed successfully", body = CheckResponse),
            (status = 400, description = "Bad request", body = ServiceError),
            (status = 500, description = "Internal server error", body = ServiceError)
        ),
    )]
pub async fn check_detailed(
    store: web::Data<SharedPolicyStore>,
    req: web::Json<Request>,
) -> Result<web::Json<CheckResponse>, ServiceError> {
    let store = store.lock()?;
    match store.engine.evaluate(&req) {
        Ok(decision) => Ok(web::Json(CheckResponse::from(decision))),
        Err(e) => Err(ServiceError::EvaluationError(e.to_string())),
    }
}

#[utoipa::path(
        post,
        path = "/api/v1/batch_check",
        request_body = BatchCheckRequest,
        responses(
            (status = 200, description = "Batch check performed successfully", body = BatchCheckResponse),
            (status = 400, description = "Bad request", body = ServiceError),
            (status = 500, description = "Internal server error", body = ServiceError)
        ),
    )]
pub async fn batch_check(
    store: web::Data<SharedPolicyStore>,
    req: web::Json<BatchCheckRequest>,
) -> Result<web::Json<BatchCheckResponse>, ServiceError> {
    let store = store.lock()?;
    let engine_snapshot = store.engine.clone();
    let version = engine_snapshot.current_version();

    // Release the lock before parallel processing
    drop(store);

    // Process in parallel using rayon
    let results: Vec<IndexedResult<CheckResponseBrief>> = req
        .requests
        .par_iter()
        .enumerate()
        .map(|(index, request)| {
            let result = match engine_snapshot.evaluate(request) {
                Ok(decision) => BatchResult::Success {
                    data: CheckResponseBrief::from(decision),
                },
                Err(e) => BatchResult::Error {
                    message: e.to_string(),
                },
            };
            IndexedResult { index, result }
        })
        .collect();

    let successful = results
        .iter()
        .filter(|r| matches!(r.result, BatchResult::Success { .. }))
        .count();
    let failed = results.len() - successful;

    Ok(web::Json(BatchCheckResponse {
        results,
        version,
        successful,
        failed,
    }))
}

#[utoipa::path(
        post,
        path = "/api/v1/batch_check_detailed",
        request_body = BatchCheckRequest,
        responses(
            (status = 200, description = "Batch check performed successfully", body = BatchCheckDetailedResponse),
            (status = 400, description = "Bad request", body = ServiceError),
            (status = 500, description = "Internal server error", body = ServiceError)
        ),
    )]
pub async fn batch_check_detailed(
    store: web::Data<SharedPolicyStore>,
    req: web::Json<BatchCheckRequest>,
) -> Result<web::Json<BatchCheckDetailedResponse>, ServiceError> {
    let store = store.lock()?;
    let engine_snapshot = store.engine.clone();
    let version = engine_snapshot.current_version();

    // Release the lock before parallel processing
    drop(store);

    // Process in parallel using rayon
    let results: Vec<IndexedResult<CheckResponse>> = req
        .requests
        .par_iter()
        .enumerate()
        .map(|(index, request)| {
            let result = match engine_snapshot.evaluate(request) {
                Ok(decision) => BatchResult::Success {
                    data: CheckResponse::from(decision),
                },
                Err(e) => BatchResult::Error {
                    message: e.to_string(),
                },
            };
            IndexedResult { index, result }
        })
        .collect();

    let successful = results
        .iter()
        .filter(|r| matches!(r.result, BatchResult::Success { .. }))
        .count();
    let failed = results.len() - successful;

    Ok(web::Json(BatchCheckDetailedResponse {
        results,
        version,
        successful,
        failed,
    }))
}

#[utoipa::path(
        get,
        path = "/api/v1/policies",
        responses(
            (status = 200, description = "Policies retrieved successfully", body = PoliciesDownload),
            (status = 400, description = "Bad request", body = ServiceError),
            (status = 500, description = "Internal server error", body = ServiceError)
        ),
    )]
pub async fn get_policies(
    query: web::Query<HashMap<String, String>>,
    store: web::Data<SharedPolicyStore>,
) -> Result<HttpResponse, ServiceError> {
    let format = query.get("format").map(String::as_str).unwrap_or("json");
    let store = store.lock()?;

    if format.eq_ignore_ascii_case("raw") || format.eq_ignore_ascii_case("text") {
        Ok(HttpResponse::Ok()
            .content_type("text/plain")
            .body(store.policies.content.clone()))
    } else {
        Ok(HttpResponse::Ok().json(PoliciesDownload {
            policies: store.policies.clone(),
        }))
    }
}

#[utoipa::path(
        post,
        path = "/api/v1/policies",
        request_body = Upload,
        responses(
            (status = 200, description = "Policies uploaded successfully", body = PoliciesMetadata),
            (status = 400, description = "Bad request", body = ServiceError),
            (status = 500, description = "Internal server error", body = ServiceError)
        ),
    )]
pub async fn upload_policies(
    req: HttpRequest,
    body: web::Bytes,
    store: web::Data<SharedPolicyStore>,
) -> Result<web::Json<PoliciesMetadata>, ServiceError> {
    // Check that upload is allowed, and if it is, check that the upload token is set in the headers
    let mut guard = store.lock()?;
    if !guard.allow_upload {
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
        let upload: Upload = serde_json::from_slice(&body)?;
        upload.policies
    } else {
        String::from_utf8(body.to_vec()).map_err(|_| ServiceError::InvalidTextPayload)?
    };

    guard.set_dsl(&dsl_string, None, None)?;

    Ok(web::Json(PoliciesMetadata {
        allow_upload: guard.allow_upload,
        policies: guard.policies.clone(),
        labels: guard.labels.clone(),
    }))
}

#[utoipa::path(
        get,
        path = "/api/v1/policies/{user}",
        responses(
            (status = 200, description = "Policies for user retrieved successfully", body = UserPolicies),
            (status = 400, description = "Bad request", body = ServiceError),
            (status = 500, description = "Internal server error", body = ServiceError)
        ),
    )]
pub async fn list_policies(
    store: web::Data<SharedPolicyStore>,
    user: web::Path<String>,
) -> Result<web::Json<UserPolicies>, ServiceError> {
    let store = store.lock()?;
    println!("Listing policies for user: {user}");
    let policies = store.engine.list_policies_for_user(&user, vec![])?;
    Ok(web::Json(policies.into()))
}

#[utoipa::path(
    get,
    path = "/api/v1/status",
    responses(
        (status = 200, description = "Service status retrieved successfully", body = PoliciesMetadata),
        (status = 400, description = "Bad request", body = ServiceError),
        (status = 500, description = "Internal server error", body = ServiceError)
    ),
)]
pub async fn get_status(
    store: web::Data<SharedPolicyStore>,
) -> Result<web::Json<PoliciesMetadata>, ServiceError> {
    Ok(web::Json(store.lock()?.into()))
}

#[utoipa::path(
    get,
    path = "/metrics",
    responses(
        (status = 200, description = "Prometheus metrics"),
    ),
)]
pub async fn metrics(registry: web::Data<Arc<Registry>>) -> Result<HttpResponse, ServiceError> {
    match crate::metrics::encode_registry(&registry) {
        Ok(buf) => Ok(HttpResponse::Ok()
            .content_type("text/plain; version=0.0.4")
            .body(buf)),
        Err(e) => Err(ServiceError::EvaluationError(e.to_string())),
    }
}
