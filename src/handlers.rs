use actix_web::{HttpMessage, HttpRequest, HttpResponse, web};
use prometheus::Registry;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;
use treetop_core::PolicyVersion;
use url::form_urlencoded;
use utoipa::{OpenApi, ToSchema};

use crate::build_info::build_info;
use crate::errors::ServiceError;
use crate::models::{
    AuthRequest, AuthorizeBriefResponse, AuthorizeDecisionBrief, AuthorizeDecisionDetailed,
    AuthorizeDetailedResponse, AuthorizeRequest, AuthorizeResponseVariant, BatchResult,
    IndexedResult, PoliciesDownload, PoliciesMetadata, StatusResponse, UserPolicies,
};
use crate::parallel::ParallelConfig;
use crate::state::SharedPolicyStore;

fn parse_group_and_namespace(req: &HttpRequest) -> (Vec<String>, Vec<String>) {
    let mut groups = Vec::new();
    let mut namespaces = Vec::new();

    for (key, value) in form_urlencoded::parse(req.query_string().as_bytes()) {
        match key.as_ref() {
            "groups" | "groups[]" => groups.push(value.into_owned()),
            "namespaces" | "namespaces[]" => namespaces.push(value.into_owned()),
            _ => {}
        }
    }

    (groups, namespaces)
}

fn should_return_raw_format(format: Option<&str>) -> bool {
    format.is_some_and(|fmt| {
        fmt.eq_ignore_ascii_case("raw") || fmt.eq_ignore_ascii_case("text")
    })
}

#[derive(Deserialize, ToSchema)]
struct Upload {
    policies: String,
}

/// Configure routes for the service.
pub fn init(cfg: &mut web::ServiceConfig) {
    cfg.route("/api/v1/status", web::get().to(get_status))
        .route("/api/v1/health", web::get().to(health))
        .route("/api/v1/version", web::get().to(version))
        // New unified endpoint
        .route("/api/v1/authorize", web::post().to(authorize))
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
        authorize,
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

#[derive(Debug, Clone, Copy)]
enum DetailLevel {
    Brief,
    Full,
}

impl DetailLevel {
    fn from_query(detail: Option<&str>) -> Self {
        match detail {
            Some(d) if d.eq_ignore_ascii_case("full") || d.eq_ignore_ascii_case("detailed") => {
                DetailLevel::Full
            }
            _ => DetailLevel::Brief,
        }
    }
}

/// Evaluate a single authorization request and produce an indexed result.
fn eval_one<T, F>(
    index: usize,
    auth_req: &AuthRequest,
    engine_snapshot: &std::sync::Arc<treetop_core::PolicyEngine>,
    map_fn: &F,
) -> IndexedResult<T>
where
    T: Send,
    F: Fn(treetop_core::Decision) -> T + Send + Sync,
{
    let result = match engine_snapshot.evaluate(&auth_req.request) {
        Ok(decision) => BatchResult::Success {
            data: map_fn(decision),
        },
        Err(e) => BatchResult::Failed {
            message: e.to_string(),
        },
    };
    IndexedResult::new(index, auth_req.id.clone(), result)
}

/// Generic helper to evaluate batch requests and return results with counts
fn evaluate_batch_requests<T, F>(
    requests: &[AuthRequest],
    engine_snapshot: &std::sync::Arc<treetop_core::PolicyEngine>,
    parallel: &ParallelConfig,
    map_fn: F,
) -> (Vec<IndexedResult<T>>, usize, usize)
where
    T: Send,
    F: Fn(treetop_core::Decision) -> T + Send + Sync,
{
    let use_parallel = parallel.allow_parallel && requests.len() >= parallel.par_threshold;

    let results: Vec<IndexedResult<T>> = if use_parallel {
        requests
            .par_iter()
            .with_min_len(parallel.par_threshold)
            .enumerate()
            .map(|(index, auth_req)| eval_one(index, auth_req, engine_snapshot, &map_fn))
            .collect()
    } else {
        requests
            .iter()
            .enumerate()
            .map(|(index, auth_req)| eval_one(index, auth_req, engine_snapshot, &map_fn))
            .collect()
    };

    let successful = results
        .iter()
        .filter(|r| matches!(r.result(), BatchResult::Success { .. }))
        .count();
    let failed = results.len() - successful;

    (results, successful, failed)
}

#[doc(hidden)]
pub fn evaluate_batch_requests_for_bench<T, F>(
    requests: &[AuthRequest],
    engine_snapshot: &std::sync::Arc<treetop_core::PolicyEngine>,
    parallel: &ParallelConfig,
    map_fn: F,
) -> (Vec<IndexedResult<T>>, usize, usize)
where
    T: Send,
    F: Fn(treetop_core::Decision) -> T + Send + Sync,
{
    evaluate_batch_requests(requests, engine_snapshot, parallel, map_fn)
}

#[derive(serde::Deserialize)]
pub struct AuthorizeQuery {
    /// Response detail level: 'brief' (default) or 'full'
    detail: Option<String>,
}

#[utoipa::path(
        post,
        path = "/api/v1/authorize",
        params(
            ("detail" = Option<String>, Query, description = "Response detail level: 'brief' (default) or 'full'"),
        ),
        responses(
            (status = 200, description = "Authorize performed successfully", body = AuthorizeResponseVariant),
            (status = 400, description = "Bad request", body = ServiceError),
            (status = 500, description = "Internal server error", body = ServiceError)
        ),
    )]
pub async fn authorize(
    store: web::Data<SharedPolicyStore>,
    parallel: web::Data<ParallelConfig>,
    query: web::Query<AuthorizeQuery>,
    req: web::Json<AuthorizeRequest>,
) -> Result<web::Json<AuthorizeResponseVariant>, ServiceError> {
    let store = store.lock()?;
    let engine_snapshot = store.engine.clone();
    let version = engine_snapshot.current_version();

    // Release the lock before parallel processing
    drop(store);

    let detail_level = DetailLevel::from_query(query.detail.as_deref());

    match detail_level {
        DetailLevel::Full => {
            let (results, successful, failed) = evaluate_batch_requests(
                &req.requests,
                &engine_snapshot,
                &parallel,
                AuthorizeDecisionDetailed::from,
            );

            Ok(web::Json(AuthorizeResponseVariant::Detailed(
                AuthorizeDetailedResponse::new(results, version, successful, failed),
            )))
        }
        DetailLevel::Brief => {
            let (results, successful, failed) = evaluate_batch_requests(
                &req.requests,
                &engine_snapshot,
                &parallel,
                AuthorizeDecisionBrief::from,
            );

            Ok(web::Json(AuthorizeResponseVariant::Brief(
                AuthorizeBriefResponse::new(results, version, successful, failed),
            )))
        }
    }
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
    let format = query.get("format").map(String::as_str);
    let store = store.lock()?;

    if should_return_raw_format(format) {
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
        params(
            ("user" = String, Path, description = "User principal identifier"),
            ("groups" = Option<Vec<String>>, Query, description = "List of group names"),
            ("namespaces" = Option<Vec<String>>, Query, description = "List of namespaces"),
            ("format" = Option<String>, Query, description = "Response format: 'json' (default) or 'raw'/'text' for plain text"),
        ),
        responses(
            (status = 200, description = "Policies for user retrieved successfully", body = UserPolicies),
            (status = 400, description = "Bad request", body = ServiceError),
            (status = 500, description = "Internal server error", body = ServiceError)
        ),
    )]
pub async fn list_policies(
    store: web::Data<SharedPolicyStore>,
    user: web::Path<String>,
    req: HttpRequest,
) -> Result<HttpResponse, ServiceError> {
    let store = store.lock()?;

    // User path parameter is just the entity ID
    let entity_id = user.into_inner();

    // Use namespace and groups from query parameters
    let (groups, namespaces) = parse_group_and_namespace(&req);
    let namespace: Vec<&str> = namespaces.iter().map(|s| s.as_str()).collect();
    let group_refs: Vec<&str> = groups.iter().map(|s| s.as_str()).collect();

    debug!(message = "Listing policies for user", entity = %entity_id, namespaces = ?namespaces, groups = ?groups);

    let policies = store
        .engine
        .list_policies_for_user(&entity_id, &group_refs, &namespace)?;

    // Check format query parameter
    let format = req
        .query_string()
        .split('&')
        .find(|q| q.starts_with("format="))
        .and_then(|q| q.strip_prefix("format="));

    if should_return_raw_format(format) {
        // Return policies as text/plain: just the policy DSL from the store
        let content = policies
            .policies()
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<String>>()
            .join("\n");
        return Ok(HttpResponse::Ok().content_type("text/plain").body(content));
    }

    // Default: return as JSON
    Ok(HttpResponse::Ok().json(UserPolicies::from(policies)))
}

#[utoipa::path(
    get,
    path = "/api/v1/status",
    responses(
        (status = 200, description = "Service status retrieved successfully", body = StatusResponse),
        (status = 400, description = "Bad request", body = ServiceError),
        (status = 500, description = "Internal server error", body = ServiceError)
    ),
)]
pub async fn get_status(
    store: web::Data<SharedPolicyStore>,
    parallel: web::Data<ParallelConfig>,
) -> Result<web::Json<StatusResponse>, ServiceError> {
    let store = store.lock()?;
    let status = StatusResponse {
        policy_configuration: store.into(),
        parallel_configuration: *parallel.get_ref(),
    };

    Ok(web::Json(status))
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
