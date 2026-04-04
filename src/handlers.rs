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
use crate::config::SchemaValidationMode;
use crate::errors::ServiceError;
use crate::metrics;
use crate::models::{
    AuthRequest, AuthorizeBriefResponse, AuthorizeDecisionBrief, AuthorizeDecisionDetailed,
    AuthorizeDetailedResponse, AuthorizeRequest, AuthorizeResponseVariant, BatchResult,
    IndexedResult, PoliciesDownload, PoliciesMetadata, RequestLimits, SchemaDownload,
    StatusResponse, UserPolicies,
};
use crate::parallel::ParallelConfig;
use crate::state::SharedPolicyStore;

fn parse_query_params(req: &HttpRequest) -> (Vec<String>, Vec<String>, Option<String>) {
    let mut groups = Vec::new();
    let mut namespaces = Vec::new();
    let mut format = None;

    for (key, value) in form_urlencoded::parse(req.query_string().as_bytes()) {
        match key.as_ref() {
            "groups" | "groups[]" => groups.push(value.into_owned()),
            "namespaces" | "namespaces[]" => namespaces.push(value.into_owned()),
            "format" => format = Some(value.into_owned()),
            _ => {}
        }
    }

    (groups, namespaces, format)
}

fn should_return_raw_format(format: Option<&str>) -> bool {
    matches!(format, Some(fmt) if fmt.eq_ignore_ascii_case("raw") || fmt.eq_ignore_ascii_case("text"))
}

#[derive(Deserialize, ToSchema)]
struct Upload {
    policies: String,
}

#[derive(Deserialize, ToSchema)]
struct SchemaUpload {
    schema: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
pub struct AuthorizeRuntimeConfig {
    pub context_enabled: bool,
    pub max_context_bytes: usize,
    pub max_context_depth: usize,
    pub max_context_keys: usize,
}

impl Default for AuthorizeRuntimeConfig {
    fn default() -> Self {
        Self {
            context_enabled: false,
            max_context_bytes: 16 * 1024,
            max_context_depth: 8,
            max_context_keys: 64,
        }
    }
}

fn check_upload_auth(
    req: &HttpRequest,
    allow_upload: bool,
    token: Option<&str>,
) -> Result<(), ServiceError> {
    if !allow_upload {
        return Err(ServiceError::UploadNotAllowed);
    }

    let Some(expected_token) = token else {
        return Err(ServiceError::UploadTokenNotSet);
    };

    if req
        .headers()
        .get("X-Upload-Token")
        .is_none_or(|h| h.to_str().unwrap_or("") != expected_token)
    {
        return Err(ServiceError::InvalidUploadToken);
    }

    Ok(())
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
        .route("/api/v1/schema", web::get().to(get_schema))
        .route("/api/v1/schema", web::post().to(upload_schema))
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
        get_schema,
        upload_schema,
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
        get,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<SchemaVersionInfo>,
}

#[derive(Serialize, ToSchema, Deserialize)]
pub struct SchemaVersionInfo {
    pub hash: String,
    pub loaded_at: String,
}

#[utoipa::path(
        get,
        path = "/api/v1/version",
        responses(
            (status = 200, description = "Version information", body = VersionInfo),
        ),
    )]
pub async fn version(
    store: web::Data<SharedPolicyStore>,
) -> Result<web::Json<VersionInfo>, ServiceError> {
    let build_info = build_info();
    let store = store.read()?;
    let schema = if store.schema.sha256.is_empty() {
        None
    } else {
        Some(SchemaVersionInfo {
            hash: store.schema.sha256.clone(),
            loaded_at: store.schema.timestamp.to_rfc3339(),
        })
    };
    Ok(web::Json(VersionInfo {
        version: build_info.version.clone(),
        core: Core {
            version: build_info.core.clone(),
            cedar: build_info.cedar.to_string(),
        },
        policies: store.engine.current_version(),
        schema,
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

fn context_value_depth(value: &treetop_core::AttrValue) -> usize {
    match value {
        treetop_core::AttrValue::Set(xs) => {
            1 + xs.iter().map(context_value_depth).max().unwrap_or(0)
        }
        _ => 1,
    }
}

fn validate_request_context(
    auth_req: &AuthRequest,
    runtime: &AuthorizeRuntimeConfig,
    strict_schema: bool,
    schema_loaded: bool,
) -> Result<(), ServiceError> {
    let Some(context) = auth_req.context.as_ref() else {
        return Ok(());
    };

    if context.len() > runtime.max_context_keys {
        metrics::record_context_validation_failure("too_many_keys");
        return Err(ServiceError::ContextValidationError(format!(
            "context has too many keys: {} > {}",
            context.len(),
            runtime.max_context_keys
        )));
    }

    let bytes = serde_json::to_vec(context)
        .map_err(|e| ServiceError::ContextValidationError(e.to_string()))?
        .len();
    if bytes > runtime.max_context_bytes {
        metrics::record_context_validation_failure("too_many_bytes");
        return Err(ServiceError::ContextValidationError(format!(
            "context payload too large: {} bytes > {} bytes",
            bytes, runtime.max_context_bytes
        )));
    }

    let depth = context.values().map(context_value_depth).max().unwrap_or(0);
    if depth > runtime.max_context_depth {
        metrics::record_context_validation_failure("too_deep");
        return Err(ServiceError::ContextValidationError(format!(
            "context nesting depth too high: {} > {}",
            depth, runtime.max_context_depth
        )));
    }

    if strict_schema && !schema_loaded {
        metrics::record_context_validation_failure("missing_schema_strict");
        return Err(ServiceError::ContextValidationError(
            "context requires an uploaded schema in strict validation mode".to_string(),
        ));
    }

    if !runtime.context_enabled {
        metrics::record_context_validation_failure("unsupported_by_core");
        return Err(ServiceError::ContextValidationError(
            "context is not supported by the current core engine version".to_string(),
        ));
    }

    Ok(())
}

/// Evaluate a single authorization request and produce an indexed result.
fn eval_one<T, F>(
    index: usize,
    auth_req: &AuthRequest,
    engine_snapshot: &std::sync::Arc<treetop_core::PolicyEngine>,
    runtime: &AuthorizeRuntimeConfig,
    strict_schema: bool,
    schema_loaded: bool,
    map_fn: &F,
) -> IndexedResult<T>
where
    T: Send,
    F: Fn(treetop_core::Decision) -> T + Send + Sync,
{
    if let Err(e) = validate_request_context(auth_req, runtime, strict_schema, schema_loaded) {
        return IndexedResult::new(
            index,
            auth_req.id.clone(),
            BatchResult::Failed {
                message: e.to_string(),
            },
        );
    }

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
    runtime: &AuthorizeRuntimeConfig,
    strict_schema: bool,
    schema_loaded: bool,
    map_fn: F,
) -> (Vec<IndexedResult<T>>, usize, usize)
where
    T: Send,
    F: Fn(treetop_core::Decision) -> T + Send + Sync,
{
    let use_parallel = parallel.allow_parallel && requests.len() >= parallel.par_threshold;

    let (results, successful) = if use_parallel {
        let results: Vec<IndexedResult<T>> = requests
            .par_iter()
            .with_min_len(parallel.par_threshold)
            .enumerate()
            .map(|(index, auth_req)| {
                eval_one(
                    index,
                    auth_req,
                    engine_snapshot,
                    runtime,
                    strict_schema,
                    schema_loaded,
                    &map_fn,
                )
            })
            .collect();
        // Count successes in the collected results
        let successful = results
            .iter()
            .filter(|r| matches!(r.result(), BatchResult::Success { .. }))
            .count();
        (results, successful)
    } else {
        let mut results = Vec::with_capacity(requests.len());
        let mut successful = 0;
        for (index, auth_req) in requests.iter().enumerate() {
            let result = eval_one(
                index,
                auth_req,
                engine_snapshot,
                runtime,
                strict_schema,
                schema_loaded,
                &map_fn,
            );
            if matches!(result.result(), BatchResult::Success { .. }) {
                successful += 1;
            }
            results.push(result);
        }
        (results, successful)
    };
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
    evaluate_batch_requests(
        requests,
        engine_snapshot,
        parallel,
        &AuthorizeRuntimeConfig::default(),
        false,
        false,
        map_fn,
    )
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
    runtime_cfg: Option<web::Data<AuthorizeRuntimeConfig>>,
    query: web::Query<AuthorizeQuery>,
    req: web::Json<AuthorizeRequest>,
) -> Result<web::Json<AuthorizeResponseVariant>, ServiceError> {
    let store = store.read()?;
    let engine_snapshot = store.engine.clone();
    let version = engine_snapshot.current_version();
    let strict_schema = store.schema_validation_mode == SchemaValidationMode::Strict;
    let schema_loaded = !store.schema.content.is_empty();

    // Release the lock before parallel processing
    drop(store);
    let runtime_cfg = runtime_cfg.map(|cfg| *cfg.get_ref()).unwrap_or_default();

    let detail_level = DetailLevel::from_query(query.detail.as_deref());

    match detail_level {
        DetailLevel::Full => {
            let (results, successful, failed) = evaluate_batch_requests(
                &req.requests,
                &engine_snapshot,
                &parallel,
                &runtime_cfg,
                strict_schema,
                schema_loaded,
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
                &runtime_cfg,
                strict_schema,
                schema_loaded,
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
    let store = store.read()?;

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
    // Parse and validate the body BEFORE acquiring the lock (this can be expensive)
    let content_type = req.content_type();
    let dsl_string = if content_type.starts_with("application/json") {
        let upload: Upload = serde_json::from_slice(&body)?;
        upload.policies
    } else {
        String::from_utf8(body.to_vec()).map_err(|_| ServiceError::InvalidTextPayload)?
    };

    // Validate the DSL before acquiring lock (computationally expensive)
    if dsl_string.is_empty() {
        return Err(ServiceError::InvalidTextPayload);
    }

    // Now acquire lock for authentication and applying changes
    let mut guard = store.write()?;

    check_upload_auth(&req, guard.allow_upload, guard.upload_token.as_deref())?;

    // Apply the validated DSL (this is fast, mostly just Arc assignments)
    guard.set_dsl(&dsl_string, None, None)?;

    Ok(web::Json(PoliciesMetadata {
        allow_upload: guard.allow_upload,
        schema_validation_mode: guard.schema_validation_mode.to_string(),
        policies: guard.policies.clone(),
        labels: guard.labels.clone(),
        schema: guard.schema.clone(),
    }))
}

#[utoipa::path(
        get,
        path = "/api/v1/schema",
        responses(
            (status = 200, description = "Schema retrieved successfully", body = SchemaDownload),
            (status = 400, description = "Bad request", body = ServiceError),
            (status = 500, description = "Internal server error", body = ServiceError)
        ),
    )]
pub async fn get_schema(
    query: web::Query<HashMap<String, String>>,
    store: web::Data<SharedPolicyStore>,
) -> Result<HttpResponse, ServiceError> {
    let format = query.get("format").map(String::as_str);
    let store = store.read()?;

    if should_return_raw_format(format) {
        Ok(HttpResponse::Ok()
            .content_type("text/plain")
            .body(store.schema.content.clone()))
    } else {
        Ok(HttpResponse::Ok().json(SchemaDownload {
            schema: store.schema.clone(),
        }))
    }
}

#[utoipa::path(
        post,
        path = "/api/v1/schema",
        request_body = SchemaUpload,
        responses(
            (status = 200, description = "Schema uploaded successfully", body = PoliciesMetadata),
            (status = 400, description = "Bad request", body = ServiceError),
            (status = 500, description = "Internal server error", body = ServiceError)
        ),
    )]
pub async fn upload_schema(
    req: HttpRequest,
    body: web::Bytes,
    store: web::Data<SharedPolicyStore>,
) -> Result<web::Json<PoliciesMetadata>, ServiceError> {
    let content_type = req.content_type();
    let schema_string = if content_type.starts_with("application/json") {
        match serde_json::from_slice::<SchemaUpload>(&body) {
            Ok(upload) => upload.schema,
            Err(_) => {
                let value: serde_json::Value = serde_json::from_slice(&body)?;
                serde_json::to_string(&value)
                    .map_err(|e| ServiceError::InvalidJsonPayload(e.to_string()))?
            }
        }
    } else {
        String::from_utf8(body.to_vec()).map_err(|_| ServiceError::InvalidTextPayload)?
    };

    if schema_string.trim().is_empty() {
        return Err(ServiceError::InvalidTextPayload);
    }

    let mut guard = store.write()?;
    check_upload_auth(&req, guard.allow_upload, guard.upload_token.as_deref())?;
    guard.set_schema(&schema_string, None, None)?;

    Ok(web::Json(PoliciesMetadata {
        allow_upload: guard.allow_upload,
        schema_validation_mode: guard.schema_validation_mode.to_string(),
        policies: guard.policies.clone(),
        labels: guard.labels.clone(),
        schema: guard.schema.clone(),
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
    let store = store.read()?;

    // User path parameter is just the entity ID
    let entity_id = user.into_inner();

    // Use namespace and groups from query parameters
    let (groups, namespaces, format) = parse_query_params(&req);

    debug!(message = "Listing policies for user", entity = %entity_id, namespaces = ?namespaces, groups = ?groups);

    // Check format query parameter
    if should_return_raw_format(format.as_deref()) {
        let content: std::sync::Arc<String> =
            store.list_policies_raw(entity_id, groups, namespaces)?;
        // Clone the Arc (cheap pointer copy), then clone the String for response
        return Ok(HttpResponse::Ok()
            .content_type("text/plain")
            .body((*content).clone()));
    }

    // Default: return as JSON
    let response: std::sync::Arc<UserPolicies> =
        store.list_policies_json(entity_id, groups, namespaces)?;
    Ok(HttpResponse::Ok().json(response.as_ref()))
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
    runtime_cfg: Option<web::Data<AuthorizeRuntimeConfig>>,
) -> Result<web::Json<StatusResponse>, ServiceError> {
    let store = store.read()?;
    let request_limits = runtime_cfg
        .map(|cfg| RequestLimits {
            max_context_bytes: cfg.max_context_bytes,
            max_context_depth: cfg.max_context_depth,
            max_context_keys: cfg.max_context_keys,
        })
        .unwrap_or_default();
    let status = StatusResponse {
        policy_configuration: store.into(),
        parallel_configuration: *parallel.get_ref(),
        request_limits,
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
