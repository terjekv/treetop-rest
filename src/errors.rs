use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use regex::Regex;
use serde::Serialize;
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    sync::{PoisonError, RwLockReadGuard, RwLockWriteGuard},
};
use treetop_bundle::BundleError;
use treetop_core::PolicyError;
use utoipa::ToSchema;

use crate::state::PolicyStore;

#[derive(Debug)]
pub enum ServiceError {
    LockPoison(String),
    InvalidIp,
    InvalidJsonPayload(String),
    InvalidTextPayload,
    UploadNotAllowed,
    InvalidUploadToken,
    UploadTokenNotSet,
    ClientNotAllowed,
    InvalidAccessToken,
    CompileError(String),
    SchemaValidationError(String),
    ContextValidationError(String),
    EvaluationError(String),
    ListPoliciesError(String),
    ValidationError(String),
    InvalidBundle(String),
    BundleTooLarge(String),
    UnsupportedBundleMediaType,
    BundleModeConflict,
}

#[derive(Serialize, ToSchema)]
pub(crate) struct ErrorResponse {
    error: String,
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<ErrorDetails>,
}

#[derive(Serialize, ToSchema)]
struct ErrorDetails {
    line: Option<usize>,
    column: Option<usize>,
}

impl Display for ServiceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ServiceError::LockPoison(msg) => write!(f, "Internal server error: {msg}"),
            ServiceError::InvalidIp => write!(f, "Invalid IP address"),
            ServiceError::InvalidJsonPayload(msg) => write!(f, "Invalid JSON payload: {msg}"),
            ServiceError::InvalidTextPayload => write!(f, "Invalid text payload"),
            ServiceError::CompileError(msg) => write!(f, "Failed to compile policies: {msg}"),
            ServiceError::EvaluationError(msg) => write!(f, "Policy evaluation error: {msg}"),
            ServiceError::ListPoliciesError(_) => write!(f, "Error listing policies"),
            ServiceError::UploadNotAllowed => write!(f, "Policy upload is not allowed"),
            ServiceError::InvalidUploadToken => write!(f, "Invalid upload token provided"),
            ServiceError::UploadTokenNotSet => write!(f, "Upload token is not set"),
            ServiceError::ClientNotAllowed => write!(f, "Client is not allowed"),
            ServiceError::InvalidAccessToken => write!(f, "Invalid or missing access token"),
            ServiceError::ValidationError(msg) => write!(f, "Validation error: {msg}"),
            ServiceError::InvalidBundle(msg) => write!(f, "Invalid bundle: {msg}"),
            ServiceError::BundleTooLarge(msg) => write!(f, "Bundle too large: {msg}"),
            ServiceError::UnsupportedBundleMediaType => {
                write!(
                    f,
                    "Bundle uploads require application/gzip or application/x-gzip"
                )
            }
            ServiceError::BundleModeConflict => write!(
                f,
                "Individual policy and schema uploads are disabled in bundle URL mode"
            ),
            ServiceError::SchemaValidationError(msg) => {
                write!(f, "Schema validation error: {msg}")
            }
            ServiceError::ContextValidationError(msg) => {
                write!(f, "Context validation error: {msg}")
            }
        }
    }
}

impl ResponseError for ServiceError {
    fn status_code(&self) -> StatusCode {
        match self {
            ServiceError::LockPoison(_)
            | ServiceError::EvaluationError(_)
            | ServiceError::ListPoliciesError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ServiceError::InvalidIp
            | ServiceError::InvalidJsonPayload(_)
            | ServiceError::InvalidTextPayload
            | ServiceError::ValidationError(_)
            | ServiceError::CompileError(_)
            | ServiceError::SchemaValidationError(_)
            | ServiceError::ContextValidationError(_) => StatusCode::BAD_REQUEST,
            ServiceError::InvalidBundle(_) => StatusCode::BAD_REQUEST,
            ServiceError::BundleTooLarge(_) => StatusCode::PAYLOAD_TOO_LARGE,
            ServiceError::UnsupportedBundleMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ServiceError::BundleModeConflict => StatusCode::CONFLICT,
            ServiceError::UploadNotAllowed
            | ServiceError::InvalidUploadToken
            | ServiceError::UploadTokenNotSet
            | ServiceError::ClientNotAllowed => StatusCode::FORBIDDEN,
            ServiceError::InvalidAccessToken => StatusCode::UNAUTHORIZED,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let err = ErrorResponse {
            error: self.to_string(),
            code: self.code().to_string(),
            details: self.details(),
        };
        HttpResponse::build(self.status_code()).json(err)
    }
}

impl ServiceError {
    fn code(&self) -> &'static str {
        match self {
            ServiceError::LockPoison(_) => "lock_poisoned",
            ServiceError::InvalidIp => "invalid_ip",
            ServiceError::InvalidJsonPayload(_) => "invalid_json_payload",
            ServiceError::InvalidTextPayload => "invalid_text_payload",
            ServiceError::UploadNotAllowed => "upload_not_allowed",
            ServiceError::InvalidUploadToken => "invalid_upload_token",
            ServiceError::UploadTokenNotSet => "upload_token_not_set",
            ServiceError::ClientNotAllowed => "client_not_allowed",
            ServiceError::InvalidAccessToken => "invalid_access_token",
            ServiceError::CompileError(_) => "compile_error",
            ServiceError::SchemaValidationError(_) => "schema_validation_error",
            ServiceError::ContextValidationError(_) => "context_validation_error",
            ServiceError::EvaluationError(_) => "evaluation_error",
            ServiceError::ListPoliciesError(_) => "list_policies_error",
            ServiceError::ValidationError(_) => "validation_error",
            ServiceError::InvalidBundle(_) => "invalid_bundle",
            ServiceError::BundleTooLarge(_) => "bundle_too_large",
            ServiceError::UnsupportedBundleMediaType => "unsupported_bundle_media_type",
            ServiceError::BundleModeConflict => "bundle_mode_conflict",
        }
    }

    fn details(&self) -> Option<ErrorDetails> {
        let msg = match self {
            ServiceError::CompileError(msg) | ServiceError::SchemaValidationError(msg) => msg,
            _ => return None,
        };

        // Capture optional line/column hints commonly emitted by Cedar parsers.
        let re = Regex::new(r"(?i)line\D*(\d+)(?:\D+column\D*(\d+))?").ok()?;
        let caps = re.captures(msg)?;
        let line = caps.get(1).and_then(|m| m.as_str().parse::<usize>().ok());
        let column = caps.get(2).and_then(|m| m.as_str().parse::<usize>().ok());
        Some(ErrorDetails { line, column })
    }
}

impl From<PolicyError> for ServiceError {
    fn from(err: PolicyError) -> Self {
        match err {
            PolicyError::ParseError(msg) => ServiceError::CompileError(msg),
            PolicyError::EvalError(msg)
            | PolicyError::EntityError(msg)
            | PolicyError::EntityAttrError(msg) => ServiceError::EvaluationError(msg),
            PolicyError::RequestValidationError(msg) | PolicyError::InvalidFormat(msg) => {
                ServiceError::ValidationError(msg)
            }
            PolicyError::ContextError(msg) => ServiceError::ContextValidationError(msg),
            err => ServiceError::EvaluationError(err.to_string()),
        }
    }
}

impl From<BundleError> for ServiceError {
    fn from(error: BundleError) -> Self {
        match error {
            BundleError::SizeLimit { .. } => ServiceError::BundleTooLarge(error.to_string()),
            BundleError::Validation(diagnostics) => ServiceError::InvalidBundle(
                diagnostics
                    .into_iter()
                    .map(|diagnostic| diagnostic.message)
                    .collect::<Vec<_>>()
                    .join("; "),
            ),
            _ => ServiceError::InvalidBundle(error.to_string()),
        }
    }
}

impl From<PoisonError<RwLockReadGuard<'_, PolicyStore>>> for ServiceError {
    fn from(e: PoisonError<RwLockReadGuard<'_, PolicyStore>>) -> Self {
        ServiceError::LockPoison(e.to_string())
    }
}

impl From<PoisonError<RwLockWriteGuard<'_, PolicyStore>>> for ServiceError {
    fn from(e: PoisonError<RwLockWriteGuard<'_, PolicyStore>>) -> Self {
        ServiceError::LockPoison(e.to_string())
    }
}

impl From<serde_json::Error> for ServiceError {
    fn from(e: serde_json::Error) -> Self {
        ServiceError::InvalidJsonPayload(e.to_string())
    }
}

impl std::error::Error for ServiceError {}
