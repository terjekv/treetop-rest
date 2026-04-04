use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use regex::Regex;
use serde::Serialize;
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    sync::{PoisonError, RwLockReadGuard, RwLockWriteGuard},
};
use treetop_core::PolicyError;
use utoipa::ToSchema;

use crate::state::PolicyStore;

#[derive(Debug, ToSchema)]
#[allow(dead_code)]
pub enum ServiceError {
    LockPoison(String),
    InvalidIp,
    InvalidJsonPayload(String),
    InvalidTextPayload,
    UploadNotAllowed,
    InvalidUploadToken,
    UploadTokenNotSet,
    CompileError(String),
    SchemaValidationError(String),
    ContextValidationError(String),
    EvaluationError(String),
    ListPoliciesError(String),
    ValidationError(String),
}

#[derive(Serialize)]
struct JsonError {
    error: String,
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<JsonErrorDetails>,
}

#[derive(Serialize)]
struct JsonErrorDetails {
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
            ServiceError::ValidationError(msg) => write!(f, "Validation error: {msg}"),
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
            ServiceError::UploadNotAllowed
            | ServiceError::InvalidUploadToken
            | ServiceError::UploadTokenNotSet => StatusCode::FORBIDDEN,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let err = JsonError {
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
            ServiceError::CompileError(_) => "compile_error",
            ServiceError::SchemaValidationError(_) => "schema_validation_error",
            ServiceError::ContextValidationError(_) => "context_validation_error",
            ServiceError::EvaluationError(_) => "evaluation_error",
            ServiceError::ListPoliciesError(_) => "list_policies_error",
            ServiceError::ValidationError(_) => "validation_error",
        }
    }

    fn details(&self) -> Option<JsonErrorDetails> {
        let msg = match self {
            ServiceError::CompileError(msg) | ServiceError::SchemaValidationError(msg) => msg,
            _ => return None,
        };

        // Capture optional line/column hints commonly emitted by Cedar parsers.
        let re = Regex::new(r"(?i)line\D*(\d+)(?:\D+column\D*(\d+))?").ok()?;
        let caps = re.captures(msg)?;
        let line = caps.get(1).and_then(|m| m.as_str().parse::<usize>().ok());
        let column = caps.get(2).and_then(|m| m.as_str().parse::<usize>().ok());
        Some(JsonErrorDetails { line, column })
    }
}

impl From<PolicyError> for ServiceError {
    fn from(err: PolicyError) -> Self {
        ServiceError::CompileError(err.to_string())
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
