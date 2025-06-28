use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::Serialize;
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    sync::{MutexGuard, PoisonError},
};
use treetop_core::PolicyError;

use crate::state::PolicyStore;

#[derive(Debug)]
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
    EvaluationError(String),
    ListPoliciesError(String),
    ValidationError(String),
}

#[derive(Serialize)]
struct JsonError {
    error: String,
}

impl Display for ServiceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ServiceError::LockPoison(msg) => write!(f, "Internal server error: {}", msg),
            ServiceError::InvalidIp => write!(f, "Invalid IP address"),
            ServiceError::InvalidJsonPayload(msg) => write!(f, "Invalid JSON payload: {}", msg),
            ServiceError::InvalidTextPayload => write!(f, "Invalid text payload"),
            ServiceError::CompileError(msg) => write!(f, "Failed to compile policies: {}", msg),
            ServiceError::EvaluationError(msg) => write!(f, "Policy evaluation error: {}", msg),
            ServiceError::ListPoliciesError(_) => write!(f, "Error listing policies"),
            ServiceError::UploadNotAllowed => write!(f, "Policy upload is not allowed"),
            ServiceError::InvalidUploadToken => write!(f, "Invalid upload token provided"),
            ServiceError::UploadTokenNotSet => write!(f, "Upload token is not set"),
            ServiceError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
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
            | ServiceError::CompileError(_) => StatusCode::BAD_REQUEST,
            ServiceError::UploadNotAllowed
            | ServiceError::InvalidUploadToken
            | ServiceError::UploadTokenNotSet => StatusCode::FORBIDDEN,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let err = JsonError {
            error: self.to_string(),
        };
        HttpResponse::build(self.status_code()).json(err)
    }
}

impl From<PolicyError> for ServiceError {
    fn from(err: PolicyError) -> Self {
        ServiceError::CompileError(err.to_string())
    }
}

impl From<PoisonError<MutexGuard<'_, PolicyStore>>> for ServiceError {
    fn from(e: PoisonError<MutexGuard<'_, PolicyStore>>) -> Self {
        ServiceError::LockPoison(e.to_string())
    }
}

impl From<serde_json::Error> for ServiceError {
    fn from(e: serde_json::Error) -> Self {
        ServiceError::InvalidJsonPayload(e.to_string())
    }
}

impl std::error::Error for ServiceError {}
