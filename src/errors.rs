use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::Serialize;
use std::fmt::{Display, Formatter, Result as FmtResult};

#[derive(Debug)]
#[allow(dead_code)]
pub enum ServiceError {
    LockPoison,
    InvalidIp,
    InvalidJsonPayload,
    InvalidTextPayload,
    CompileError(String),
    EvaluationError(String),
    ListPoliciesError(String),
}

#[derive(Serialize)]
struct JsonError {
    error: String,
}

impl Display for ServiceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            ServiceError::LockPoison => write!(f, "Internal server error"),
            ServiceError::InvalidIp => write!(f, "Invalid IP address"),
            ServiceError::InvalidJsonPayload => write!(f, "Invalid JSON payload"),
            ServiceError::InvalidTextPayload => write!(f, "Invalid text payload"),
            ServiceError::CompileError(msg) => write!(f, "Failed to compile policies: {}", msg),
            ServiceError::EvaluationError(msg) => write!(f, "Policy evaluation error: {}", msg),
            ServiceError::ListPoliciesError(_) => write!(f, "Error listing policies"),
        }
    }
}

impl ResponseError for ServiceError {
    fn status_code(&self) -> StatusCode {
        match self {
            ServiceError::LockPoison
            | ServiceError::EvaluationError(_)
            | ServiceError::ListPoliciesError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ServiceError::InvalidIp
            | ServiceError::InvalidJsonPayload
            | ServiceError::InvalidTextPayload
            | ServiceError::CompileError(_) => StatusCode::BAD_REQUEST,
        }
    }

    fn error_response(&self) -> HttpResponse {
        let err = JsonError {
            error: self.to_string(),
        };
        HttpResponse::build(self.status_code()).json(err)
    }
}
