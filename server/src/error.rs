//! A single error type for every HTTP handler.
//!
//! Handlers return `Result<T, AppError>`. Because `AppError` implements
//! `IntoResponse`, axum knows how to turn any error into an HTTP response,
//! and the `?` operator works everywhere inside handlers.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

pub enum AppError {
    BadRequest(String),
    Unauthorized(&'static str),
    Forbidden(&'static str),
    NotFound(&'static str),
    Conflict(String),
    /// Rate limit hit (HTTP 429).
    TooManyRequests(&'static str),
    /// Anything unexpected (database down, bug, ...). Details are logged
    /// server-side but never leaked to the client.
    Internal(anyhow::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, msg) = match self {
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            AppError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m.to_string()),
            AppError::Forbidden(m) => (StatusCode::FORBIDDEN, m.to_string()),
            AppError::NotFound(m) => (StatusCode::NOT_FOUND, m.to_string()),
            AppError::Conflict(m) => (StatusCode::CONFLICT, m),
            AppError::TooManyRequests(m) => (StatusCode::TOO_MANY_REQUESTS, m.to_string()),
            AppError::Internal(e) => {
                tracing::error!("internal error: {e:#}");
                (StatusCode::INTERNAL_SERVER_ERROR, "internal server error".to_string())
            }
        };
        (status, Json(json!({ "error": msg }))).into_response()
    }
}

/// Lets `?` convert any standard error (sqlx::Error, JoinError, ...) into
/// `AppError::Internal` automatically.
impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        AppError::Internal(e.into())
    }
}
