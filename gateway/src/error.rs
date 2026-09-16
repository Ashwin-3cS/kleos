use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub enum GatewayError {
    BadRequest(String),
    Unauthorized(String),
    EnclaveUnreachable(String),
    Internal(String),
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            GatewayError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            GatewayError::Unauthorized(m) => (StatusCode::UNAUTHORIZED, m),
            GatewayError::EnclaveUnreachable(m) => (StatusCode::BAD_GATEWAY, m),
            GatewayError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
