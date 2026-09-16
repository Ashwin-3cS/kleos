use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub enum EnclaveError {
    BadRequest(String),
    Upstream(String),
    Internal(String),
}

impl IntoResponse for EnclaveError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            EnclaveError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            EnclaveError::Upstream(m) => (StatusCode::BAD_GATEWAY, m),
            EnclaveError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
