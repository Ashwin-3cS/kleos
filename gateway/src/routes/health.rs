use crate::AppState;
use axum::extract::State;
use axum::Json;
use serde_json::{json, Value};
use std::sync::Arc;

pub async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    let enclave_status = match state.enclave.health().await {
        Ok(body) => json!({ "reachable": true, "enclave": body }),
        Err(e) => json!({ "reachable": false, "error": e.to_string() }),
    };
    Json(json!({
        "status": "ok",
        "enclave": enclave_status,
    }))
}
