use crate::AppState;
use axum::extract::State;
use axum::Json;
use fastcrypto::traits::{KeyPair, ToFromBytes};
use serde_json::{json, Value};
use std::sync::Arc;

pub async fn health(State(state): State<Arc<AppState>>) -> Json<Value> {
    let pk = state.signing_key.public();
    Json(json!({
        "status": "ok",
        "mode": state.config.enclave_mode,
        "pk": hex::encode(pk.as_bytes()),
    }))
}
