use crate::error::EnclaveError;
use crate::services::attestation::get_attestation;
use crate::AppState;
use axum::extract::State;
use axum::Json;
use fastcrypto::traits::{KeyPair, ToFromBytes};
use serde_json::{json, Value};
use std::sync::Arc;

pub async fn attest(State(state): State<Arc<AppState>>) -> Result<Json<Value>, EnclaveError> {
    let pk = state.signing_key.public();
    let attestation = get_attestation(pk.as_bytes().to_vec()).await?;
    Ok(Json(json!({ "attestation": attestation })))
}
