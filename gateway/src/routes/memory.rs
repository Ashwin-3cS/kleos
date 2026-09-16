use crate::error::GatewayError;
use crate::AppState;
use axum::extract::State;
use axum::Json;
use shared::Timeline;
use std::sync::Arc;

// Phase 2: memory query/recall routes, once the enclave can actually
// ingest anything. Stub kept typed so the router wiring is settled now.

pub async fn timeline(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Timeline>, GatewayError> {
    todo!("memory timeline retrieval is out of scope for Phase 1")
}
