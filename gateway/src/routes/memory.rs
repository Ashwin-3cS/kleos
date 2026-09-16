use crate::error::GatewayError;
use crate::AppState;
use axum::extract::State;
use axum::Json;
use shared::Timeline;
use std::sync::Arc;

// Phase 2: memory query/recall routes. Stub kept typed so the router
// wiring is settled now.
//
// This is the query API the Python orchestration service's query graph
// will call, and the eventual base for the MCP server's tool calls --
// see README's "Phase 2 direction" section. Not the orchestration/
// retrieval logic itself, which lives outside the enclave in LangGraph/
// LlamaIndex.

pub async fn timeline(
    State(_state): State<Arc<AppState>>,
) -> Result<Json<Timeline>, GatewayError> {
    todo!("memory timeline retrieval is out of scope for Phase 1")
}
