use crate::error::GatewayError;
use crate::middleware::grant::{issue_grant_token, validate_grant_token};
use crate::middleware::session::require_session;
use crate::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use shared::{
    ScopeGrantRequest, ScopeGrantResponse, ScopeIntrospectRequest, ScopeIntrospectResponse,
    SealEncryptRequest, SealEncryptResponse,
};
use std::sync::Arc;

// The Rust side of the memory layer is deliberately only two things:
// enclave-touching operations, and owner-authenticated permission gating.
//
// Retrieval, ranking, extraction and resolution all live in the Python
// orchestration service (LangGraph/LlamaIndex over Neo4j) and are not
// mirrored here -- there is no second implementation of the query path in
// Rust, on purpose. What the orchestrator cannot do for itself is (a) get
// raw content encrypted inside the TEE and (b) learn what an agent is
// actually authorised to see, which is what these routes provide.

/// Encrypts raw source content inside the enclave on behalf of the
/// ingestion graph. The owner session, not the caller's claim, decides
/// whose key the content is sealed under.
pub async fn seal_encrypt(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SealEncryptRequest>,
) -> Result<Json<SealEncryptResponse>, GatewayError> {
    let session = require_session(&headers, &state.config.session_jwt_secret)?;
    let req = SealEncryptRequest {
        owner_id: session.owner_id,
        plaintext_b64: req.plaintext_b64,
    };
    let response = state.enclave.seal_encrypt(&req).await?;
    Ok(Json(response))
}

/// Mints a scoped, expiring grant for a named agent. Only the owner can do
/// this, and only over their own memory. This is the seam that later becomes
/// an on-chain grant object: the token is the capability, and the scope
/// inside it is what the query graph enforces per object.
pub async fn scope_grant(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ScopeGrantRequest>,
) -> Result<Json<ScopeGrantResponse>, GatewayError> {
    let session = require_session(&headers, &state.config.session_jwt_secret)?;
    if req.scope.owner_id != session.owner_id {
        return Err(GatewayError::Unauthorized(
            "cannot grant a scope over another owner's memory".into(),
        ));
    }
    if req.scope.agent_id.trim().is_empty() {
        return Err(GatewayError::BadRequest(
            "scope.agent_id is required".into(),
        ));
    }

    let (grant_token, expires_at_ms) =
        issue_grant_token(&req.scope, req.ttl_secs, &state.config.session_jwt_secret)
            .map_err(|e| GatewayError::Internal(format!("failed to mint grant: {e}")))?;

    Ok(Json(ScopeGrantResponse {
        grant_token,
        expires_at_ms,
    }))
}

/// Resolves a grant token back to the authoritative scope. The orchestrator
/// calls this at the start of every query rather than trusting a scope
/// supplied by the requesting agent.
pub async fn scope_introspect(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScopeIntrospectRequest>,
) -> Result<Json<ScopeIntrospectResponse>, GatewayError> {
    let scope = validate_grant_token(&req.grant_token, &state.config.session_jwt_secret)
        .map_err(|e| GatewayError::Unauthorized(format!("invalid grant: {e}")))?;
    Ok(Json(ScopeIntrospectResponse {
        active: true,
        scope,
    }))
}
