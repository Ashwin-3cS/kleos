use crate::error::GatewayError;
use crate::middleware::grant::{issue_grant_token, validate_grant_token};
use crate::middleware::session::require_session;
use crate::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use shared::{
    ScopeGrantRequest, ScopeGrantResponse, ScopeIntrospectRequest, ScopeIntrospectResponse,
    SealDecryptRequest, SealDecryptResponse, SealEncryptRequest, SealEncryptResponse,
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
    let session = require_session(&headers, state.config.keys.session())?;
    let req = SealEncryptRequest {
        owner_id: session.owner_id,
        plaintext_b64: req.plaintext_b64,
    };
    let response = state.enclave.seal_encrypt(&req).await?;
    Ok(Json(response))
}

/// Decrypts content that was sealed inside the enclave, back out to the owner's
/// own orchestrator.
///
/// `store/mod.rs` says there is "deliberately no decrypt here", and that is
/// still true of the *sealed refresh token store* -- unsealing an OAuth refresh
/// token would hand the host standing access to a mailbox, which is the whole
/// thing the connect flow exists to prevent. This route unseals **record
/// content**, which is a different asset: the orchestrator produced it, from
/// plaintext it already had, and needs it back to answer a query.
///
/// Owner-authenticated, and the owner comes from the session rather than the
/// request, so a caller cannot ask for another owner's content. The enclave
/// derives the key from that owner id, so a mismatched key id fails inside the
/// TEE rather than here.
///
/// The thing that makes this safe to expose is *when* the orchestrator calls it:
/// only for objects that have already passed the permission check. The decrypt
/// budget is therefore the disclosure budget -- nothing gets unsealed that was
/// not about to be shown to someone entitled to see it.
pub async fn seal_decrypt(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SealDecryptRequest>,
) -> Result<Json<SealDecryptResponse>, GatewayError> {
    let session = require_session(&headers, state.config.keys.session())?;
    let req = SealDecryptRequest {
        owner_id: session.owner_id,
        ciphertext_b64: req.ciphertext_b64,
        key_id: req.key_id,
    };
    let response = state.enclave.seal_decrypt(&req).await?;
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
    let session = require_session(&headers, state.config.keys.session())?;
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
        issue_grant_token(&req.scope, req.ttl_secs, state.config.keys.grant())
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
    let scope = validate_grant_token(&req.grant_token, state.config.keys.grant())
        .map_err(|e| GatewayError::Unauthorized(format!("invalid grant: {e}")))?;
    Ok(Json(ScopeIntrospectResponse {
        active: true,
        scope,
    }))
}
