use crate::error::GatewayError;
use crate::AppState;
use axum::extract::{Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Redirect-flow inputs. The gateway only exchanges the OAuth `code` for an
/// access token here -- it never inspects or trusts the token's claims.
/// That verification happens inside the enclave (see routes/identity.rs),
/// which is the whole point of the architecture.
#[derive(Debug, Deserialize)]
pub struct AuthCallbackQuery {
    pub code: String,
    pub provider: String,
}

#[derive(Debug, Serialize)]
pub struct AuthCallbackResponse {
    pub provider: String,
    pub access_token: String,
}

pub async fn callback(
    State(_state): State<Arc<AppState>>,
    Query(_query): Query<AuthCallbackQuery>,
) -> Result<Json<AuthCallbackResponse>, GatewayError> {
    // Real code->token exchange against Google/GitHub's token endpoints is
    // Phase 2 (needs registered OAuth app credentials + a redirect UI).
    // Phase 1 proves the path with tokens obtained manually; see
    // scripts/smoke_test.sh.
    Err(GatewayError::BadRequest(
        "OAuth code exchange is not implemented in Phase 1; obtain a token manually and POST it to /identity/verify".into(),
    ))
}

/// Session bootstrap: verifies an identity through the enclave exactly as
/// `/identity/verify` does, then issues a session JWT bound to the owner id
/// the enclave attested. The orchestrator uses this to obtain the session
/// it needs for the seal and grant routes.
#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub session_token: String,
    pub identity: shared::OwnerIdentity,
    pub attestation: String,
}

pub async fn session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<shared::IdentityVerifyRequest>,
) -> Result<Json<SessionResponse>, GatewayError> {
    let verified = state.enclave.verify_identity(&req).await?;
    let session_token = crate::middleware::session::issue_session_token(
        &verified.identity.owner_id,
        &state.config.session_jwt_secret,
        state.config.session_ttl_secs,
    )
    .map_err(|e| GatewayError::Internal(format!("failed to issue session: {e}")))?;

    Ok(Json(SessionResponse {
        session_token,
        identity: verified.identity,
        attestation: verified.attestation,
    }))
}
