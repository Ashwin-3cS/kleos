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
