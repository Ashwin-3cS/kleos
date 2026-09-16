use crate::error::GatewayError;
use crate::AppState;
use axum::extract::State;
use axum::Json;
use shared::{IdentityVerifyRequest, IdentityVerifyResponse};
use std::sync::Arc;

/// Pure proxy: the gateway forwards the raw tokens to the enclave and
/// relays back whatever it attested. It never verifies anything itself --
/// see enclave/src/routes/identity.rs for why that boundary matters.
pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IdentityVerifyRequest>,
) -> Result<Json<IdentityVerifyResponse>, GatewayError> {
    let response = state.enclave.verify_identity(&req).await?;
    Ok(Json(response))
}
