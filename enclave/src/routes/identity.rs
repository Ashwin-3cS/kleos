use crate::error::EnclaveError;
use crate::services::attestation::get_attestation;
use crate::services::identity::{compute_identity, derive_owner_id};
use crate::services::oauth::github::GitHubProvider;
use crate::services::oauth::google::GoogleProvider;
use crate::services::oauth::OAuthProvider;
use crate::AppState;
use axum::extract::State;
use axum::Json;
use fastcrypto::traits::{KeyPair, ToFromBytes};
use shared::{IdentityVerifyRequest, IdentityVerifyResponse, OAuthSignal};
use std::sync::Arc;

pub async fn verify(
    State(state): State<Arc<AppState>>,
    Json(req): Json<IdentityVerifyRequest>,
) -> Result<Json<IdentityVerifyResponse>, EnclaveError> {
    let mock = state.config.is_mock();
    let mut signals: Vec<OAuthSignal> = Vec::new();

    if let Some(token) = &req.google_token {
        let provider = GoogleProvider {
            tunnel_port: state.config.google_tokeninfo_port,
            mock,
            client_id: state.config.google_client_id.clone(),
            client_secret: state.config.google_client_secret.clone(),
            token_path: state.config.google_token_path.clone(),
        };
        signals.push(provider.verify(token).await?);
    }

    if let Some(token) = &req.github_token {
        let provider = GitHubProvider {
            tunnel_port: state.config.github_api_port,
            mock,
            client_id: state.config.github_client_id.clone(),
            client_secret: state.config.github_client_secret.clone(),
            token_path: state.config.github_token_path.clone(),
        };
        signals.push(provider.verify(token).await?);
    }

    // Wallet signature recovery and domain proof verification are Phase 2
    // work (see services/identity.rs); reject explicitly rather than
    // silently ignoring the field.
    if req.wallet_signature.is_some() {
        return Err(EnclaveError::BadRequest(
            "wallet_signature verification is not implemented in Phase 1".into(),
        ));
    }
    if req.domain_proof.is_some() {
        return Err(EnclaveError::BadRequest(
            "domain_proof verification is not implemented in Phase 1".into(),
        ));
    }

    if signals.is_empty() {
        return Err(EnclaveError::BadRequest(
            "at least one of google_token or github_token is required".into(),
        ));
    }

    let owner_id = derive_owner_id(&signals);
    let identity = compute_identity(owner_id, signals);

    let pk = state.signing_key.public();
    let attestation_input = serde_json::to_vec(&identity)
        .map_err(|e| EnclaveError::Internal(format!("failed to serialize identity: {e}")))?;
    let mut committed = pk.as_bytes().to_vec();
    committed.extend_from_slice(&attestation_input);
    let attestation = get_attestation(committed).await?;

    Ok(Json(IdentityVerifyResponse {
        identity,
        attestation,
    }))
}
