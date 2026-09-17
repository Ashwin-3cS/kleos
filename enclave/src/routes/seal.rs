use crate::error::EnclaveError;
use crate::services::attestation::get_attestation;
use crate::services::seal::{self, SealEncrypted};
use crate::AppState;
use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fastcrypto::traits::{KeyPair, ToFromBytes};
use shared::{SealDecryptRequest, SealDecryptResponse, SealEncryptRequest, SealEncryptResponse};
use std::sync::Arc;

/// Encrypts one piece of raw source content inside the TEE. The attestation
/// returned covers the enclave public key plus the resulting key id, so a
/// verifier can tell that this particular blob was sealed in here and not
/// on the host.
pub async fn encrypt(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SealEncryptRequest>,
) -> Result<Json<SealEncryptResponse>, EnclaveError> {
    let plaintext = B64
        .decode(req.plaintext_b64.as_bytes())
        .map_err(|e| EnclaveError::BadRequest(format!("plaintext_b64 is not base64: {e}")))?;

    let sealed = seal::encrypt(&req.owner_id, plaintext).await?;

    let pk = state.signing_key.public();
    let mut committed = pk.as_bytes().to_vec();
    committed.extend_from_slice(sealed.key_id.as_bytes());
    let attestation = get_attestation(committed).await?;

    Ok(Json(SealEncryptResponse {
        ciphertext_b64: B64.encode(&sealed.ciphertext),
        key_id: sealed.key_id,
        scheme: sealed.scheme,
        attestation,
    }))
}

pub async fn decrypt(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<SealDecryptRequest>,
) -> Result<Json<SealDecryptResponse>, EnclaveError> {
    let ciphertext = B64
        .decode(req.ciphertext_b64.as_bytes())
        .map_err(|e| EnclaveError::BadRequest(format!("ciphertext_b64 is not base64: {e}")))?;

    let plaintext = seal::decrypt(
        &req.owner_id,
        SealEncrypted {
            ciphertext,
            key_id: req.key_id,
            scheme: String::new(),
        },
    )
    .await?;

    Ok(Json(SealDecryptResponse {
        plaintext_b64: B64.encode(&plaintext),
    }))
}
