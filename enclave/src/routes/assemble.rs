use crate::error::EnclaveError;
use crate::services::assemble::assemble;
use crate::services::attestation::get_attestation;
use crate::services::recipient::seal_to_device;
use crate::AppState;
use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fastcrypto::traits::{KeyPair, ToFromBytes};
use shared::attestation::{commitment, purpose};
use shared::{AssembleRequest, AssembleResponse};
use std::sync::Arc;

/// Answers a query from inside the TEE, and hands back something the host
/// cannot read.
///
/// The only route in the enclave that produces *content* rather than an
/// acknowledgement, a ciphertext or an identity -- which is why it is also the
/// only one whose reply is encrypted to someone other than the caller. The
/// caller here is the orchestrator, and the orchestrator is precisely who must
/// not be able to read it.
///
/// ## What this route trusts, and what it cannot check
///
/// It trusts the gateway for two facts: that the grant verified, and that
/// `recipient_key_b64` is the encryption key registered to the device that
/// signed it. Neither is checkable in here, because the device key registry is
/// a Postgres table on the host and putting it inside the measured image would
/// mean putting a database client there for a check the host chooses whether to
/// reach anyway.
///
/// That is a real limit and worth naming: an operator who forges an owner
/// session can register a key of their own and have answers sealed to it. What
/// stops that being silent is the registration row -- timestamped, immutable
/// under `ON CONFLICT DO NOTHING`, and listed to the owner by `GET
/// /auth/device/keys`. The attack is key substitution, which is detectable,
/// rather than quiet decryption, which would not be. Closing it needs a
/// verification root the operator cannot substitute; see ADR 0011.
///
/// ## The attestation
///
/// Covers the enclave public key, the recipient key id and the ciphertext, so
/// the document is about *this* assembly rather than about the enclave in
/// general. As a digest rather than the parts, because NSM caps `public_key` at
/// 1024 bytes and a real ciphertext is kilobytes -- see
/// `shared::attestation::commitment`, which also length-prefixes the parts so
/// the commitment uniquely determines what it covers.
///
/// Verified by the device before it opens the blob (ADR 0026), which is the
/// check that is not the operator's, and by the orchestrator and the gateway as
/// a configuration check.
pub async fn assemble_for_device(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AssembleRequest>,
) -> Result<Json<AssembleResponse>, EnclaveError> {
    let recipient_key = B64
        .decode(req.recipient_key_b64.as_bytes())
        .map_err(|e| EnclaveError::BadRequest(format!("recipient_key_b64 is not base64: {e}")))?;

    let assembly = assemble(&req.owner_id, &req.scope, &req.question, req.candidates).await?;

    // Serialised and sealed even when the answer is a decline. A decline is
    // short and says why, and the reasons are already in the clear beside it --
    // but a reply that is sometimes sealed and sometimes not tells the host
    // which queries found something, and the length of the blob is the most
    // the host should learn.
    let plaintext = serde_json::to_vec(&assembly.answer)
        .map_err(|e| EnclaveError::Internal(format!("could not serialise the answer: {e}")))?;
    let sealed = seal_to_device(&recipient_key, &req.recipient_key_id, &plaintext)?;

    let pk = state.signing_key.public();
    // A digest, not the parts: NSM caps `public_key` at 1024 bytes and this
    // route was committing the whole ciphertext, so on real hardware it would
    // have been refused. See `shared::attestation::commitment`.
    let committed = commitment(
        purpose::ASSEMBLE,
        &[
            pk.as_bytes(),
            sealed.recipient_key_id.as_bytes(),
            sealed.ciphertext_b64.as_bytes(),
        ],
    );
    let attestation = get_attestation(committed.to_vec()).await?;

    // Counts only. The ids are in the response because the read log needs
    // them, but a log line naming what an agent read would put the disclosure
    // record on the host's stdout, where it is the one place the operator reads
    // by habit.
    tracing::info!(
        owner = %req.owner_id,
        recipient = %sealed.recipient_key_id,
        disclosed = assembly.disclosed_ids.len(),
        denied = assembly.denials.len(),
        considered = assembly.considered,
        "assembled and sealed to device"
    );

    Ok(Json(AssembleResponse {
        sealed,
        disclosed_ids: assembly.disclosed_ids,
        denials: assembly.denials,
        considered: assembly.considered,
        attestation,
        enclave_public_key_b64: B64.encode(pk.as_bytes()),
    }))
}
