use crate::error::EnclaveError;
use crate::services::actions;
use crate::AppState;
use axum::extract::State;
use axum::Json;
use shared::{ActionAck, ActionIntent};
use std::sync::Arc;

/// Performs one sensitive action inside the TEE and returns an acknowledgement.
///
/// The request carries an **intent**; the response carries an **ack**. What it
/// never carries is the credential the action needed, or the material that
/// credential unlocks. See `services/actions.rs` for why the registry is
/// compiled in and what keeps an action small enough to belong in here at all.
///
/// `owner_id` arrives already set by the gateway from a verified grant. This
/// route does not re-derive it and could not: it has no device key store and no
/// signing key, which is the division every enclave route keeps -- the gateway
/// decides *who is asking*, the enclave decides *what may be done in here*.
///
/// A refused action still returns `200` with `ok: false`. That is deliberate: an
/// attempt that was made and failed is a different fact from an attempt that was
/// never made, and the orchestrator records both. Collapsing them into an HTTP
/// error would lose the distinction a trace needs most -- the same reason every
/// tool in the Python layer returns a `ToolResult` instead of raising.
pub async fn act(
    State(_state): State<Arc<AppState>>,
    Json(intent): Json<ActionIntent>,
) -> Result<Json<ActionAck>, EnclaveError> {
    if intent.owner_id.is_empty() {
        // Not recoverable and not an action failure: the gateway sets this from
        // the verified scope, so an empty one means the request did not come
        // through the gateway.
        return Err(EnclaveError::BadRequest(
            "owner_id is set by the gateway from a verified grant and cannot be empty".into(),
        ));
    }

    match actions::perform(&intent.owner_id, &intent.action_id, &intent.args).await {
        Ok(outcome) => Ok(Json(ActionAck {
            ok: true,
            action_id: intent.action_id,
            at_ms: intent.at_ms,
            digest: outcome.digest,
            summary: outcome.summary,
            sealed_ref: None,
            error: None,
        })),
        Err(EnclaveError::BadRequest(reason)) => Ok(Json(ActionAck {
            ok: false,
            action_id: intent.action_id,
            at_ms: intent.at_ms,
            digest: String::new(),
            summary: actions::truncate(&reason),
            sealed_ref: None,
            error: Some(actions::truncate(&reason)),
        })),
        // An upstream or internal failure is not an ack. A provider error can
        // carry request URLs and token prefixes, so it never becomes ack text --
        // it propagates as an error the gateway turns into a status, and the
        // orchestrator records the attempt without the provider's words in it.
        Err(other) => Err(other),
    }
}
