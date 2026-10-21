//! Deciding whether an agent may see an object, in here (ADR 0028).
//!
//! `evaluate` and `evaluate_write` were already compiled into this image for
//! `/assemble`, which is why this is the smallest remaining increase in the
//! trusted computing base for the largest gain: two routes and no new
//! dependency. What they replace is the same two functions running in host
//! Python, where an operator changes a verdict by editing a file -- not by
//! exploiting anything. Being pure, total and deny-by-default makes `evaluate`
//! the easiest thing in the service to audit and also the easiest to replace
//! with `return Allow`.
//!
//! **The clock is read in here.** There is no `now_ms` in either request. Every
//! time-window check and every grant expiry is measured against it, so a host
//! that supplied it could rewind it to resurrect an expired grant or reopen a
//! closed window -- and nothing downstream would look wrong, because the
//! verdict would be correct for the time it was given. That is the part of this
//! change that closes an exposure rather than relocating one.
//!
//! **What it does not do** is make the scope trustworthy. The `Scope` is the one
//! the gateway resolved from the grant, on the host, exactly as `AssembleRequest`
//! already carries it: the gateway holds the device key registry, and putting
//! that registry in the measured image would buy nothing while the host still
//! chooses what reaches this route. So the operator can no longer compute the
//! verdict and can still choose the question. ADR 0011 has the rest.

use std::sync::Arc;

use axum::extract::State;
use axum::Json;
use shared::permissions::{evaluate, evaluate_write, PermissionDecision};
use shared::{
    EvaluateRequest, EvaluateResponse, EvaluateVerdict, EvaluateWriteRequest,
    EvaluateWriteResponse,
};

use crate::error::EnclaveError;
use crate::AppState;

/// One verdict per object, batched.
///
/// Batched rather than one call per object because a neighbourhood of forty
/// objects would otherwise be forty round trips into the TEE. The ids are
/// echoed in the verdicts so the host matches by id: a list matched by position
/// is one an intermediary can reorder or truncate, with the gap reading as
/// "allowed".
pub async fn evaluate_objects(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<EvaluateRequest>,
) -> Result<Json<EvaluateResponse>, EnclaveError> {
    // Checked here as well as by the gateway, because `evaluate` itself denies
    // on an owner mismatch and a request that disagrees with its own scope is a
    // caller bug worth naming rather than forty identical denials.
    if req.scope.owner_id != req.owner_id {
        return Err(EnclaveError::BadRequest(
            "owner_id does not match the scope's owner".into(),
        ));
    }

    let now_ms = now_ms();
    let verdicts = req
        .objects
        .iter()
        .map(|object| match evaluate(&req.scope, &object.acl, now_ms) {
            PermissionDecision::Allow => EvaluateVerdict {
                id: object.id.clone(),
                allowed: true,
                reason: None,
            },
            PermissionDecision::Deny(reason) => EvaluateVerdict {
                id: object.id.clone(),
                allowed: false,
                reason: Some(reason),
            },
        })
        .collect::<Vec<_>>();

    // Counts only, and the same reason `/assemble` logs counts: a log line
    // naming what an agent was shown would put the disclosure record on the
    // host's stdout, which is the one place the operator reads by habit.
    let denied = verdicts.iter().filter(|v| !v.allowed).count();
    tracing::info!(
        owner = %req.owner_id,
        agent = %req.scope.agent_id,
        considered = verdicts.len(),
        denied,
        "evaluated in the enclave"
    );

    Ok(Json(EvaluateResponse { verdicts, now_ms }))
}

/// The write gate.
///
/// A separate route rather than a mode on the one above, mirroring
/// `evaluate_write` being a sibling function rather than a flag on `evaluate`:
/// a mode parameter means every call site has to say "read", and the one that
/// forgets gets whatever the default is.
pub async fn evaluate_write_intent(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<EvaluateWriteRequest>,
) -> Result<Json<EvaluateWriteResponse>, EnclaveError> {
    if req.scope.owner_id != req.owner_id {
        return Err(EnclaveError::BadRequest(
            "owner_id does not match the scope's owner".into(),
        ));
    }

    let now_ms = now_ms();
    let (allowed, reason) = match evaluate_write(&req.scope, &req.intent, now_ms) {
        PermissionDecision::Allow => (true, None),
        PermissionDecision::Deny(reason) => (false, Some(reason)),
    };

    tracing::info!(
        owner = %req.owner_id,
        agent = %req.scope.agent_id,
        allowed,
        "evaluated a write in the enclave"
    );

    Ok(Json(EvaluateWriteResponse {
        allowed,
        reason,
        now_ms,
    }))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
