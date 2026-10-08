//! Sensitive actions performed inside the TEE, which return an acknowledgement.
//!
//! The rule the whole module exists for: **an agent submits an intent and
//! receives an acknowledgement.** It never receives the credential the action
//! needs, and never the raw material that credential unlocks.
//!
//! This is not new machinery so much as a generalisation of the one thing the
//! enclave already does right. `/oauth/exchange` lives in here precisely because
//! a refresh token is standing, renewable access to a person's mailbox and the
//! host must never hold one; the enclave holds the only copy of the client
//! secret. The broker says: so must every other sensitive action. If the *action*
//! runs in here, nothing outside holds even a short-lived token.
//!
//! ## A closed registry, compiled in
//!
//! `action_id` resolves against the table below and an unknown id is refused
//! rather than forwarded. Same reason the upstream hostnames in
//! `services/http.rs` are compile-time constants: the enclave's environment is
//! supplied by the host, so a host-settable action is an operator-repointable
//! one. Adding an action is a rebuild, a new measurement and a new attestation
//! -- which is the point rather than the cost, because the measurement is what
//! the attestation is worth.
//!
//! ## What constrains it
//!
//! Growing the TCB is the risk here, and this repo guards that hard: the
//! attestation is only meaningful if what it measures is small enough to audit.
//! So an action is **small and auditable by construction** -- no LLM, no
//! ingestion, no retrieval and no pagination in here. Something that needs any of
//! those is not an action; it is the orchestrator's job, operating on what an ack
//! gave it.
//!
//! A result too large to summarise comes back as a sealed blob ref rather than as
//! bytes, so the agent must then pass the `may_unseal` gate to read any of it.
//! Acknowledgement by default; disclosure as a second, separately granted step.

use crate::error::EnclaveError;
use crate::services::attestation::get_attestation;
use fastcrypto::hash::{Blake2b256, HashFunction};
use serde_json::Value;

/// One line of ack text is enough to act on. An action that wants to say more
/// than this is an action returning data, which is what `sealed_ref` is for.
const SUMMARY_MAX: usize = 240;

/// An action the enclave knows how to perform.
pub struct ActionSpec {
    pub action_id: &'static str,
    /// Shown in a refusal, so an operator reading "unknown action" learns what
    /// *is* known without reading this file.
    pub description: &'static str,
    /// Whether performing it needs the owner's sealed provider credential. The
    /// audit question asked first, answerable from the registry rather than by
    /// reading each implementation -- the same reason `ToolSpec` declares
    /// `writes_memory` and `reaches_network`.
    pub needs_credential: bool,
}

/// Attest a digest the caller computed.
///
/// The one action that works today, and it is deliberately the one that needs no
/// provider credential: it proves the *shape* -- intent in, acknowledgement out,
/// nothing sensitive crossing back -- without pretending the credential path
/// exists. It is genuinely enclave-only work, since only the enclave can produce
/// an NSM attestation.
pub const ATTEST_DIGEST: ActionSpec = ActionSpec {
    action_id: "attest.digest",
    description: "produce an NSM attestation over a caller-supplied digest",
    needs_credential: false,
};

/// Send mail as the owner, through their Google credential.
pub const GMAIL_SEND: ActionSpec = ActionSpec {
    action_id: "google.gmail.send",
    description: "send one message as the owner",
    needs_credential: true,
};

/// Comment on a GitHub issue as the owner.
pub const GITHUB_COMMENT: ActionSpec = ActionSpec {
    action_id: "github.issue.comment",
    description: "post one issue comment as the owner",
    needs_credential: true,
};

/// Every action this build knows. Closed, and ordered so a refusal lists them
/// predictably.
pub const REGISTRY: &[&ActionSpec] = &[&ATTEST_DIGEST, &GMAIL_SEND, &GITHUB_COMMENT];

pub fn spec(action_id: &str) -> Option<&'static ActionSpec> {
    REGISTRY.iter().copied().find(|s| s.action_id == action_id)
}

fn known() -> String {
    REGISTRY
        .iter()
        .map(|s| s.action_id)
        .collect::<Vec<_>>()
        .join(", ")
}

/// What an action produced, before it is wrapped in an ack.
pub struct Outcome {
    pub digest: String,
    pub summary: String,
}

/// Performs one action, or refuses.
///
/// `owner_id` comes from the gateway's verified grant and is never read from the
/// agent's request. It is passed here because a credential-bearing action needs
/// it to find the owner's sealed token -- the same scoping every other route in
/// the enclave applies.
pub async fn perform(
    owner_id: &str,
    action_id: &str,
    args: &Value,
) -> Result<Outcome, EnclaveError> {
    let spec = spec(action_id).ok_or_else(|| {
        EnclaveError::BadRequest(format!(
            "unknown action {action_id:?}; this build knows: {}. Actions are \
             compiled in, so adding one is a rebuild and a new measurement.",
            known()
        ))
    })?;

    match spec.action_id {
        "attest.digest" => attest_digest(owner_id, args).await,
        // Declared with real metadata and refused explicitly, the same discipline
        // the Google and GitHub connectors practise. What is missing is not this
        // function: it is the path by which the enclave turns a sealed refresh
        // token into a usable short-lived credential, which is roadmap step 5 and
        // gets an ADR first. An action that silently did nothing, or that asked
        // the host for a token, would be worse than one that says so.
        _ => Err(EnclaveError::BadRequest(format!(
            "action {action_id:?} is declared and not wired: it needs the owner's \
             sealed provider credential, and the enclave has no path yet from a \
             sealed refresh token to a short-lived access token. Nothing outside \
             the TEE may hold either, which is why this is not a quick fix."
        ))),
    }
}

async fn attest_digest(owner_id: &str, args: &Value) -> Result<Outcome, EnclaveError> {
    let digest = args
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| EnclaveError::BadRequest("attest.digest needs a 'digest' string".into()))?;
    if digest.is_empty() || digest.len() > 128 {
        return Err(EnclaveError::BadRequest(
            "'digest' must be between 1 and 128 characters".into(),
        ));
    }

    // Committed to the attestation alongside the owner, so the document says
    // *whose* digest was attested and not merely that some digest was.
    let mut committed = owner_id.as_bytes().to_vec();
    committed.extend_from_slice(digest.as_bytes());
    let attestation = get_attestation(committed).await?;

    Ok(Outcome {
        digest: digest_of(attestation.as_bytes()),
        summary: truncate(&format!(
            "attested {} characters of digest; document is {} bytes",
            digest.len(),
            attestation.len()
        )),
    })
}

/// A hash over what an action did, so two acks can be compared and a replay
/// recognised -- without the content itself crossing the boundary.
pub fn digest_of(bytes: &[u8]) -> String {
    let mut hasher = Blake2b256::default();
    hasher.update(bytes);
    hex::encode(&hasher.finalize().digest[..16])
}

/// Bounded, because an ack goes straight into an agent's context window and an
/// unbounded summary is a way to push arbitrary provider output through a field
/// that is documented as one line.
pub fn truncate(summary: &str) -> String {
    if summary.len() <= SUMMARY_MAX {
        return summary.to_string();
    }
    format!("{}...", &summary[..SUMMARY_MAX])
}
