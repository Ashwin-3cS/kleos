//! Signing in to a personal install, with no OAuth app (ADR 0029).
//!
//! Every other identity in this system is established in the enclave, because
//! the claim is "this token was verified against Google" and an attestation
//! over an unverified claim is worth nothing. A local identity makes no such
//! claim. It says *this request was signed by a registered key*, the registry
//! is here, and so is the check. A local session therefore carries no
//! attestation, and that is not a gap: there is nothing an enclave could attest
//! to that this file did not already verify.
//!
//! Two routes, and the split is first-run against every run after:
//!
//! **`/auth/local/enrol`** turns a keypair into an owner. The owner id is
//! `hex("local:<key_id>")`, which is the shape every owner id already has, so
//! nothing downstream learns a new format and two people on two laptops cannot
//! collide on a name.
//!
//! **`/auth/local/session`** takes a short-lived assertion the device signed
//! and returns a session. Not a challenge-response round trip: a challenge
//! store would need its own lifetime to provide what the timestamp and nonce
//! already provide, and a one-shot assertion is something `kleos-device` can
//! print offline and a script can pipe into curl -- which is what keeps the
//! device CLI free of an HTTP client.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::GatewayError;
use crate::store::device_keys::DeviceKey;
use crate::AppState;

/// What the device signs, with the fields in a fixed order.
///
/// Prefixed and versioned so these bytes cannot be confused with anything else
/// the same key signs -- a grant, most of all. A signature is only as specific
/// as the thing it covers, and a key that signs two formats which can be read
/// as each other has signed both.
const ASSERTION_V1: &str = "kleos-local-session|v1";

/// How far from now an assertion may be dated.
///
/// Both directions: a clock ahead of the gateway's is as much a replay window
/// as one behind it.
const ASSERTION_SKEW_MS: i64 = 60_000;

#[derive(Debug, Deserialize)]
pub struct EnrolRequest {
    pub enrolment_code: String,
    pub public_key_b64: String,
    /// The X25519 half. Optional only because `/auth/device/register` made it
    /// optional for devices registered before ADR 0024; a device enrolling now
    /// should send it, and without it this owner cannot receive a sealed
    /// answer on any device.
    #[serde(default)]
    pub encryption_key_b64: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LocalSessionResponse {
    pub owner_id: String,
    pub key_id: String,
    pub session_token: String,
    /// Always absent, and present as a field so that a client reading this
    /// response does not have to guess. See the module docstring.
    pub attestation: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LocalSessionRequest {
    pub key_id: String,
    pub issued_at_ms: i64,
    pub nonce: String,
    pub signature_b64: String,
}

/// Turns a keypair into this install's owner.
pub async fn enrol(
    State(state): State<Arc<AppState>>,
    Json(req): Json<EnrolRequest>,
) -> Result<Json<LocalSessionResponse>, GatewayError> {
    let enrolment = state
        .config
        .local_enrolment
        .as_ref()
        .ok_or_else(|| {
            GatewayError::BadRequest(
                "local enrolment is not enabled on this gateway. It is for personal \
                 installs; a deployment uses OAuth."
                    .into(),
            )
        })?;

    enrolment.check(&req.enrolment_code)?;

    let public_key = decode_key(&req.public_key_b64, "public_key_b64")?;
    let encryption_key = match req.encryption_key_b64.as_deref() {
        None => None,
        Some(encoded) => {
            let bytes = decode_key(encoded, "encryption_key_b64")?;
            if bytes == public_key {
                // A category error rather than a size one: the same keypair
                // cannot both sign and receive, and accepting it would seal
                // every answer to a key whose private half cannot open it.
                return Err(GatewayError::BadRequest(
                    "the encryption key must not be the signing key: Ed25519 signs and \
                     X25519 receives, and they are separate keypairs"
                        .into(),
                ));
            }
            Some(bytes)
        }
    };

    let key_id = shared::key_id_for(&public_key);
    let owner_id = owner_id_for(&key_id);

    // Registered before the code is consumed: a storage failure should leave
    // the code usable, or a person is locked out of their own install by a
    // transient error with no way back but deleting a file they were never
    // told about.
    let registered = state
        .device_keys
        .register(&DeviceKey {
            owner_id: owner_id.clone(),
            key_id: key_id.clone(),
            public_key,
            encryption_key,
            label: req.label.unwrap_or_else(|| "this device".to_string()),
            registered_at_ms: now_ms(),
            revoked_at_ms: None,
        })
        .await?;

    enrolment.consume()?;

    let session_token = crate::middleware::session::issue_session_token(
        &registered.owner_id,
        state.config.keys.session(),
        state.config.session_ttl_secs,
    )
    .map_err(|e| GatewayError::Internal(format!("failed to issue session: {e}")))?;

    tracing::info!(
        owner = %registered.owner_id,
        key_id = %registered.key_id,
        "enrolled a local owner"
    );

    Ok(Json(LocalSessionResponse {
        owner_id: registered.owner_id,
        key_id: registered.key_id,
        session_token,
        attestation: None,
    }))
}

/// A session for an already-enrolled key.
pub async fn session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<LocalSessionRequest>,
) -> Result<Json<LocalSessionResponse>, GatewayError> {
    if state.config.local_enrolment.is_none() {
        return Err(GatewayError::BadRequest(
            "local sign-in is not enabled on this gateway".into(),
        ));
    }

    let drift = now_ms() - req.issued_at_ms;
    if drift.abs() > ASSERTION_SKEW_MS {
        return Err(GatewayError::Unauthorized(format!(
            "this assertion is dated {}ms from now and the limit is {ASSERTION_SKEW_MS}ms. \
             Sign a fresh one.",
            drift
        )));
    }

    let key = state
        .device_keys
        .get(&req.key_id)
        .await?
        .ok_or_else(|| GatewayError::Unauthorized("no such device key".into()))?;
    if key.is_revoked() {
        return Err(GatewayError::Unauthorized(
            "this device key is revoked".into(),
        ));
    }
    // A key registered under an OAuth owner must not be a way into that owner
    // without the OAuth check. Local sign-in is for local owners.
    if key.owner_id != owner_id_for(&key.key_id) {
        return Err(GatewayError::Unauthorized(
            "this key belongs to an owner that does not sign in locally".into(),
        ));
    }

    verify_assertion(&key, &req)?;
    state.local_nonces.remember(&req.key_id, &req.nonce)?;

    let session_token = crate::middleware::session::issue_session_token(
        &key.owner_id,
        state.config.keys.session(),
        state.config.session_ttl_secs,
    )
    .map_err(|e| GatewayError::Internal(format!("failed to issue session: {e}")))?;

    Ok(Json(LocalSessionResponse {
        owner_id: key.owner_id,
        key_id: key.key_id,
        session_token,
        attestation: None,
    }))
}

/// The bytes a device signs for a local session.
///
/// Public because `kleos-device` builds the same string, and two
/// implementations of one byte layout in two crates is how a signature check
/// starts failing for reasons nobody can see.
pub fn assertion_bytes(key_id: &str, issued_at_ms: i64, nonce: &str) -> Vec<u8> {
    format!("{ASSERTION_V1}|{key_id}|{issued_at_ms}|{nonce}").into_bytes()
}

/// `hex("local:<key_id>")` -- the shape every owner id already has.
pub fn owner_id_for(key_id: &str) -> String {
    hex::encode(format!("local:{key_id}"))
}

fn verify_assertion(key: &DeviceKey, req: &LocalSessionRequest) -> Result<(), GatewayError> {
    use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
    use fastcrypto::traits::{ToFromBytes, VerifyingKey};

    if req.nonce.len() < 8 || req.nonce.len() > 128 {
        return Err(GatewayError::BadRequest(
            "nonce must be between 8 and 128 characters".into(),
        ));
    }
    let signature_bytes = B64
        .decode(req.signature_b64.as_bytes())
        .map_err(|e| GatewayError::BadRequest(format!("signature_b64 is not base64: {e}")))?;
    let signature = Ed25519Signature::from_bytes(&signature_bytes)
        .map_err(|_| GatewayError::Unauthorized("malformed signature".into()))?;
    let public = Ed25519PublicKey::from_bytes(&key.public_key)
        .map_err(|_| GatewayError::Internal("registered key is not Ed25519".into()))?;

    public
        .verify(
            &assertion_bytes(&req.key_id, req.issued_at_ms, &req.nonce),
            &signature,
        )
        .map_err(|_| GatewayError::Unauthorized("the assertion does not verify".into()))
}

/// Nonces already used, for as long as one could still be replayed.
///
/// In process, like the PKCE verifiers next door and with the same consequence:
/// a restart forgets them. That is survivable here because an assertion is only
/// valid for `ASSERTION_SKEW_MS` either way, so the window a restart reopens is
/// two minutes wide and needs the signed bytes to have been captured already.
#[derive(Default)]
pub struct NonceCache {
    seen: Mutex<HashMap<String, i64>>,
}

impl NonceCache {
    /// Records a nonce, refusing one already used.
    pub fn remember(&self, key_id: &str, nonce: &str) -> Result<(), GatewayError> {
        let mut seen = self
            .seen
            .lock()
            .map_err(|_| GatewayError::Internal("nonce cache is poisoned".into()))?;
        let now = now_ms();
        // Swept on write rather than on a timer: the map only grows when
        // somebody signs in, so that is exactly when it is worth looking.
        seen.retain(|_, at| now - *at <= ASSERTION_SKEW_MS * 2);
        if seen.insert(format!("{key_id}:{nonce}"), now).is_some() {
            return Err(GatewayError::Unauthorized(
                "this assertion has already been used".into(),
            ));
        }
        Ok(())
    }
}

fn decode_key(encoded: &str, field: &str) -> Result<Vec<u8>, GatewayError> {
    let bytes = B64
        .decode(encoded.as_bytes())
        .map_err(|e| GatewayError::BadRequest(format!("{field} is not base64: {e}")))?;
    // Checked here rather than at first use: a key of the wrong size would
    // register cleanly and fail every signature afterwards, surfacing nowhere
    // near the mistake.
    if bytes.len() != 32 {
        return Err(GatewayError::BadRequest(format!(
            "{field} must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
