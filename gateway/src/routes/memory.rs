use crate::error::GatewayError;
use crate::middleware::session::require_session;
use crate::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use shared::{
    ScopeIntrospectRequest, ScopeIntrospectResponse, SealDecryptRequest, SealDecryptResponse,
    SealEncryptRequest, SealEncryptResponse,
};
use std::sync::Arc;

// The Rust side of the memory layer is deliberately only two things:
// enclave-touching operations, and owner-authenticated permission gating.
//
// Retrieval, ranking, extraction and resolution all live in the Python
// orchestration service (LangGraph/LlamaIndex over Neo4j) and are not
// mirrored here -- there is no second implementation of the query path in
// Rust, on purpose. What the orchestrator cannot do for itself is (a) get
// raw content encrypted inside the TEE and (b) learn what an agent is
// actually authorised to see, which is what these routes provide.

/// Encrypts raw source content inside the enclave on behalf of the
/// ingestion graph. The owner session, not the caller's claim, decides
/// whose key the content is sealed under.
pub async fn seal_encrypt(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SealEncryptRequest>,
) -> Result<Json<SealEncryptResponse>, GatewayError> {
    let session = require_session(&headers, state.config.keys.session())?;
    let req = SealEncryptRequest {
        owner_id: session.owner_id,
        plaintext_b64: req.plaintext_b64,
    };
    let response = state.enclave.seal_encrypt(&req).await?;
    Ok(Json(response))
}

/// Decrypts content that was sealed inside the enclave, back out to the owner's
/// own orchestrator.
///
/// `store/mod.rs` says there is "deliberately no decrypt here", and that is
/// still true of the *sealed refresh token store* -- unsealing an OAuth refresh
/// token would hand the host standing access to a mailbox, which is the whole
/// thing the connect flow exists to prevent. This route unseals **record
/// content**, which is a different asset: the orchestrator produced it, from
/// plaintext it already had, and needs it back to answer a query.
///
/// Owner-authenticated, and the owner comes from the session rather than the
/// request, so a caller cannot ask for another owner's content. The enclave
/// derives the key from that owner id, so a mismatched key id fails inside the
/// TEE rather than here.
///
/// The thing that makes this safe to expose is *when* the orchestrator calls it:
/// only for objects that have already passed the permission check. The decrypt
/// budget is therefore the disclosure budget -- nothing gets unsealed that was
/// not about to be shown to someone entitled to see it.
pub async fn seal_decrypt(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<SealDecryptRequest>,
) -> Result<Json<SealDecryptResponse>, GatewayError> {
    let session = require_session(&headers, state.config.keys.session())?;
    let req = SealDecryptRequest {
        owner_id: session.owner_id,
        ciphertext_b64: req.ciphertext_b64,
        key_id: req.key_id,
    };
    let response = state.enclave.seal_decrypt(&req).await?;
    Ok(Json(response))
}

/// Registers a device public key for the authenticated owner.
///
/// This is the owner's side of the authorization root: the device keeps the
/// private half and from then on signs its own grants, which this gateway can
/// verify and cannot produce. See `shared/src/grants.rs` and ADR 0011.
///
/// Authorised by an owner session, which is still host-signed -- so this route is
/// where the design's remaining weakness lives, and it is deliberately loud about
/// it. A host that forges a session can register a key of its own; what it cannot
/// do is that invisibly, because the row is timestamped and `GET
/// /auth/device/keys` shows it to the owner.
#[derive(Debug, Deserialize)]
pub struct DeviceRegisterRequest {
    /// Raw Ed25519 public key, base64.
    pub public_key_b64: String,
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceKeyView {
    pub key_id: String,
    pub label: String,
    pub registered_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
}

impl From<&crate::store::device_keys::DeviceKey> for DeviceKeyView {
    fn from(key: &crate::store::device_keys::DeviceKey) -> Self {
        Self {
            key_id: key.key_id.clone(),
            label: key.label.clone(),
            registered_at_ms: key.registered_at_ms,
            revoked_at_ms: key.revoked_at_ms,
        }
    }
}

pub async fn device_register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DeviceRegisterRequest>,
) -> Result<Json<DeviceKeyView>, GatewayError> {
    let session = require_session(&headers, state.config.keys.session())?;
    let public_key = B64
        .decode(req.public_key_b64.as_bytes())
        .map_err(|e| GatewayError::BadRequest(format!("public_key_b64 is not base64: {e}")))?;
    // Length-checked here rather than at first use: a key of the wrong size would
    // otherwise register cleanly and fail every grant afterwards, with the error
    // surfacing nowhere near the mistake.
    if public_key.len() != 32 {
        return Err(GatewayError::BadRequest(format!(
            "an Ed25519 public key is 32 bytes, got {}",
            public_key.len()
        )));
    }

    let key = crate::store::device_keys::DeviceKey {
        owner_id: session.owner_id,
        key_id: shared::key_id_for(&public_key),
        public_key,
        label: req.label.chars().take(64).collect(),
        registered_at_ms: now_ms() as i64,
        revoked_at_ms: None,
    };
    let stored = state.device_keys.register(&key).await?;
    if stored.owner_id != key.owner_id {
        // The same key material already belongs to someone else. Refused rather
        // than shared: two owners signing with one key makes "whose grant is
        // this" unanswerable.
        return Err(GatewayError::Unauthorized(
            "this device key is already registered to another owner".into(),
        ));
    }
    tracing::info!(owner = %stored.owner_id, key_id = %stored.key_id, "device key registered");
    Ok(Json(DeviceKeyView::from(&stored)))
}

/// Every device key for the authenticated owner, revoked ones included.
///
/// Exists so key substitution is detectable: a client that remembers its own key
/// id can see at a glance whether the server is reporting a key it never created.
pub async fn device_keys(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<DeviceKeyView>>, GatewayError> {
    let session = require_session(&headers, state.config.keys.session())?;
    let keys = state.device_keys.list(&session.owner_id).await?;
    Ok(Json(keys.iter().map(DeviceKeyView::from).collect()))
}

/// Revokes one device key, invalidating every grant it ever signed.
///
/// The only revocation lever that exists. It is coarse -- per device, not per
/// grant -- and it is the first thing in this system that can take an outstanding
/// capability away before it expires.
#[derive(Debug, Deserialize)]
pub struct DeviceRevokeRequest {
    pub key_id: String,
}

#[derive(Debug, Serialize)]
pub struct DeviceRevokeResponse {
    pub revoked: bool,
}

pub async fn device_revoke(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DeviceRevokeRequest>,
) -> Result<Json<DeviceRevokeResponse>, GatewayError> {
    let session = require_session(&headers, state.config.keys.session())?;
    let revoked = state
        .device_keys
        .revoke(&session.owner_id, &req.key_id, now_ms() as i64)
        .await?;
    if revoked {
        tracing::warn!(
            owner = %session.owner_id,
            key_id = %req.key_id,
            "device key revoked; every grant it signed is now invalid"
        );
    }
    Ok(Json(DeviceRevokeResponse { revoked }))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

/// Resolves a grant token back to the authoritative scope.
///
/// The orchestrator calls this at the start of every read rather than trusting a
/// scope supplied by the requesting agent. What changed with ADR 0011 is what
/// "authoritative" rests on: the scope is now authoritative because the **owner
/// signed it**, not because this gateway did. There is no signing key here, so
/// this process can verify a grant and cannot produce one.
pub async fn scope_introspect(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ScopeIntrospectRequest>,
) -> Result<Json<ScopeIntrospectResponse>, GatewayError> {
    // The key is fetched before verification because a signature cannot be
    // checked without knowing which key it claims -- `parse_unverified` reads the
    // key id out of a payload nothing has authenticated yet, and nothing else in
    // that payload is trusted until the signature holds.
    let (claims, _, _) = shared::grants::parse_unverified(&req.grant_token)
        .map_err(|e| GatewayError::Unauthorized(format!("invalid grant: {e}")))?;
    let registered = state.device_keys.get(&claims.key_id).await?;

    let scope = shared::verify_grant(
        &req.grant_token,
        |_| {
            registered.map(|key| shared::RegisteredKey {
                owner_id: key.owner_id.clone(),
                public_key: key.public_key.clone(),
                revoked: key.is_revoked(),
            })
        },
        now_ms(),
    )
    .map_err(|e| GatewayError::Unauthorized(format!("invalid grant: {e}")))?;

    Ok(Json(ScopeIntrospectResponse {
        active: true,
        scope,
    }))
}
