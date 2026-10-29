//! Signing in to a personal install (ADR 0029).
//!
//! The tests that matter here are the refusals, because what this replaced was
//! a sign-in that refused nothing: in mock mode `mock_google_<subject>` minted
//! a session for an owner id that is a deterministic hash of the subject, so
//! the identity was not guessed but derived.
//!
//! The happy path is short. The rest is: a wrong code, a spent code, a replayed
//! assertion, a stale one, one signed by the wrong key, and an OAuth owner's key
//! trying to come in through the local door.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::{KeyPair, Signer, ToFromBytes};
use gateway::config::Config;
use gateway::routes::local_auth::{assertion_bytes, owner_id_for};
use gateway::store::device_keys::{DeviceKey, InMemoryDeviceKeyStore};
use gateway::store::InMemoryTokenStore;
use gateway::vsock::client::EnclaveClient;
use gateway::{build_router, AppState};
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;
use x25519_dalek::{PublicKey, StaticSecret};

/// A gateway with local enrolment open, and its code.
///
/// The code file lands in a fresh temp directory per test: these tests consume
/// codes, and a shared file would make them order-dependent in a way that only
/// shows up when one is run alone.
fn gateway_with_enrolment() -> (Arc<AppState>, String, tempdir::TempDir) {
    let dir = tempdir::TempDir::new();
    let path = dir.path().join("enrolment-code");
    let enrolment = gateway::enrolment::Enrolment::open(&path).expect("enrolment");
    let code = std::fs::read_to_string(&path).expect("code").trim().to_string();

    let mut config = Config::mock();
    config.local_enrolment = Some(enrolment);
    config.allow_mock_identity = false;

    let state = Arc::new(AppState {
        enclave: EnclaveClient::new(&config.enclave_host, config.enclave_port),
        config,
        pending_auth: Default::default(),
        tokens: Box::new(InMemoryTokenStore::default()),
        device_keys: Box::new(InMemoryDeviceKeyStore::default()),
        local_nonces: Default::default(),
    });
    (state, code, dir)
}

/// The smallest temp directory that cleans up after itself.
mod tempdir {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new() -> Self {
            let mut path = std::env::temp_dir();
            path.push(format!(
                "kleos-local-identity-{}-{:?}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).expect("temp dir");
            Self(path)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

async fn call(state: &Arc<AppState>, path: &str, body: Value) -> (StatusCode, Value) {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = build_router(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

struct Device {
    signing: Ed25519KeyPair,
    sealing: StaticSecret,
}

impl Device {
    fn new() -> Self {
        Self {
            signing: Ed25519KeyPair::generate(&mut rand::thread_rng()),
            sealing: StaticSecret::random_from_rng(rand::thread_rng()),
        }
    }

    fn key_id(&self) -> String {
        shared::key_id_for(self.signing.public().as_bytes())
    }

    fn enrol_body(&self, code: &str) -> Value {
        json!({
            "enrolment_code": code,
            "public_key_b64": B64.encode(self.signing.public().as_bytes()),
            "encryption_key_b64": B64.encode(PublicKey::from(&self.sealing).as_bytes()),
            "label": "laptop",
        })
    }

    fn assertion(&self, issued_at_ms: i64, nonce: &str) -> Value {
        let key_id = self.key_id();
        let signature = self
            .signing
            .sign(&assertion_bytes(&key_id, issued_at_ms, nonce));
        json!({
            "key_id": key_id,
            "issued_at_ms": issued_at_ms,
            "nonce": nonce,
            "signature_b64": B64.encode(signature.as_ref()),
        })
    }
}

#[tokio::test]
async fn enrolling_makes_this_keypair_the_owner() {
    let (state, code, _dir) = gateway_with_enrolment();
    let device = Device::new();

    let (status, body) = call(&state, "/auth/local/enrol", device.enrol_body(&code)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["owner_id"], owner_id_for(&device.key_id()));
    assert_eq!(body["key_id"], device.key_id());
    assert!(!body["session_token"].as_str().unwrap().is_empty());
    // Stated rather than omitted: there is nothing for an enclave to attest to
    // here that this gateway did not already check.
    assert!(body["attestation"].is_null());
}

#[tokio::test]
async fn the_owner_id_is_the_key_and_not_a_name() {
    // Two installs, two keypairs, two owners -- with nothing to collide on.
    let (state, code, _dir) = gateway_with_enrolment();
    let (other_state, other_code, _other_dir) = gateway_with_enrolment();

    let (_, first) = call(&state, "/auth/local/enrol", Device::new().enrol_body(&code)).await;
    let (_, second) = call(
        &other_state,
        "/auth/local/enrol",
        Device::new().enrol_body(&other_code),
    )
    .await;
    assert_ne!(first["owner_id"], second["owner_id"]);
}

#[tokio::test]
async fn a_wrong_code_is_refused() {
    let (state, _code, _dir) = gateway_with_enrolment();
    let (status, _) = call(
        &state,
        "/auth/local/enrol",
        Device::new().enrol_body("not-the-code"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn the_code_is_spent_once() {
    let (state, code, _dir) = gateway_with_enrolment();
    let (first, _) = call(&state, "/auth/local/enrol", Device::new().enrol_body(&code)).await;
    assert_eq!(first, StatusCode::OK);

    // A second enrolment with the same code is a second owner on one install,
    // which is what the code exists to prevent.
    let (second, body) = call(&state, "/auth/local/enrol", Device::new().enrol_body(&code)).await;
    assert_eq!(second, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn an_enrolled_key_can_sign_in_again() {
    let (state, code, _dir) = gateway_with_enrolment();
    let device = Device::new();
    call(&state, "/auth/local/enrol", device.enrol_body(&code)).await;

    let (status, body) = call(
        &state,
        "/auth/local/session",
        device.assertion(now_ms(), "nonce-one"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["owner_id"], owner_id_for(&device.key_id()));
    assert!(!body["session_token"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn an_assertion_cannot_be_used_twice() {
    // The one an attacker gets for free if nothing remembers: the signed bytes
    // stay valid for the whole skew window, so without this a captured
    // assertion is a session for a minute.
    let (state, code, _dir) = gateway_with_enrolment();
    let device = Device::new();
    call(&state, "/auth/local/enrol", device.enrol_body(&code)).await;

    let assertion = device.assertion(now_ms(), "nonce-replayed");
    let (first, _) = call(&state, "/auth/local/session", assertion.clone()).await;
    assert_eq!(first, StatusCode::OK);
    let (second, body) = call(&state, "/auth/local/session", assertion).await;
    assert_eq!(second, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body["error"].as_str().unwrap().contains("already been used"));
}

#[tokio::test]
async fn a_stale_or_future_assertion_is_refused() {
    let (state, code, _dir) = gateway_with_enrolment();
    let device = Device::new();
    call(&state, "/auth/local/enrol", device.enrol_body(&code)).await;

    let (old, _) = call(
        &state,
        "/auth/local/session",
        device.assertion(now_ms() - 600_000, "nonce-old"),
    )
    .await;
    assert_eq!(old, StatusCode::UNAUTHORIZED);

    // Ahead of the gateway's clock is as much a replay window as behind it.
    let (ahead, _) = call(
        &state,
        "/auth/local/session",
        device.assertion(now_ms() + 600_000, "nonce-ahead"),
    )
    .await;
    assert_eq!(ahead, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_assertion_signed_by_another_key_is_refused() {
    let (state, code, _dir) = gateway_with_enrolment();
    let owner = Device::new();
    let impostor = Device::new();
    call(&state, "/auth/local/enrol", owner.enrol_body(&code)).await;

    // The owner's key id, the impostor's signature.
    let mut forged = impostor.assertion(now_ms(), "nonce-forged");
    forged["key_id"] = json!(owner.key_id());
    let (status, _) = call(&state, "/auth/local/session", forged).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_unenrolled_key_cannot_sign_in() {
    let (state, _code, _dir) = gateway_with_enrolment();
    let stranger = Device::new();
    let (status, _) = call(
        &state,
        "/auth/local/session",
        stranger.assertion(now_ms(), "nonce-stranger"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_key_registered_to_an_oauth_owner_cannot_use_the_local_door() {
    // The interesting one. A device key registered under `google:alice` is a
    // real registered key, and local sign-in only checks a signature -- so
    // without the owner-shape check it would be a way into an OAuth account
    // without the OAuth check.
    let (state, _code, _dir) = gateway_with_enrolment();
    let device = Device::new();
    state
        .device_keys
        .register(&DeviceKey {
            owner_id: hex::encode("google:alice"),
            key_id: device.key_id(),
            public_key: device.signing.public().as_bytes().to_vec(),
            encryption_key: None,
            label: "borrowed".into(),
            registered_at_ms: now_ms(),
            revoked_at_ms: None,
        })
        .await
        .expect("register");

    let (status, body) = call(
        &state,
        "/auth/local/session",
        device.assertion(now_ms(), "nonce-oauth-owner"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("does not sign in locally"));
}

#[tokio::test]
async fn a_revoked_key_cannot_sign_in() {
    let (state, code, _dir) = gateway_with_enrolment();
    let device = Device::new();
    call(&state, "/auth/local/enrol", device.enrol_body(&code)).await;
    state
        .device_keys
        .revoke(&owner_id_for(&device.key_id()), &device.key_id(), now_ms())
        .await
        .expect("revoke");

    let (status, _) = call(
        &state,
        "/auth/local/session",
        device.assertion(now_ms(), "nonce-revoked"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mock_sign_in_is_refused_unless_it_is_asked_for() {
    // What this whole ADR is about. The owner id is a hash of the subject, so
    // an accepted mock token is not a guessed session but a derived one.
    let (state, _code, _dir) = gateway_with_enrolment();
    let (status, body) = call(
        &state,
        "/auth/session",
        json!({"google_token": "mock_google_alice"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body["error"].as_str().unwrap().contains("mock sign-in"));
}

#[tokio::test]
async fn local_routes_are_absent_when_enrolment_is_disabled() {
    // What a hosted deployment runs: OAuth only, and an enrolment route there
    // would mint owners for anyone who can reach it.
    let mut config = Config::mock();
    config.local_enrolment = None;
    let state = Arc::new(AppState {
        enclave: EnclaveClient::new(&config.enclave_host, config.enclave_port),
        config,
        pending_auth: Default::default(),
        tokens: Box::new(InMemoryTokenStore::default()),
        device_keys: Box::new(InMemoryDeviceKeyStore::default()),
        local_nonces: Default::default(),
    });

    let (status, _) = call(
        &state,
        "/auth/local/enrol",
        Device::new().enrol_body("any-code"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
