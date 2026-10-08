//! The gateway can verify a grant and cannot mint one.
//!
//! Driven through the real router with a real enclave router behind it, in the
//! same spirit as `oauth_flow_tests.rs`: the claim is a property of the whole
//! path, so a stand-in for any part of it could be wrong in the gateway's favour.
//!
//! The property under test is narrow and worth stating precisely. It is **not**
//! that an operator cannot obtain a grant -- registration is authorised by an
//! owner session, sessions are still host-signed, so a host that forges a session
//! can register a key of its own. It is that the host has no key that signs a
//! grant *silently*: forging one requires registering a key, which is a stored,
//! timestamped row the owner can list. See ADR 0011.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::{KeyPair, ToFromBytes};
use gateway::config::Config;
use gateway::store::device_keys::InMemoryDeviceKeyStore;
use gateway::store::InMemoryTokenStore;
use gateway::{build_router, AppState};
use serde_json::{json, Value};
use shared::{EntityKind, Scope, Sensitivity, SourceId};
use std::sync::Arc;
use tower::ServiceExt;

const HOUR_MS: u64 = 3_600_000;

fn state() -> Arc<AppState> {
    Arc::new(AppState {
        config: Config::mock(),
        enclave: gateway::vsock::client::EnclaveClient::new("127.0.0.1", 4000),
        pending_auth: Default::default(),
        tokens: Box::new(InMemoryTokenStore::default()),
        device_keys: Box::new(InMemoryDeviceKeyStore::default()),
    })
}

async fn call(state: &Arc<AppState>, request: Request<Body>) -> (StatusCode, Value) {
    let response = build_router(state.clone())
        .oneshot(request)
        .await
        .expect("router responds");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("body readable");
    let value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, value)
}

fn post(path: &str, session: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = session {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder.body(Body::from(body.to_string())).expect("request")
}

fn session_for(owner: &str) -> String {
    gateway::middleware::session::issue_session_token(owner, Config::mock().keys.session(), 3600)
        .expect("session")
}

fn keypair() -> Ed25519KeyPair {
    Ed25519KeyPair::generate(&mut rand::thread_rng())
}

fn scope(owner: &str, agent: &str) -> Scope {
    Scope {
        agent_id: agent.into(),
        owner_id: owner.into(),
        sources: vec![SourceId::parse("mock").unwrap()],
        entity_kinds: vec![EntityKind::Project],
        not_before_ms: None,
        not_after_ms: None,
        max_sensitivity: Sensitivity::Personal,
        expires_at_ms: None,
        // Read-only. A capability added to `Scope` later must not quietly
        // become granted in a test that never mentioned it.
        ..Default::default()
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

async fn register(state: &Arc<AppState>, owner: &str, kp: &Ed25519KeyPair) -> String {
    let (status, body) = call(
        state,
        post(
            "/auth/device/register",
            Some(&session_for(owner)),
            json!({"public_key_b64": B64.encode(kp.public().as_bytes()), "label": "test"}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "register failed: {body}");
    body["key_id"].as_str().expect("key_id").to_string()
}

#[tokio::test]
async fn there_is_no_route_that_mints_a_grant() {
    // The route that used to exist. Its absence is the feature.
    let state = state();
    let (status, _) = call(
        &state,
        post(
            "/memory/scope/grant",
            Some(&session_for("owner-1")),
            json!({"ttl_secs": 3600, "scope": scope("owner-1", "agent-1")}),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "the gateway must not expose a way to mint a grant"
    );
}

#[tokio::test]
async fn an_owner_signed_grant_introspects_to_its_scope() {
    let state = state();
    let kp = keypair();
    register(&state, "owner-1", &kp).await;

    let token =
        shared::sign_grant(&scope("owner-1", "agent-1"), &kp, now_ms(), HOUR_MS, "n1").unwrap();
    let (status, body) = call(
        &state,
        post("/memory/scope/introspect", None, json!({"grant_token": token})),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "introspect failed: {body}");
    assert_eq!(body["active"], json!(true));
    assert_eq!(body["scope"]["agent_id"], json!("agent-1"));
    assert_eq!(body["scope"]["owner_id"], json!("owner-1"));
}

#[tokio::test]
async fn introspect_reports_the_device_that_signed_the_grant() {
    // The identity an agent asserts and the identity it proves are different
    // things. `scope.agent_id` is a label the owner typed before signing; the key
    // id is the key this gateway just checked a signature against. Attribution
    // downstream rests on the second, so introspection has to return it -- it
    // used to be read, used, and dropped. ADR 0016.
    let state = state();
    let kp = keypair();
    let key_id = register(&state, "owner-1", &kp).await;

    let token =
        shared::sign_grant(&scope("owner-1", "agent-1"), &kp, now_ms(), HOUR_MS, "n1").unwrap();
    let (status, body) = call(
        &state,
        post("/memory/scope/introspect", None, json!({"grant_token": token})),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "introspect failed: {body}");
    assert_eq!(
        body["key_id"],
        json!(key_id),
        "introspection must name the registered device key it verified against"
    );
}

#[tokio::test]
async fn the_signing_device_is_not_a_field_the_signer_can_choose() {
    // Two agents can be handed the same scope file, so `agent_id` collides by
    // design and is not a device id. The guard is that the device id is reported
    // out of band from the signed payload: two grants over an identical scope,
    // signed by different registered keys, must introspect to different devices.
    let state = state();
    let (kp1, kp2) = (keypair(), keypair());
    let id1 = register(&state, "owner-1", &kp1).await;
    let id2 = register(&state, "owner-1", &kp2).await;
    assert_ne!(id1, id2);

    let same_scope = scope("owner-1", "agent-1");
    let mut seen = vec![];
    for (kp, nonce) in [(&kp1, "n1"), (&kp2, "n2")] {
        let token = shared::sign_grant(&same_scope, kp, now_ms(), HOUR_MS, nonce).unwrap();
        let (status, body) = call(
            &state,
            post("/memory/scope/introspect", None, json!({"grant_token": token})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "introspect failed: {body}");
        assert_eq!(body["scope"]["agent_id"], json!("agent-1"));
        seen.push(body["key_id"].as_str().unwrap().to_string());
    }

    assert_eq!(seen, vec![id1, id2], "the same label, two distinguishable devices");
}

#[tokio::test]
async fn a_grant_signed_by_an_unregistered_key_is_refused() {
    let state = state();
    let kp = keypair();
    // Deliberately not registered: this is the host holding its own keypair.
    let token =
        shared::sign_grant(&scope("owner-1", "agent-1"), &kp, now_ms(), HOUR_MS, "n1").unwrap();

    let (status, _) = call(
        &state,
        post("/memory/scope/introspect", None, json!({"grant_token": token})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_registered_key_cannot_sign_for_another_owner() {
    let state = state();
    let kp = keypair();
    register(&state, "owner-1", &kp).await;

    // A real signature from a real registered key, over somebody else's memory.
    let token =
        shared::sign_grant(&scope("owner-2", "agent-1"), &kp, now_ms(), HOUR_MS, "n1").unwrap();
    let (status, _) = call(
        &state,
        post("/memory/scope/introspect", None, json!({"grant_token": token})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoking_a_device_key_invalidates_the_grants_it_signed() {
    let state = state();
    let kp = keypair();
    let key_id = register(&state, "owner-1", &kp).await;
    let token =
        shared::sign_grant(&scope("owner-1", "agent-1"), &kp, now_ms(), HOUR_MS, "n1").unwrap();

    let (status, _) = call(
        &state,
        post("/memory/scope/introspect", None, json!({"grant_token": token.clone()})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "valid before revocation");

    let (status, body) = call(
        &state,
        post(
            "/auth/device/revoke",
            Some(&session_for("owner-1")),
            json!({"key_id": key_id}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], json!(true));

    // The first revocation lever this system has ever had.
    let (status, _) = call(
        &state,
        post("/memory/scope/introspect", None, json!({"grant_token": token})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a revoked device key must invalidate grants it already signed"
    );
}

#[tokio::test]
async fn one_owner_cannot_revoke_anothers_device() {
    let state = state();
    let kp = keypair();
    let key_id = register(&state, "owner-1", &kp).await;

    let (status, body) = call(
        &state,
        post(
            "/auth/device/revoke",
            Some(&session_for("owner-2")),
            json!({"key_id": key_id}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["revoked"], json!(false), "nothing should have changed");
}

#[tokio::test]
async fn registering_requires_an_owner_session() {
    let state = state();
    let kp = keypair();
    let (status, _) = call(
        &state,
        post(
            "/auth/device/register",
            None,
            json!({"public_key_b64": B64.encode(kp.public().as_bytes())}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_key_of_the_wrong_length_is_refused_at_registration() {
    // Otherwise it registers cleanly and fails every grant afterwards, with the
    // error surfacing nowhere near the mistake.
    let state = state();
    let (status, _) = call(
        &state,
        post(
            "/auth/device/register",
            Some(&session_for("owner-1")),
            json!({"public_key_b64": B64.encode([1u8; 16])}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_owner_can_list_their_keys_to_detect_substitution() {
    // The mitigation for the one attack this design does not prevent: a client
    // that remembers its own key id can see a key it never created.
    let state = state();
    let mine = keypair();
    let key_id = register(&state, "owner-1", &mine).await;
    let planted = keypair();
    register(&state, "owner-1", &planted).await;

    let response = build_router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/auth/device/keys")
                .header("authorization", format!("Bearer {}", session_for("owner-1")))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    let listed: Vec<Value> = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(listed.len(), 2);
    let ids: Vec<&str> = listed.iter().map(|k| k["key_id"].as_str().unwrap()).collect();
    assert!(ids.contains(&key_id.as_str()));
    assert!(
        ids.len() > 1,
        "a key the owner did not create is visible, which is the whole mitigation"
    );
}

#[tokio::test]
async fn registration_is_idempotent() {
    let state = state();
    let kp = keypair();
    let first = register(&state, "owner-1", &kp).await;
    let second = register(&state, "owner-1", &kp).await;
    assert_eq!(first, second);
}

#[tokio::test]
async fn the_same_key_cannot_be_claimed_by_two_owners() {
    // Two owners signing with one key makes "whose grant is this" unanswerable.
    let state = state();
    let kp = keypair();
    register(&state, "owner-1", &kp).await;

    let (status, _) = call(
        &state,
        post(
            "/auth/device/register",
            Some(&session_for("owner-2")),
            json!({"public_key_b64": B64.encode(kp.public().as_bytes())}),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
