//! The permission routes through the real gateway and a real enclave (ADR 0028).
//!
//! One property, and it is not "the verdict is correct" -- `evaluate` has its
//! own tests in `shared`. It is that **the scope the verdict is computed
//! against is the one the grant carried**, and that nothing a caller sends can
//! widen it. A route named `/memory/evaluate` that trusted a caller-supplied
//! scope would be an authorisation check the caller authorises.
//!
//! A real enclave in-process, for the reason `assemble_tests.rs` runs one: the
//! claim is a property of the whole path, and a stand-in could be wrong in the
//! gateway's favour.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::{KeyPair, ToFromBytes};
use gateway::config::Config;
use gateway::store::device_keys::InMemoryDeviceKeyStore;
use gateway::store::InMemoryTokenStore;
use gateway::vsock::client::EnclaveClient;
use gateway::{build_router, AppState};
use serde_json::{json, Value};
use shared::{EntityKind, MemoryKind, Scope, Sensitivity, SourceId};
use std::sync::Arc;
use tower::ServiceExt;

const HOUR_MS: u64 = 3_600_000;
const OWNER: &str = "owner-evaluate-routes";
const INTRUDER: &str = "owner-somebody-else";

async fn gateway_with_enclave() -> Arc<AppState> {
    let enclave_state = Arc::new(enclave::AppState {
        signing_key: enclave::services::attestation::generate_ephemeral_key(),
        config: enclave::config::Config::mock(),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, enclave::build_router(enclave_state))
            .await
            .unwrap();
    });

    let mut config = Config::mock();
    config.enclave_port = port;
    let enclave = EnclaveClient::new(&config.enclave_host, config.enclave_port);
    Arc::new(AppState {
        config,
        enclave,
        pending_auth: Default::default(),
        tokens: Box::new(InMemoryTokenStore::default()),
        device_keys: Box::new(InMemoryDeviceKeyStore::default()),
        local_nonces: Default::default(),
    })
}

async fn call(state: &Arc<AppState>, request: Request<Body>) -> (StatusCode, Value) {
    let response = build_router(state.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

fn post(path: &str, session: Option<&str>, body: Value) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json");
    if let Some(token) = session {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

fn session_for(owner: &str) -> String {
    gateway::middleware::session::issue_session_token(owner, Config::mock().keys.session(), 3600)
        .unwrap()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn scope(owner: &str) -> Scope {
    Scope {
        agent_id: "agent-1".into(),
        owner_id: owner.into(),
        sources: vec![SourceId::parse("text").unwrap()],
        entity_kinds: vec![EntityKind::Project],
        max_sensitivity: Sensitivity::Confidential,
        memory_kinds: vec![MemoryKind::Episodic],
        may_write: true,
        write_sources: vec![SourceId::parse("agent").unwrap()],
        ..Default::default()
    }
}

struct Device {
    signing: Ed25519KeyPair,
}

impl Device {
    fn new() -> Self {
        Self {
            signing: Ed25519KeyPair::generate(&mut rand::thread_rng()),
        }
    }

    async fn register(&self, state: &Arc<AppState>, owner: &str) {
        let (status, response) = call(
            state,
            post(
                "/auth/device/register",
                Some(&session_for(owner)),
                json!({
                    "public_key_b64": B64.encode(self.signing.public().as_bytes()),
                    "label": "test",
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "register failed: {response}");
    }

    fn grant_for(&self, scope: &Scope) -> String {
        shared::sign_grant(scope, &self.signing, now_ms(), HOUR_MS, "n1").unwrap()
    }
}

fn acl(owner: &str, overrides: Value) -> Value {
    let mut base = json!({
        "owner_id": owner,
        "sources": ["text"],
        "sensitivity": "personal",
        "entity_kinds": ["project"],
        "occurred_at_ms": 1_000u64,
        "memory_kind": "episodic",
    });
    for (key, value) in overrides.as_object().unwrap() {
        base[key] = value.clone();
    }
    base
}

#[tokio::test]
async fn a_verdict_comes_back_per_object() {
    let state = gateway_with_enclave().await;
    let device = Device::new();
    device.register(&state, OWNER).await;

    let (status, body) = call(
        &state,
        post(
            "/memory/evaluate",
            None,
            json!({
                "grant_token": device.grant_for(&scope(OWNER)),
                "objects": [
                    {"id": "in-scope", "acl": acl(OWNER, json!({}))},
                    {"id": "wrong-source", "acl": acl(OWNER, json!({"sources": ["github"]}))},
                ],
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let verdicts = body["verdicts"].as_array().unwrap();
    assert_eq!(verdicts[0]["id"], "in-scope");
    assert_eq!(verdicts[0]["allowed"], true);
    assert_eq!(verdicts[1]["allowed"], false);
    assert_eq!(verdicts[1]["reason"], "source_not_in_scope");
    // The clock the enclave used, reported rather than assumed.
    assert!(body["now_ms"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn the_scope_cannot_be_sent_by_the_caller() {
    // The attack: a narrow grant, plus a wide scope in the body. There is no
    // field for it, so a caller that sends one is sending something serde drops
    // -- and the verdict stays the narrow grant's.
    let state = gateway_with_enclave().await;
    let device = Device::new();
    device.register(&state, OWNER).await;

    let mut narrow = scope(OWNER);
    narrow.sources = vec![SourceId::parse("github").unwrap()];
    let mut wide = scope(OWNER);
    wide.sources = vec![SourceId::parse("text").unwrap()];

    let (status, body) = call(
        &state,
        post(
            "/memory/evaluate",
            None,
            json!({
                "grant_token": device.grant_for(&narrow),
                "scope": wide,
                "owner_id": OWNER,
                "objects": [{"id": "a", "acl": acl(OWNER, json!({}))}],
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["verdicts"][0]["allowed"], false);
    assert_eq!(body["verdicts"][0]["reason"], "source_not_in_scope");
}

#[tokio::test]
async fn an_unregistered_or_revoked_key_cannot_ask_at_all() {
    let state = gateway_with_enclave().await;
    let stranger = Device::new();
    // Never registered, so there is no key to verify the signature against.
    let (status, _) = call(
        &state,
        post(
            "/memory/evaluate",
            None,
            json!({
                "grant_token": stranger.grant_for(&scope(OWNER)),
                "objects": [{"id": "a", "acl": acl(OWNER, json!({}))}],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn another_owners_object_is_denied_not_answered() {
    // The owner comes from the verified grant, so an ACL naming somebody else
    // is simply out of scope. Worth a test because the alternative -- taking
    // the owner from the request -- would make this a disclosure.
    let state = gateway_with_enclave().await;
    let device = Device::new();
    device.register(&state, OWNER).await;

    let (status, body) = call(
        &state,
        post(
            "/memory/evaluate",
            None,
            json!({
                "grant_token": device.grant_for(&scope(OWNER)),
                "objects": [{"id": "theirs", "acl": acl(INTRUDER, json!({}))}],
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["verdicts"][0]["allowed"], false);
    assert_eq!(body["verdicts"][0]["reason"], "wrong_owner");
}

// -- the write gate ----------------------------------------------------

fn intent(owner: &str, overrides: Value) -> Value {
    let mut base = json!({
        "owner_id": owner,
        "source": "agent",
        "entity_kinds": ["project"],
        "sensitivity": "personal",
        "memory_kind": "episodic",
    });
    for (key, value) in overrides.as_object().unwrap() {
        base[key] = value.clone();
    }
    base
}

#[tokio::test]
async fn a_write_under_a_writing_grant_is_allowed() {
    let state = gateway_with_enclave().await;
    let device = Device::new();
    device.register(&state, OWNER).await;

    let (status, body) = call(
        &state,
        post(
            "/memory/evaluate-write",
            None,
            json!({
                "grant_token": device.grant_for(&scope(OWNER)),
                "intent": intent(OWNER, json!({})),
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["allowed"], true);
}

#[tokio::test]
async fn a_read_only_grant_cannot_write() {
    let state = gateway_with_enclave().await;
    let device = Device::new();
    device.register(&state, OWNER).await;

    let mut read_only = scope(OWNER);
    read_only.may_write = false;
    read_only.write_sources = vec![];

    let (status, body) = call(
        &state,
        post(
            "/memory/evaluate-write",
            None,
            json!({
                "grant_token": device.grant_for(&read_only),
                "intent": intent(OWNER, json!({})),
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["allowed"], false);
    assert_eq!(body["reason"], "write_not_permitted");
}

#[tokio::test]
async fn an_intent_naming_another_owner_is_overwritten_not_honoured() {
    // The intent carries an `owner_id` because `evaluate_write` needs one, and
    // a caller could name somebody else's. The gateway overwrites it from the
    // verified scope rather than comparing -- a comparison is what a later
    // change deletes as redundant (ADR 0027 removed the same field for the same
    // reason). So this is allowed, under *this* owner, rather than refused in a
    // way that confirms the other owner exists.
    let state = gateway_with_enclave().await;
    let device = Device::new();
    device.register(&state, OWNER).await;

    let (status, body) = call(
        &state,
        post(
            "/memory/evaluate-write",
            None,
            json!({
                "grant_token": device.grant_for(&scope(OWNER)),
                "intent": intent(INTRUDER, json!({})),
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["allowed"], true,
        "the intent's owner was replaced by the grant's, not compared against it"
    );
}
