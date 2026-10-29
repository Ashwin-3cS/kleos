//! The read path of ADR 0024, through the real gateway and a real enclave.
//!
//! One property, and it is not "the content is encrypted". It is that **the
//! device the content is encrypted to is the one the grant names**. A
//! caller-supplied recipient would be a hole large enough to drive the whole
//! system through: anyone holding a leaked grant could ask for the answer
//! sealed to a key they control, and every other control here would still pass.
//!
//! So these tests do what an attacker would: sign a grant with one device's key
//! and try to get the answer readable somewhere else. They run a real enclave
//! in-process for the same reason `oauth_flow_tests.rs` does -- the claim is a
//! property of the whole path, and a stand-in for the enclave could be wrong in
//! the gateway's favour.

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use enclave::services::recipient::open_as_device;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::{KeyPair, ToFromBytes};
use gateway::config::Config;
use gateway::store::device_keys::InMemoryDeviceKeyStore;
use gateway::store::InMemoryTokenStore;
use gateway::vsock::client::EnclaveClient;
use gateway::{build_router, AppState};
use serde_json::{json, Value};
use shared::{AssembledAnswer, EntityKind, MemoryKind, Scope, SealedToDevice, Sensitivity, SourceId};
use std::sync::Arc;
use tower::ServiceExt;
use x25519_dalek::{PublicKey, StaticSecret};

const HOUR_MS: u64 = 3_600_000;

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

/// One device as the owner's browser holds it: two keypairs, one registration.
struct Device {
    signing: Ed25519KeyPair,
    sealing: Option<StaticSecret>,
}

impl Device {
    fn new() -> Self {
        Self {
            signing: Ed25519KeyPair::generate(&mut rand::thread_rng()),
            sealing: Some(StaticSecret::random_from_rng(rand::thread_rng())),
        }
    }

    /// A device registered before ADR 0024, or by a client that sends only the
    /// signing half.
    fn signing_only() -> Self {
        Self {
            signing: Ed25519KeyPair::generate(&mut rand::thread_rng()),
            sealing: None,
        }
    }

    async fn register(&self, state: &Arc<AppState>, owner: &str) -> String {
        let mut body = json!({
            "public_key_b64": B64.encode(self.signing.public().as_bytes()),
            "label": "test",
        });
        if let Some(secret) = &self.sealing {
            body["encryption_key_b64"] =
                json!(B64.encode(PublicKey::from(secret).as_bytes()));
        }
        let (status, response) = call(
            state,
            post("/auth/device/register", Some(&session_for(owner)), body),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "register failed: {response}");
        response["key_id"].as_str().unwrap().to_string()
    }

    fn grant(&self, owner: &str) -> String {
        shared::sign_grant(&scope(owner), &self.signing, now_ms(), HOUR_MS, "n1").unwrap()
    }

    fn open(&self, sealed: &Value) -> AssembledAnswer {
        let sealed: SealedToDevice = serde_json::from_value(sealed.clone()).unwrap();
        let plaintext =
            open_as_device(&self.sealing.as_ref().unwrap().to_bytes(), &sealed).unwrap();
        serde_json::from_slice(&plaintext).unwrap()
    }
}

fn scope(owner: &str) -> Scope {
    Scope {
        agent_id: "agent-1".into(),
        owner_id: owner.into(),
        sources: vec![SourceId::parse("text").unwrap()],
        entity_kinds: vec![EntityKind::Project],
        max_sensitivity: Sensitivity::Confidential,
        memory_kinds: vec![MemoryKind::Episodic, MemoryKind::Procedural],
        ..Default::default()
    }
}

fn a_claim(id: &str, statement: &str, owner: &str) -> Value {
    json!({
        "object_type": "claim",
        "id": id,
        "owner_id": owner,
        "statement": statement,
        "subject_entity_ids": [],
        "status": "active",
        "supersedes": [],
        "contradicts": [],
        "reconciled_into": null,
        "commitment": null,
        "asserted_at_ms": 1_000,
        "provenance": {
            "citations": [],
            "derived_by": "test",
            "confidence": 1.0,
            "created_at_ms": 1_000
        },
        "acl": {
            "owner_id": owner,
            "sources": ["text"],
            "sensitivity": "personal",
            "entity_kinds": ["project"],
            "occurred_at_ms": 1_000,
            "denied_agents": []
        }
    })
}

fn ask(grant: &str, statement: &str) -> Value {
    json!({
        "grant_token": grant,
        "question": "what did we decide?",
        "candidates": [{ "node": a_claim("c1", statement, "owner-1"), "score": 0.9 }],
    })
}

#[tokio::test]
async fn the_answer_is_sealed_to_the_device_that_signed_the_grant() {
    let state = gateway_with_enclave().await;
    let device = Device::new();
    let key_id = device.register(&state, "owner-1").await;

    let (status, body) = call(
        &state,
        post(
            "/memory/assemble",
            None,
            ask(&device.grant("owner-1"), "we decided on Neo4j"),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    // Echoed back so the device can tell the answer came to the key it asked
    // with, rather than to another of the owner's devices.
    assert_eq!(body["sealed"]["recipient_key_id"], json!(key_id));
    assert_eq!(body["disclosed_ids"], json!(["c1"]));
    assert!(!body.to_string().contains("Neo4j"));

    assert_eq!(device.open(&body["sealed"]).text, "- we decided on Neo4j (c1)");
}

#[tokio::test]
async fn a_second_device_cannot_read_the_first_devices_answer() {
    // The recipient is derived from the grant, so there is no request a second
    // device can make that gets the first device's answer into its own hands.
    // This is the same owner -- both devices are legitimately theirs -- and it
    // still does not work, which is the point: the blast radius of a stolen
    // grant is one device, not one account.
    let state = gateway_with_enclave().await;
    let first = Device::new();
    let second = Device::new();
    first.register(&state, "owner-1").await;
    second.register(&state, "owner-1").await;

    let (_, body) = call(
        &state,
        post(
            "/memory/assemble",
            None,
            ask(&first.grant("owner-1"), "we decided on Neo4j"),
        ),
    )
    .await;

    let sealed: SealedToDevice = serde_json::from_value(body["sealed"].clone()).unwrap();
    assert!(open_as_device(&second.sealing.unwrap().to_bytes(), &sealed).is_err());
}

#[tokio::test]
async fn a_recipient_in_the_request_body_is_ignored_rather_than_honoured() {
    // The attack the derivation exists to stop, written out. A field named
    // after the enclave's own parameter is sent alongside a valid grant; the
    // request body type has no such field, so serde drops it and the gateway
    // looks the recipient up as always.
    let state = gateway_with_enclave().await;
    let device = Device::new();
    let attacker = StaticSecret::random_from_rng(rand::thread_rng());
    device.register(&state, "owner-1").await;

    let mut body = ask(&device.grant("owner-1"), "we decided on Neo4j");
    body["recipient_key_b64"] = json!(B64.encode(PublicKey::from(&attacker).as_bytes()));
    body["owner_id"] = json!("owner-2");

    let (status, response) = call(&state, post("/memory/assemble", None, body)).await;

    assert_eq!(status, StatusCode::OK, "{response}");
    let sealed: SealedToDevice = serde_json::from_value(response["sealed"].clone()).unwrap();
    assert!(open_as_device(&attacker.to_bytes(), &sealed).is_err());
    assert_eq!(device.open(&response["sealed"]).text, "- we decided on Neo4j (c1)");
}

#[tokio::test]
async fn a_device_with_no_encryption_key_is_refused_and_told_why() {
    // Not a failure deeper down. Such a device keeps signing grants and reading
    // the unsealed paths exactly as it did, so the refusal has to name the one
    // thing that is missing -- an owner otherwise sees a working grant and a
    // failing query.
    let state = gateway_with_enclave().await;
    let device = Device::signing_only();
    device.register(&state, "owner-1").await;

    let (status, body) = call(
        &state,
        post("/memory/assemble", None, ask(&device.grant("owner-1"), "anything")),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let message = body["error"].as_str().unwrap_or_default();
    assert!(message.contains("encryption key"), "{message}");
    assert!(message.contains("re-register"), "{message}");
}

#[tokio::test]
async fn a_revoked_device_receives_nothing() {
    // Revocation has to mean the device stops *receiving* as well as stops
    // signing. `verify_grant` refuses first, which is why this asserts on the
    // status and not on a sealed blob: there must be no path that reaches the
    // enclave at all.
    let state = gateway_with_enclave().await;
    let device = Device::new();
    let key_id = device.register(&state, "owner-1").await;
    let grant = device.grant("owner-1");

    let (status, _) = call(
        &state,
        post(
            "/auth/device/revoke",
            Some(&session_for("owner-1")),
            json!({ "key_id": key_id }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = call(&state, post("/memory/assemble", None, ask(&grant, "anything"))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_unregistered_grant_never_reaches_the_enclave() {
    let state = gateway_with_enclave().await;
    let stranger = Device::new();

    let (status, _) = call(
        &state,
        post(
            "/memory/assemble",
            None,
            ask(&stranger.grant("owner-1"), "anything"),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn one_owners_grant_cannot_assemble_anothers_memory() {
    // The candidates are chosen by the host, so a compromised orchestrator can
    // put anything in the list. The ACL check inside the enclave is what makes
    // that pointless, and it runs against the owner in the verified grant.
    let state = gateway_with_enclave().await;
    let device = Device::new();
    device.register(&state, "owner-1").await;

    let (status, body) = call(
        &state,
        post(
            "/memory/assemble",
            None,
            json!({
                "grant_token": device.grant("owner-1"),
                "question": "?",
                "candidates": [{
                    "node": a_claim("c9", "someone else's memory", "owner-2"),
                    "score": 0.9
                }],
            }),
        ),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["denials"][0]["reason"], json!("wrong_owner"));
    assert!(body["disclosed_ids"].as_array().unwrap().is_empty());
    let answer = device.open(&body["sealed"]);
    assert!(!answer.answered);
    assert!(!answer.text.contains("someone else's memory"));
}
