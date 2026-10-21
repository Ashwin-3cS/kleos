use axum::body::Body;
use axum::http::{Request, StatusCode};
use enclave::config::Config;
use enclave::services::attestation::generate_ephemeral_key;
use enclave::{build_router, AppState};
use std::sync::Arc;
use tower::util::ServiceExt;

fn test_state() -> Arc<AppState> {
    Arc::new(AppState {
        signing_key: generate_ephemeral_key(),
        config: Config::mock(),
    })
}

#[tokio::test]
async fn health_returns_ok() {
    let router = build_router(test_state());
    let response = router
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn attest_returns_mock_document() {
    let router = build_router(test_state());
    let response = router
        .oneshot(Request::builder().uri("/attest").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn identity_verify_requires_a_signal() {
    let router = build_router(test_state());
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/identity/verify")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

// -- the action broker ---------------------------------------------------
//
// The rule the broker exists for: an agent submits an intent and receives an
// acknowledgement, never the credential and never the material that credential
// unlocks. These are mostly about what does *not* come back.

async fn act(body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let router = build_router(test_state());
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/act")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn an_action_returns_an_ack_and_never_the_credential() {
    // `attest.digest` is the one wired action, and deliberately the one needing
    // no provider credential: it proves the shape without pretending the
    // credential path exists. What comes back is a digest and one line of
    // summary -- no attestation document, no key material, no provider response.
    let (status, ack) = act(serde_json::json!({
        "owner_id": "owner-1",
        "action_id": "attest.digest",
        "args": {"digest": "deadbeef"},
        "at_ms": 1_700_000_000_000u64,
    }))
    .await;

    assert_eq!(status, StatusCode::OK, "{ack}");
    assert_eq!(ack["ok"], serde_json::json!(true));
    assert!(!ack["digest"].as_str().unwrap().is_empty());
    assert!(ack["sealed_ref"].is_null());

    // The attestation itself must not cross back. In mock mode it is prefixed
    // `MOCK_ATTESTATION_`, which is exactly the string to look for.
    let serialised = ack.to_string();
    assert!(
        !serialised.contains("MOCK_ATTESTATION_"),
        "the ack must acknowledge, not disclose: {serialised}"
    );
    assert!(
        !serialised.contains("deadbeefdeadbeef"),
        "and must not echo its input back as content"
    );
}

#[tokio::test]
async fn an_unregistered_action_id_is_refused_and_says_what_is_known() {
    let (status, ack) = act(serde_json::json!({
        "owner_id": "owner-1",
        "action_id": "rm.minus.rf",
        "args": {},
        "at_ms": 1u64,
    }))
    .await;

    assert_eq!(status, StatusCode::OK, "a refusal is still an ack");
    assert_eq!(ack["ok"], serde_json::json!(false));
    let error = ack["error"].as_str().unwrap();
    assert!(error.contains("unknown action"));
    // Listed, so an operator reading a refusal learns what *is* known without
    // reading the registry.
    assert!(error.contains("attest.digest"));
}

#[tokio::test]
async fn a_declared_but_unwired_action_says_so_rather_than_doing_nothing() {
    // The Google and GitHub actions are declared with real metadata and refuse
    // explicitly, the same discipline their connectors practise. An action that
    // silently did nothing would be worse than one that says why it cannot.
    let (status, ack) = act(serde_json::json!({
        "owner_id": "owner-1",
        "action_id": "google.gmail.send",
        "args": {"to": "someone@example.com"},
        "at_ms": 1u64,
    }))
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(ack["ok"], serde_json::json!(false));
    let error = ack["error"].as_str().unwrap();
    assert!(error.contains("declared and not wired"));
    assert!(error.contains("sealed refresh token"));
}

#[tokio::test]
async fn a_failed_action_is_still_an_attempt_that_happened() {
    // 200 with ok:false, on purpose. An attempt made and failed is a different
    // fact from an attempt never made, and collapsing them into an HTTP error
    // would lose the distinction a trace needs most.
    let (status, ack) = act(serde_json::json!({
        "owner_id": "owner-1",
        "action_id": "attest.digest",
        "args": {},
        "at_ms": 1u64,
    }))
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(ack["ok"], serde_json::json!(false));
    assert_eq!(ack["action_id"], serde_json::json!("attest.digest"));
    assert!(ack["error"].as_str().unwrap().contains("needs a 'digest'"));
}

#[tokio::test]
async fn an_action_without_an_owner_did_not_come_through_the_gateway() {
    // The gateway sets `owner_id` from the verified scope, so an empty one means
    // the request bypassed it. Not an action failure -- a malformed request.
    let (status, _) = act(serde_json::json!({
        "owner_id": "",
        "action_id": "attest.digest",
        "args": {"digest": "a"},
        "at_ms": 1u64,
    }))
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_summary_is_bounded() {
    // An ack goes straight into an agent's context window, so an unbounded
    // summary is a way to push arbitrary output through a field documented as
    // one line.
    let long = "x".repeat(5_000);
    let (status, ack) = act(serde_json::json!({
        "owner_id": "owner-1",
        "action_id": long,
        "args": {},
        "at_ms": 1u64,
    }))
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(ack["summary"].as_str().unwrap().len() <= 243);
}

// -- assembling and sealing to the device (ADR 0024) ---------------------
//
// The route's contract in one line: the host gets structure, the device gets
// content. These tests go through the HTTP surface rather than calling
// `services::assemble` directly, because what matters is the shape of the
// *reply* -- a unit test on the assembler can only check the plaintext it
// produced, and the whole point is what the host receives instead of it.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use enclave::services::recipient::open_as_device;
use shared::{AssembledAnswer, SealedToDevice};
use x25519_dalek::{PublicKey, StaticSecret};

async fn post(uri: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let router = build_router(test_state());
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap_or_default())
}

fn test_device() -> (StaticSecret, String) {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = B64.encode(PublicKey::from(&secret).as_bytes());
    (secret, public)
}

fn a_claim(id: &str, statement: &str) -> serde_json::Value {
    serde_json::json!({
        "object_type": "claim",
        "id": id,
        "owner_id": "owner-1",
        "statement": statement,
        "subject_entity_ids": [],
        "status": "active",
        "supersedes": [],
        "contradicts": [],
        "reconciled_into": null,
        "commitment": null,
        "asserted_at_ms": 1_000,
        "provenance": {
            "citations": [{
                "event_id": "e1",
                "source": {
                    "connector": "text",
                    "external_id": "x1",
                    "url": null,
                    "occurred_at_ms": 1_000,
                    "ingested_at_ms": 2_000
                },
                "quote": null
            }],
            "derived_by": "test",
            "confidence": 1.0,
            "created_at_ms": 1_000
        },
        "acl": {
            "owner_id": "owner-1",
            "sources": ["text"],
            "sensitivity": "personal",
            "entity_kinds": ["project"],
            "occurred_at_ms": 1_000,
            "denied_agents": []
        }
    })
}

fn a_scope() -> serde_json::Value {
    serde_json::json!({
        "agent_id": "agent-1",
        "owner_id": "owner-1",
        "sources": ["text"],
        "entity_kinds": ["project"],
        "max_sensitivity": "confidential",
        "memory_kinds": ["episodic", "procedural"]
    })
}

fn open(secret: &StaticSecret, sealed: &serde_json::Value) -> AssembledAnswer {
    let sealed: SealedToDevice = serde_json::from_value(sealed.clone()).unwrap();
    let plaintext = open_as_device(&secret.to_bytes(), &sealed).unwrap();
    serde_json::from_slice(&plaintext).unwrap()
}

#[tokio::test]
async fn the_answer_comes_back_readable_only_by_the_asking_device() {
    let (secret, public) = test_device();
    let (status, body) = post(
        "/assemble",
        serde_json::json!({
            "owner_id": "owner-1",
            "scope": a_scope(),
            "recipient_key_b64": public,
            "recipient_key_id": "key-1",
            "question": "what did we decide about the database?",
            "candidates": [{ "node": a_claim("c1", "we decided on Neo4j"), "score": 0.9 }]
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);

    // What the host sees: structure, and a blob.
    assert_eq!(body["disclosed_ids"], serde_json::json!(["c1"]));
    assert_eq!(body["considered"], 1);
    assert_eq!(body["sealed"]["recipient_key_id"], "key-1");
    assert!(!body.to_string().contains("Neo4j"));
    assert!(!body.to_string().contains("what did we decide"));

    // What the device sees.
    let answer = open(&secret, &body["sealed"]);
    assert!(answer.answered);
    assert_eq!(answer.text, "- we decided on Neo4j (c1)");
    assert_eq!(answer.question, "what did we decide about the database?");
    assert_eq!(answer.citations[0].object_id, "c1");
}

#[tokio::test]
async fn another_device_holding_the_reply_learns_nothing_from_it() {
    // A leaked grant names a device, so the answer comes back sealed to *that*
    // device's key. It narrows a stolen token from "readable by the thief" to
    // "readable by the device it was issued for"; it does not make one safe.
    let (_, public) = test_device();
    let (thief, _) = test_device();
    let (_, body) = post(
        "/assemble",
        serde_json::json!({
            "owner_id": "owner-1",
            "scope": a_scope(),
            "recipient_key_b64": public,
            "recipient_key_id": "key-1",
            "question": "?",
            "candidates": [{ "node": a_claim("c1", "we decided on Neo4j"), "score": 0.9 }]
        }),
    )
    .await;

    let sealed: SealedToDevice = serde_json::from_value(body["sealed"].clone()).unwrap();
    assert!(open_as_device(&thief.to_bytes(), &sealed).is_err());
}

#[tokio::test]
async fn a_decline_is_sealed_too() {
    // A reply that is sometimes sealed and sometimes not tells the host which
    // queries found something. The length of the blob is the most it learns.
    let (secret, public) = test_device();
    let mut denied = a_claim("c2", "the sensitive one");
    denied["acl"]["sensitivity"] = serde_json::json!("restricted");

    let (status, body) = post(
        "/assemble",
        serde_json::json!({
            "owner_id": "owner-1",
            "scope": a_scope(),
            "recipient_key_b64": public,
            "recipient_key_id": "key-1",
            "question": "?",
            "candidates": [{ "node": denied, "score": 0.9 }]
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!body["sealed"]["ciphertext_b64"].as_str().unwrap().is_empty());
    assert_eq!(body["denials"][0]["id"], "c2");
    assert_eq!(body["denials"][0]["reason"], "too_sensitive");
    assert!(body["disclosed_ids"].as_array().unwrap().is_empty());

    let answer = open(&secret, &body["sealed"]);
    assert!(!answer.answered);
    assert!(answer.text.contains("too sensitive"));
    assert!(!answer.text.contains("the sensitive one"));
}

#[tokio::test]
async fn a_recipient_key_that_is_not_a_key_is_refused() {
    let (status, _) = post(
        "/assemble",
        serde_json::json!({
            "owner_id": "owner-1",
            "scope": a_scope(),
            "recipient_key_b64": "not base64!!",
            "recipient_key_id": "key-1",
            "question": "?",
            "candidates": []
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_assembly_carries_an_attestation_over_its_own_ciphertext() {
    // Over *this* assembly rather than over the enclave in general, so the
    // document says which blob it is about, as a commitment the device
    // recomputes before it opens anything (ADR 0026).
    let (_, public) = test_device();
    let (_, body) = post(
        "/assemble",
        serde_json::json!({
            "owner_id": "owner-1",
            "scope": a_scope(),
            "recipient_key_b64": public,
            "recipient_key_id": "key-1",
            "question": "?",
            "candidates": []
        }),
    )
    .await;
    let attestation = body["attestation"].as_str().unwrap();
    assert!(attestation.starts_with("MOCK_ATTESTATION_"), "{attestation}");
}
