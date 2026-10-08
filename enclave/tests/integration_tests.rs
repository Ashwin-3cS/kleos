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
