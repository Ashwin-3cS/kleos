//! The permission routes, through the HTTP surface (ADR 0028).
//!
//! Through HTTP rather than by calling `permissions::evaluate` directly,
//! because `evaluate` has its own tests in `shared` and what is new here is the
//! route: that it reads its own clock, that it refuses a request disagreeing
//! with its own scope, and that every verdict comes back carrying the id it is
//! about. A positional list is one an intermediary can reorder or truncate with
//! the gap reading as "allowed", so the echo is the contract.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use enclave::config::Config;
use enclave::services::attestation::generate_ephemeral_key;
use enclave::{build_router, AppState};
use serde_json::json;
use std::sync::Arc;
use tower::util::ServiceExt;

fn test_state() -> Arc<AppState> {
    Arc::new(AppState {
        signing_key: generate_ephemeral_key(),
        config: Config::mock(),
    })
}

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

const OWNER: &str = "owner-permission-routes";

fn scope() -> serde_json::Value {
    json!({
        "agent_id": "agent-under-test",
        "owner_id": OWNER,
        "sources": ["mock"],
        "entity_kinds": ["project"],
        "max_sensitivity": "confidential",
        "may_write": true,
        "write_sources": ["agent"],
        "memory_kinds": ["episodic"],
    })
}

fn acl(overrides: serde_json::Value) -> serde_json::Value {
    let mut base = json!({
        "owner_id": OWNER,
        "sources": ["mock"],
        "sensitivity": "personal",
        "entity_kinds": ["project"],
        "occurred_at_ms": 1_700_000_000_000u64,
    });
    for (key, value) in overrides.as_object().unwrap() {
        base[key] = value.clone();
    }
    base
}

#[tokio::test]
async fn it_returns_one_verdict_per_object_carrying_the_id() {
    let (status, body) = post(
        "/permissions/evaluate",
        json!({
            "owner_id": OWNER,
            "scope": scope(),
            "objects": [
                {"id": "allowed-one", "acl": acl(json!({}))},
                {"id": "wrong-source", "acl": acl(json!({"sources": ["github"]}))},
                {"id": "too-sensitive", "acl": acl(json!({"sensitivity": "restricted"}))},
            ],
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let verdicts = body["verdicts"].as_array().unwrap();
    assert_eq!(verdicts.len(), 3);
    assert_eq!(verdicts[0]["id"], "allowed-one");
    assert_eq!(verdicts[0]["allowed"], true);
    assert!(verdicts[0]["reason"].is_null());
    assert_eq!(verdicts[1]["id"], "wrong-source");
    assert_eq!(verdicts[1]["allowed"], false);
    assert_eq!(verdicts[1]["reason"], "source_not_in_scope");
    assert_eq!(verdicts[2]["id"], "too-sensitive");
    assert_eq!(verdicts[2]["allowed"], false);
    assert_eq!(verdicts[2]["reason"], "too_sensitive");
}

#[tokio::test]
async fn the_clock_is_read_in_here_and_reported() {
    // The request has no `now_ms` field to send, which is the point: a host that
    // supplied the clock could rewind it to resurrect an expired grant, and
    // nothing downstream would look wrong because the verdict would be correct
    // for the time it was given.
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let (status, body) = post(
        "/permissions/evaluate",
        json!({
            "owner_id": OWNER,
            "scope": scope(),
            "objects": [{"id": "a", "acl": acl(json!({}))}],
            // Sent anyway, and ignored: there is no field for it, so serde
            // drops it rather than letting it reach `evaluate`.
            "now_ms": 1u64,
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    let reported = body["now_ms"].as_u64().unwrap();
    assert!(reported >= before, "the reported clock is the enclave's own");
    assert!(reported > 1, "a host-supplied clock did not reach the check");
}

#[tokio::test]
async fn an_expired_grant_is_denied_against_the_enclaves_clock() {
    let mut expired = scope();
    expired["expires_at_ms"] = json!(1_000_000_000_000u64);
    let (status, body) = post(
        "/permissions/evaluate",
        json!({
            "owner_id": OWNER,
            "scope": expired,
            "objects": [{"id": "a", "acl": acl(json!({}))}],
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["verdicts"][0]["allowed"], false);
    assert_eq!(body["verdicts"][0]["reason"], "grant_expired");
}

#[tokio::test]
async fn an_owner_that_disagrees_with_the_scope_is_a_bad_request() {
    // `evaluate` would deny every object on an owner mismatch, which is the
    // right answer and a confusing one: forty identical denials describe a
    // caller bug badly. Named here instead.
    let (status, _) = post(
        "/permissions/evaluate",
        json!({
            "owner_id": "somebody-else",
            "scope": scope(),
            "objects": [{"id": "a", "acl": acl(json!({}))}],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_empty_batch_is_an_empty_answer_and_not_an_error() {
    let (status, body) = post(
        "/permissions/evaluate",
        json!({"owner_id": OWNER, "scope": scope(), "objects": []}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["verdicts"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn an_object_belonging_to_another_owner_is_denied() {
    let (status, body) = post(
        "/permissions/evaluate",
        json!({
            "owner_id": OWNER,
            "scope": scope(),
            "objects": [{"id": "theirs", "acl": acl(json!({"owner_id": "somebody-else"}))}],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["verdicts"][0]["allowed"], false);
    assert_eq!(body["verdicts"][0]["reason"], "wrong_owner");
}

// -- the write gate ----------------------------------------------------

fn intent(overrides: serde_json::Value) -> serde_json::Value {
    let mut base = json!({
        "owner_id": OWNER,
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
async fn a_permitted_write_is_allowed() {
    let (status, body) = post(
        "/permissions/evaluate-write",
        json!({"owner_id": OWNER, "scope": scope(), "intent": intent(json!({}))}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["allowed"], true);
    assert!(body["reason"].is_null());
    assert!(body["now_ms"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn a_grant_that_may_not_write_is_refused_in_here() {
    let mut read_only = scope();
    read_only["may_write"] = json!(false);
    let (status, body) = post(
        "/permissions/evaluate-write",
        json!({"owner_id": OWNER, "scope": read_only, "intent": intent(json!({}))}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["allowed"], false);
    assert_eq!(body["reason"], "write_not_permitted");
}

#[tokio::test]
async fn a_memory_kind_outside_the_grant_is_refused() {
    let (status, body) = post(
        "/permissions/evaluate-write",
        json!({
            "owner_id": OWNER,
            "scope": scope(),
            "intent": intent(json!({"memory_kind": "procedural"})),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["allowed"], false);
}
