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
        config: Config {
            enclave_port: 4000,
            enclave_mode: "mock".to_string(),
            google_tokeninfo_port: 8002,
            github_api_port: 8003,
        },
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
