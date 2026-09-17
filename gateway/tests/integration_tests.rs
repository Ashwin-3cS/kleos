use axum::body::Body;
use axum::http::{Request, StatusCode};
use gateway::config::Config;
use gateway::vsock::client::EnclaveClient;
use gateway::{build_router, AppState};
use std::sync::Arc;
use tower::util::ServiceExt;

fn test_state() -> Arc<AppState> {
    let config = Config::mock();
    let enclave = EnclaveClient::new(&config.enclave_host, config.enclave_port);
    Arc::new(AppState {
        config,
        enclave,
        pending_auth: Default::default(),
        tokens: Box::new(gateway::store::InMemoryTokenStore::default()),
    })
}

#[tokio::test]
async fn health_returns_ok_even_if_enclave_unreachable() {
    let router = build_router(test_state());
    let response = router
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// A callback with no `state` at all is a malformed request, not an
/// unauthorized one -- axum rejects it at the extractor.
#[tokio::test]
async fn auth_callback_requires_a_state_parameter() {
    let router = build_router(test_state());
    let response = router
        .oneshot(
            Request::builder()
                .uri("/auth/callback?code=abc")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
