use axum::body::Body;
use axum::http::{Request, StatusCode};
use gateway::config::Config;
use gateway::vsock::client::EnclaveClient;
use gateway::{build_router, AppState};
use std::sync::Arc;
use tower::util::ServiceExt;

fn test_state() -> Arc<AppState> {
    let config = Config {
        gateway_port: 8080,
        enclave_host: "127.0.0.1".to_string(),
        enclave_port: 4000,
        session_jwt_secret: "test-secret".to_string(),
    };
    let enclave = EnclaveClient::new(&config.enclave_host, config.enclave_port);
    Arc::new(AppState { config, enclave })
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

#[tokio::test]
async fn auth_callback_is_not_implemented_in_phase_1() {
    let router = build_router(test_state());
    let response = router
        .oneshot(
            Request::builder()
                .uri("/auth/callback?code=abc&provider=google")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
