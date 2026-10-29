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
        device_keys: Box::new(gateway::store::device_keys::InMemoryDeviceKeyStore::default()),
        local_nonces: Default::default(),
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

/// The gateway listens on loopback unless something says otherwise.
///
/// A test on a default rather than on behaviour, which is usually a smell --
/// but this default is a security boundary. It was `0.0.0.0` hard-coded in
/// `main.rs`, so on a laptop in mock mode the whole gateway sat on the local
/// network, and mock mode accepts `mock_google_<subject>` as a sign-in: a
/// stranger on the same wifi could mint an owner session, register a device key
/// under it, and sign themselves a grant. Nothing else in the suite would have
/// noticed the day someone changed it back.
///
/// Both halves in one test on purpose. `set_var` is process-global and the
/// test harness runs threads in parallel, so two tests touching `GATEWAY_BIND`
/// race and fail each other intermittently -- which is worse than a long test.
#[test]
fn the_gateway_binds_loopback_unless_told_otherwise() {
    std::env::remove_var("GATEWAY_BIND");
    assert_eq!(
        gateway::config::Config::from_env().expect("config").gateway_bind,
        "127.0.0.1"
    );
    assert_eq!(gateway::config::Config::mock().gateway_bind, "127.0.0.1");

    std::env::set_var("GATEWAY_BIND", "0.0.0.0");
    let widened = gateway::config::Config::from_env().expect("config");
    std::env::remove_var("GATEWAY_BIND");
    assert_eq!(widened.gateway_bind, "0.0.0.0");
}
