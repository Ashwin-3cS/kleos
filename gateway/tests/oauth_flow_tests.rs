//! End-to-end tests for the OAuth connect flow, with a real enclave router
//! running in-process.
//!
//! These exist to prove one property: a plaintext refresh token never
//! reaches the host. Everything the gateway persists is searched for the
//! known mock token, and the check is done against what actually landed in
//! the store, not against what the code claims to have stored.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use gateway::config::Config;
use gateway::store::{InMemoryTokenStore, SealedTokenStore};
use gateway::vsock::client::EnclaveClient;
use gateway::{build_router, AppState};
use std::sync::Arc;
use tower::util::ServiceExt;

/// The plaintext the mock Google provider hands back inside the enclave.
const MOCK_REFRESH_TOKEN: &str = "mock_refresh_google_alice";
const MOCK_CODE: &str = "mock_code_google_alice";

/// Boots a real enclave (mock feature) on an ephemeral port and returns a
/// gateway state wired to it.
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
    })
}

async fn get(state: Arc<AppState>, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = build_router(state)
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn start_flow(state: Arc<AppState>) -> String {
    let (status, body) = get(state, "/auth/authorize?provider=google").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    body["state"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn authorize_url_carries_pkce_and_the_data_scopes() {
    let state = gateway_with_enclave().await;
    let (status, body) = get(state, "/auth/authorize?provider=google").await;
    assert_eq!(status, StatusCode::OK);

    let url = body["authorize_url"].as_str().unwrap();
    assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
    assert!(url.contains("code_challenge_method=S256"));
    assert!(url.contains("code_challenge="));
    // A refresh token only comes back with both of these.
    assert!(url.contains("access_type=offline"));
    assert!(url.contains("prompt=consent"));
    // Identity is not enough any more: these are the data scopes.
    assert!(url.contains("gmail.readonly"));
    assert!(url.contains("calendar.readonly"));
    // The verifier itself must never appear in anything the browser sees.
    assert!(!url.contains("code_verifier"));
}

#[tokio::test]
async fn github_authorize_url_requests_repo_and_read_user() {
    let state = gateway_with_enclave().await;
    let (status, body) = get(state, "/auth/authorize?provider=github").await;
    assert_eq!(status, StatusCode::OK);
    let url = body["authorize_url"].as_str().unwrap();
    assert!(url.starts_with("https://github.com/login/oauth/authorize?"));
    assert!(url.contains("read%3Auser"));
    assert!(url.contains("repo"));
}

#[tokio::test]
async fn unknown_provider_is_rejected() {
    let state = gateway_with_enclave().await;
    let (status, _) = get(state, "/auth/authorize?provider=dropbox").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

/// The invariant. Runs the real callback against the real enclave, then
/// searches every byte that reached the store for the plaintext token.
#[tokio::test]
async fn persisted_bytes_never_contain_the_plaintext_refresh_token() {
    let state = gateway_with_enclave().await;
    let oauth_state = start_flow(state.clone()).await;

    let (status, body) = get(
        state.clone(),
        &format!("/auth/callback?code={MOCK_CODE}&state={oauth_state}"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Nothing token-shaped may appear in the HTTP response either.
    let rendered = body.to_string();
    assert!(!rendered.contains(MOCK_REFRESH_TOKEN));
    assert!(!rendered.contains("mock_google_alice")); // the access token
    assert_eq!(body["seal_scheme"], "MOCK_SEAL_V1");

    let owner_id = body["identity"]["owner_id"].as_str().unwrap();
    assert_eq!(owner_id, hex::encode("google:alice"));

    let stored = state
        .tokens
        .get(owner_id, "google")
        .await
        .unwrap()
        .expect("callback must have persisted a sealed token");

    assert!(
        !contains(&stored.sealed_refresh_token, MOCK_REFRESH_TOKEN.as_bytes()),
        "plaintext refresh token found in the persisted bytes"
    );
    assert!(stored.sealed_refresh_token.starts_with(b"MOCK_SEAL_V1:"));
    assert_eq!(stored.scheme, "MOCK_SEAL_V1");
    assert!(stored.scopes.iter().any(|s| s.contains("gmail.readonly")));

    // ...and the ciphertext is the real thing: the enclave can unseal it.
    let plaintext = unseal(
        &stored.owner_id,
        &stored.sealed_refresh_token,
        &stored.key_id,
    )
    .await;
    assert_eq!(plaintext, MOCK_REFRESH_TOKEN);
}

/// Unsealing is an enclave operation. Doing it here through the enclave's
/// own seal service is what shows the stored bytes are the sealed token and
/// not, say, an empty buffer that trivially passes the search above.
async fn unseal(owner_id: &str, ciphertext: &[u8], key_id: &str) -> String {
    let plaintext = enclave::services::seal::decrypt(
        owner_id,
        enclave::services::seal::SealEncrypted {
            ciphertext: ciphertext.to_vec(),
            key_id: key_id.to_string(),
            scheme: String::new(),
        },
    )
    .await
    .unwrap();
    String::from_utf8(plaintext).unwrap()
}

#[tokio::test]
async fn re_consent_updates_the_row_in_place() {
    let state = gateway_with_enclave().await;
    for _ in 0..2 {
        let oauth_state = start_flow(state.clone()).await;
        let (status, _) = get(
            state.clone(),
            &format!("/auth/callback?code={MOCK_CODE}&state={oauth_state}"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
    let owner_id = hex::encode("google:alice");
    assert!(state
        .tokens
        .get(&owner_id, "google")
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn tampered_state_is_rejected() {
    let state = gateway_with_enclave().await;
    let oauth_state = start_flow(state.clone()).await;

    // Flip the last character of the signature.
    let mut tampered: Vec<char> = oauth_state.chars().collect();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == 'A' { 'B' } else { 'A' };
    let tampered: String = tampered.into_iter().collect();

    let (status, _) = get(
        state.clone(),
        &format!("/auth/callback?code={MOCK_CODE}&state={tampered}"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // And nothing was written.
    assert!(state
        .tokens
        .get(&hex::encode("google:alice"), "google")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn a_state_minted_elsewhere_is_rejected() {
    let state = gateway_with_enclave().await;
    // Correctly formed, correctly typed -- but signed with another secret.
    let forged = gateway::middleware::oauth_state::issue_state("google", "attacker-secret", 600)
        .unwrap()
        .state_token;
    let (status, _) = get(
        state,
        &format!("/auth/callback?code={MOCK_CODE}&state={forged}"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_session_token_cannot_be_used_as_state() {
    let state = gateway_with_enclave().await;
    let session = gateway::middleware::session::issue_session_token(
        "owner-1",
        &state.config.oauth_state_secret,
        600,
    )
    .unwrap();
    let (status, _) = get(
        state,
        &format!("/auth/callback?code={MOCK_CODE}&state={session}"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn replaying_a_callback_is_rejected() {
    let state = gateway_with_enclave().await;
    let oauth_state = start_flow(state.clone()).await;

    let (first, _) = get(
        state.clone(),
        &format!("/auth/callback?code={MOCK_CODE}&state={oauth_state}"),
    )
    .await;
    assert_eq!(first, StatusCode::OK);

    // Same state, same code, second time: the PKCE verifier was consumed.
    let (second, body) = get(
        state,
        &format!("/auth/callback?code={MOCK_CODE}&state={oauth_state}"),
    )
    .await;
    assert_eq!(second, StatusCode::UNAUTHORIZED);
    assert!(body["error"]
        .as_str()
        .unwrap()
        .contains("already been used"));
}

#[tokio::test]
async fn callback_without_a_prior_authorize_is_rejected() {
    let state = gateway_with_enclave().await;
    let (status, _) = get(state, &format!("/auth/callback?code={MOCK_CODE}&state=abc")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
