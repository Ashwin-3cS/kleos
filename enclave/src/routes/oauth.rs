use crate::error::EnclaveError;
use crate::services::attestation::get_attestation;
use crate::services::identity::{compute_identity, derive_owner_id};
use crate::services::oauth::github::GitHubProvider;
use crate::services::oauth::google::GoogleProvider;
use crate::services::oauth::{OAuthProvider, TokenExchange};
use crate::services::seal;
use crate::AppState;
use axum::extract::State;
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use fastcrypto::traits::{KeyPair, ToFromBytes};
use shared::{OAuthExchangeRequest, OAuthExchangeResponse, Provider};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Exchanges an OAuth authorization code for tokens **inside the TEE**, then
/// seals the refresh token before anything is returned.
///
/// This is the same argument as `/identity/verify`: an attestation is only
/// worth something if the sensitive step happened inside the thing being
/// attested. A refresh token is standing, renewable access to a mailbox, so
/// if the host performed the exchange the "not even the operator can read
/// your data" claim would be false regardless of what is attested afterwards.
///
/// Three things leave this function, and only three: sealed ciphertext, the
/// verified account identity, and non-sensitive grant metadata. The access
/// token is used here to confirm whose account this is and is then dropped.
pub async fn exchange(
    State(state): State<Arc<AppState>>,
    Json(req): Json<OAuthExchangeRequest>,
) -> Result<Json<OAuthExchangeResponse>, EnclaveError> {
    let provider = Provider::parse(&req.provider).ok_or_else(|| {
        EnclaveError::BadRequest(format!("unknown oauth provider: {}", req.provider))
    })?;
    if req.code.trim().is_empty() {
        return Err(EnclaveError::BadRequest("code is required".into()));
    }

    let mock = state.config.is_mock();
    let client: Box<dyn OAuthProvider + Send + Sync> = match provider {
        Provider::Google => Box::new(GoogleProvider {
            tunnel_port: state.config.google_tokeninfo_port,
            mock,
            client_id: state.config.google_client_id.clone(),
            client_secret: state.config.google_client_secret.clone(),
            token_path: state.config.google_token_path.clone(),
        }),
        Provider::GitHub => Box::new(GitHubProvider {
            tunnel_port: state.config.github_api_port,
            mock,
            client_id: state.config.github_client_id.clone(),
            client_secret: state.config.github_client_secret.clone(),
            token_path: state.config.github_token_path.clone(),
        }),
    };

    let exchanged: TokenExchange = client
        .exchange_code(&req.code, &req.redirect_uri, &req.code_verifier)
        .await?;

    // Identify the account the grant belongs to using the access token we
    // just obtained, so the sealed token is bound to an owner id the enclave
    // established rather than one the host asserted.
    let signal = client.verify(&exchanged.access_token).await?;
    let owner_id = derive_owner_id(std::slice::from_ref(&signal));
    let identity = compute_identity(owner_id.clone(), vec![signal]);

    let sealed = match exchanged.refresh_token {
        Some(refresh_token) => {
            let sealed = seal::encrypt(&owner_id, refresh_token.into_bytes()).await?;
            Some(sealed)
        }
        None => None,
    };

    let now_ms = now_ms();
    let pk = state.signing_key.public();
    let mut committed = pk.as_bytes().to_vec();
    committed.extend_from_slice(owner_id.as_bytes());
    committed.extend_from_slice(provider.as_str().as_bytes());
    if let Some(s) = &sealed {
        committed.extend_from_slice(s.key_id.as_bytes());
    }
    let attestation = get_attestation(committed).await?;

    Ok(Json(OAuthExchangeResponse {
        provider: provider.as_str().to_string(),
        identity,
        sealed_refresh_token_b64: sealed.as_ref().map(|s| B64.encode(&s.ciphertext)),
        sealed_key_id: sealed.as_ref().map(|s| s.key_id.clone()),
        seal_scheme: sealed.as_ref().map(|s| s.scheme.clone()),
        scopes: exchanged.scopes,
        granted_at_ms: now_ms,
        access_token_expires_at_ms: exchanged.expires_in_secs.map(|s| now_ms + s * 1_000),
        attestation,
    }))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

#[cfg(all(test, not(feature = "nitro")))]
mod tests {
    use super::*;
    use crate::services::attestation::generate_ephemeral_key;

    fn state() -> Arc<AppState> {
        Arc::new(AppState {
            signing_key: generate_ephemeral_key(),
            config: crate::config::Config::mock(),
        })
    }

    /// The invariant, checked at its source: whatever this route returns,
    /// the plaintext refresh token is not in it.
    #[tokio::test]
    async fn sealed_response_contains_no_plaintext_refresh_token() {
        let Json(resp) = exchange(
            State(state()),
            Json(OAuthExchangeRequest {
                provider: "google".into(),
                code: "mock_code_google_alice".into(),
                redirect_uri: "http://127.0.0.1:8080/auth/callback".into(),
                code_verifier: "verifier".into(),
            }),
        )
        .await
        .unwrap();

        let serialized = serde_json::to_string(&resp).unwrap();
        assert!(!serialized.contains("mock_refresh_google_alice"));

        let ciphertext = B64
            .decode(resp.sealed_refresh_token_b64.unwrap().as_bytes())
            .unwrap();
        assert!(ciphertext.starts_with(b"MOCK_SEAL_V1:"));
        assert!(!contains(&ciphertext, b"mock_refresh_google_alice"));
        assert_eq!(resp.seal_scheme.as_deref(), Some("MOCK_SEAL_V1"));
        assert!(resp.scopes.iter().any(|s| s.contains("gmail.readonly")));
    }

    #[tokio::test]
    async fn round_trips_back_to_the_token_inside_the_enclave() {
        let Json(resp) = exchange(
            State(state()),
            Json(OAuthExchangeRequest {
                provider: "github".into(),
                code: "mock_code_github_alice".into(),
                redirect_uri: "http://127.0.0.1:8080/auth/callback".into(),
                code_verifier: "verifier".into(),
            }),
        )
        .await
        .unwrap();

        let plaintext = seal::decrypt(
            &resp.identity.owner_id,
            seal::SealEncrypted {
                ciphertext: B64
                    .decode(resp.sealed_refresh_token_b64.unwrap().as_bytes())
                    .unwrap(),
                key_id: resp.sealed_key_id.unwrap(),
                scheme: String::new(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            String::from_utf8(plaintext).unwrap(),
            "mock_refresh_github_alice"
        );
    }

    #[tokio::test]
    async fn unknown_provider_is_rejected() {
        let err = exchange(
            State(state()),
            Json(OAuthExchangeRequest {
                provider: "dropbox".into(),
                code: "x".into(),
                redirect_uri: "http://localhost".into(),
                code_verifier: "v".into(),
            }),
        )
        .await;
        assert!(matches!(err, Err(EnclaveError::BadRequest(_))));
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
