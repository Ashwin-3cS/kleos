use crate::error::GatewayError;
use crate::middleware::oauth_state::{issue_state, now_secs, validate_state, PendingAuth};
use crate::store::SealedOAuthToken;
use crate::AppState;
use axum::extract::{Query, State};
use axum::Json;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use shared::{OAuthExchangeRequest, Provider};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub provider: String,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    pub provider: String,
    pub authorize_url: String,
    /// Echoed so a CLI-driven flow can be scripted; the browser gets it
    /// inside `authorize_url` anyway.
    pub state: String,
    pub scopes: Vec<String>,
    pub expires_at_ms: u64,
}

/// Builds the provider's consent URL. Returns JSON rather than a 302 because
/// there is no web app yet and this has to be drivable from curl; a UI can
/// redirect to `authorize_url` unchanged.
///
/// The PKCE verifier generated here stays on the gateway. Only its S256
/// challenge goes to the provider and only an opaque state id goes into the
/// `state` token, so observing the redirect does not let anyone complete the
/// flow.
pub async fn authorize(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Json<AuthorizeResponse>, GatewayError> {
    let provider = Provider::parse(&query.provider).ok_or_else(|| {
        GatewayError::BadRequest(format!(
            "unknown provider '{}'; expected google or github",
            query.provider
        ))
    })?;

    let client_id = state.config.client_id(provider);
    if client_id.is_empty() {
        return Err(GatewayError::BadRequest(format!(
            "{}_CLIENT_ID is not configured",
            provider.as_str().to_uppercase()
        )));
    }
    let redirect_uri = state.config.redirect_uri(provider).to_string();

    let issued = issue_state(
        provider.as_str(),
        &state.config.oauth_state_secret,
        state.config.oauth_state_ttl_secs,
    )?;
    let expires_at_secs = now_secs() + state.config.oauth_state_ttl_secs;

    state.pending_auth.insert(
        issued.state_id.clone(),
        PendingAuth {
            provider: provider.as_str().to_string(),
            code_verifier: issued.code_verifier,
            redirect_uri: redirect_uri.clone(),
            expires_at_secs,
        },
    );

    let mut params = vec![
        ("client_id", client_id.to_string()),
        ("redirect_uri", redirect_uri),
        ("response_type", "code".to_string()),
        ("scope", provider.scope_param()),
        ("state", issued.state_token.clone()),
        ("code_challenge", issued.code_challenge),
        ("code_challenge_method", "S256".to_string()),
    ];
    if provider == Provider::Google {
        // Without both of these Google returns no refresh token on a repeat
        // consent, and obtaining one is the entire point of this flow.
        params.push(("access_type", "offline".to_string()));
        params.push(("prompt", "consent".to_string()));
    }

    Ok(Json(AuthorizeResponse {
        provider: provider.as_str().to_string(),
        authorize_url: format!("{}?{}", provider.authorize_endpoint(), urlencode(&params)),
        state: issued.state_token,
        scopes: provider.scopes().iter().map(|s| s.to_string()).collect(),
        expires_at_ms: expires_at_secs * 1_000,
    }))
}

#[derive(Deserialize)]
pub struct AuthCallbackQuery {
    pub code: String,
    pub state: String,
}

// The authorization code is a single-use credential for obtaining a refresh
// token. Deriving Debug would put it into any tracing of this extractor.
impl std::fmt::Debug for AuthCallbackQuery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthCallbackQuery")
            .field("code", &"<redacted>")
            .field("state", &self.state)
            .finish()
    }
}

/// What the callback returns. No token material of any kind appears here:
/// the refresh token is ciphertext in the store, and the access token was
/// dropped inside the enclave.
#[derive(Debug, Serialize)]
pub struct AuthCallbackResponse {
    pub provider: String,
    pub session_token: String,
    pub identity: shared::OwnerIdentity,
    pub scopes: Vec<String>,
    pub granted_at_ms: u64,
    pub sealed_key_id: Option<String>,
    pub seal_scheme: Option<String>,
    pub sealed_token_bytes: usize,
    pub attestation: String,
}

/// The provider's redirect lands here.
///
/// Order matters: the state is validated and **consumed** before the code
/// goes anywhere, so a replayed callback is rejected even though its code
/// might still be live. Then the code is forwarded to the enclave, which
/// performs the exchange and hands back only ciphertext plus metadata. The
/// gateway persists that ciphertext and issues the owner session.
///
/// At no point in this function does a plaintext refresh token exist.
pub async fn callback(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuthCallbackQuery>,
) -> Result<Json<AuthCallbackResponse>, GatewayError> {
    let claims = validate_state(&query.state, &state.config.oauth_state_secret)?;
    let pending = state.pending_auth.take(&claims.state_id).ok_or_else(|| {
        GatewayError::Unauthorized(
            "oauth state is unknown, expired, or has already been used".into(),
        )
    })?;
    if pending.provider != claims.provider {
        return Err(GatewayError::Unauthorized(
            "oauth state provider mismatch".into(),
        ));
    }
    let provider = Provider::parse(&claims.provider)
        .ok_or_else(|| GatewayError::Unauthorized("oauth state names no known provider".into()))?;

    let exchanged = state
        .enclave
        .exchange_oauth_code(&OAuthExchangeRequest {
            provider: provider.as_str().to_string(),
            code: query.code,
            redirect_uri: pending.redirect_uri,
            code_verifier: pending.code_verifier,
        })
        .await?;

    let owner_id = exchanged.identity.owner_id.clone();
    let mut sealed_token_bytes = 0usize;
    if let Some(b64) = &exchanged.sealed_refresh_token_b64 {
        let ciphertext = B64
            .decode(b64.as_bytes())
            .map_err(|e| GatewayError::Internal(format!("enclave returned bad base64: {e}")))?;
        sealed_token_bytes = ciphertext.len();
        state
            .tokens
            .upsert(&SealedOAuthToken {
                owner_id: owner_id.clone(),
                provider: provider.as_str().to_string(),
                sealed_refresh_token: ciphertext,
                key_id: exchanged.sealed_key_id.clone().unwrap_or_default(),
                scheme: exchanged.seal_scheme.clone().unwrap_or_default(),
                scopes: exchanged.scopes.clone(),
                granted_at_ms: exchanged.granted_at_ms as i64,
                expires_at_ms: exchanged.access_token_expires_at_ms.map(|v| v as i64),
            })
            .await?;
    } else {
        tracing::warn!(
            provider = provider.as_str(),
            "provider issued no refresh token; this source cannot be backfilled later"
        );
    }

    let session_token = crate::middleware::session::issue_session_token(
        &owner_id,
        &state.config.session_jwt_secret,
        state.config.session_ttl_secs,
    )
    .map_err(|e| GatewayError::Internal(format!("failed to issue session: {e}")))?;

    Ok(Json(AuthCallbackResponse {
        provider: provider.as_str().to_string(),
        session_token,
        identity: exchanged.identity,
        scopes: exchanged.scopes,
        granted_at_ms: exchanged.granted_at_ms,
        sealed_key_id: exchanged.sealed_key_id,
        seal_scheme: exchanged.seal_scheme,
        sealed_token_bytes,
        attestation: exchanged.attestation,
    }))
}

/// Session bootstrap: verifies an identity through the enclave exactly as
/// `/identity/verify` does, then issues a session JWT bound to the owner id
/// the enclave attested. The orchestrator uses this to obtain the session
/// it needs for the seal and grant routes.
#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub session_token: String,
    pub identity: shared::OwnerIdentity,
    pub attestation: String,
}

pub async fn session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<shared::IdentityVerifyRequest>,
) -> Result<Json<SessionResponse>, GatewayError> {
    let verified = state.enclave.verify_identity(&req).await?;
    let session_token = crate::middleware::session::issue_session_token(
        &verified.identity.owner_id,
        &state.config.session_jwt_secret,
        state.config.session_ttl_secs,
    )
    .map_err(|e| GatewayError::Internal(format!("failed to issue session: {e}")))?;

    Ok(Json(SessionResponse {
        session_token,
        identity: verified.identity,
        attestation: verified.attestation,
    }))
}

/// Minimal `application/x-www-form-urlencoded` serializer -- pulling in
/// `serde_urlencoded` for eight known key/value pairs is not worth a
/// dependency.
fn urlencode(params: &[(&str, String)]) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
