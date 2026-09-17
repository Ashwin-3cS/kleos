pub mod github;
pub mod google;

use crate::error::EnclaveError;
use async_trait::async_trait;
use shared::OAuthSignal;

/// A provider that turns a raw OAuth token into a verified `OAuthSignal`.
/// Implementations must perform the actual verification call themselves
/// (against the provider's API, through a VSOCK-bridged tunnel) -- the
/// gateway is never trusted to have done this, since only a verification
/// that happens inside the enclave is covered by the NSM attestation.
#[async_trait]
pub trait OAuthProvider {
    async fn verify(&self, token: &str) -> Result<OAuthSignal, EnclaveError>;

    /// Exchanges an authorization code for tokens by calling the provider's
    /// token endpoint. Same rule as `verify`: this must happen in here, not
    /// on the gateway, because the refresh token it yields is standing
    /// access to the user's data and must never exist in plaintext outside
    /// the TEE.
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<TokenExchange, EnclaveError>;
}

/// Raw result of a code exchange. This struct only ever exists inside the
/// enclave; `refresh_token` is sealed before anything crosses back out, and
/// `access_token` is dropped entirely.
pub struct TokenExchange {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in_secs: Option<u64>,
    pub scopes: Vec<String>,
}

/// Provider-agnostic shape of an OAuth2 token response. GitHub returns the
/// same field names as Google when asked for JSON.
// No Debug derive: this struct holds live token material.
#[derive(serde::Deserialize)]
pub struct TokenEndpointResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub scope: Option<String>,
}

impl From<TokenEndpointResponse> for TokenExchange {
    fn from(r: TokenEndpointResponse) -> Self {
        TokenExchange {
            access_token: r.access_token,
            refresh_token: r.refresh_token,
            expires_in_secs: r.expires_in,
            scopes: r
                .scope
                .unwrap_or_default()
                .split([' ', ','])
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect(),
        }
    }
}
