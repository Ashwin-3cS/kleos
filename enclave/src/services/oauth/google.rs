use super::{OAuthProvider, TokenEndpointResponse, TokenExchange};
use crate::error::EnclaveError;
use crate::services::http::{tunnel_client, tunnel_url};
use async_trait::async_trait;
use serde::Deserialize;
use shared::OAuthSignal;

pub struct GoogleProvider {
    pub tunnel_port: u16,
    pub mock: bool,
    /// Only the enclave holds the client secret. The gateway needs the
    /// client id to build an authorize URL, but a host that also held the
    /// secret could exchange codes itself and keep the refresh token.
    pub client_id: String,
    pub client_secret: String,
    pub token_path: String,
}

#[derive(Debug, Deserialize)]
struct TokenInfo {
    sub: String,
    email: String,
}

#[async_trait]
impl OAuthProvider for GoogleProvider {
    async fn verify(&self, token: &str) -> Result<OAuthSignal, EnclaveError> {
        // Mock mode has no VSOCK tunnel bridged to Google, so a real call
        // would just hang/fail. Instead we deterministically derive a fake
        // identity from the token so the whole request path (gateway ->
        // enclave -> trust tier -> attestation) is exercisable via CLI
        // without EC2 or a real Google token.
        if self.mock {
            if let Some(fake_sub) = token.strip_prefix("mock_google_") {
                return Ok(OAuthSignal::Google {
                    subject: fake_sub.to_string(),
                    email: format!("{fake_sub}@mock.local"),
                });
            }
            return Err(EnclaveError::BadRequest(
                "mock mode expects a token of the form mock_google_<subject>".into(),
            ));
        }

        let client = tunnel_client()?;
        let url = tunnel_url(self.tunnel_port, "/tokeninfo");
        let resp = client
            .get(url)
            .query(&[("access_token", token)])
            .send()
            .await
            .map_err(|e| EnclaveError::Upstream(format!("google tokeninfo call failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(EnclaveError::Upstream(format!(
                "google tokeninfo rejected token: {}",
                resp.status()
            )));
        }

        let info: TokenInfo = resp
            .json()
            .await
            .map_err(|e| EnclaveError::Upstream(format!("bad google tokeninfo body: {e}")))?;

        Ok(OAuthSignal::Google {
            subject: info.sub,
            email: info.email,
        })
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<TokenExchange, EnclaveError> {
        // Same rationale as verify(): no tunnel exists in mock mode. A mock
        // code yields a mock access token in the `mock_google_<subject>`
        // form, so the verify() step after the exchange is literally the
        // same code path in both modes.
        if self.mock {
            let subject = code.strip_prefix("mock_code_google_").ok_or_else(|| {
                EnclaveError::BadRequest(
                    "mock mode expects a code of the form mock_code_google_<subject>".into(),
                )
            })?;
            return Ok(TokenExchange {
                access_token: format!("mock_google_{subject}"),
                refresh_token: Some(format!("mock_refresh_google_{subject}")),
                expires_in_secs: Some(3600),
                scopes: shared::Provider::Google
                    .scopes()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            });
        }

        if self.client_secret.is_empty() {
            return Err(EnclaveError::Internal(
                "GOOGLE_CLIENT_SECRET is not set inside the enclave; code exchange cannot happen anywhere else"
                    .into(),
            ));
        }

        let client = tunnel_client()?;
        let url = tunnel_url(self.tunnel_port, &self.token_path);
        let resp = client
            .post(url)
            .form(&[
                ("code", code),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("redirect_uri", redirect_uri),
                ("grant_type", "authorization_code"),
                ("code_verifier", code_verifier),
            ])
            .send()
            .await
            .map_err(|e| EnclaveError::Upstream(format!("google token exchange failed: {e}")))?;

        if !resp.status().is_success() {
            // A failed token response can echo the submitted code back;
            // surface only the status so it cannot reach the host's logs.
            return Err(EnclaveError::Upstream(format!(
                "google rejected the authorization code: {}",
                resp.status()
            )));
        }

        let body: TokenEndpointResponse = resp
            .json()
            .await
            .map_err(|e| EnclaveError::Upstream(format!("bad google token body: {e}")))?;
        Ok(body.into())
    }
}
