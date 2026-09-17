use super::{OAuthProvider, TokenEndpointResponse, TokenExchange};
use crate::error::EnclaveError;
use crate::services::http::{tunnel_client, tunnel_url, GITHUB_API, GITHUB_TOKEN};
use async_trait::async_trait;
use serde::Deserialize;
use shared::OAuthSignal;

pub struct GitHubProvider {
    pub mock: bool,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: u64,
    login: String,
}

#[async_trait]
impl OAuthProvider for GitHubProvider {
    async fn verify(&self, token: &str) -> Result<OAuthSignal, EnclaveError> {
        // Same rationale as GoogleProvider::verify: no tunnel exists to
        // GitHub in mock mode, so we short-circuit deterministically.
        if self.mock {
            if let Some(fake_login) = token.strip_prefix("mock_github_") {
                return Ok(OAuthSignal::GitHub {
                    subject: format!("mock-{fake_login}"),
                    login: fake_login.to_string(),
                });
            }
            return Err(EnclaveError::BadRequest(
                "mock mode expects a token of the form mock_github_<login>".into(),
            ));
        }

        let client = tunnel_client()?;
        let url = tunnel_url(&GITHUB_API, "/user");
        let resp = client
            .get(url)
            .bearer_auth(token)
            .header("User-Agent", "memorai-enclave")
            .send()
            .await
            .map_err(|e| EnclaveError::Upstream(format!("github /user call failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(EnclaveError::Upstream(format!(
                "github rejected token: {}",
                resp.status()
            )));
        }

        let user: GitHubUser = resp
            .json()
            .await
            .map_err(|e| EnclaveError::Upstream(format!("bad github /user body: {e}")))?;

        Ok(OAuthSignal::GitHub {
            subject: user.id.to_string(),
            login: user.login,
        })
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<TokenExchange, EnclaveError> {
        if self.mock {
            let login = code.strip_prefix("mock_code_github_").ok_or_else(|| {
                EnclaveError::BadRequest(
                    "mock mode expects a code of the form mock_code_github_<login>".into(),
                )
            })?;
            return Ok(TokenExchange {
                access_token: format!("mock_github_{login}"),
                refresh_token: Some(format!("mock_refresh_github_{login}")),
                expires_in_secs: None,
                scopes: shared::Provider::GitHub
                    .scopes()
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            });
        }

        if self.client_secret.is_empty() {
            return Err(EnclaveError::Internal(
                "GITHUB_CLIENT_SECRET is not set inside the enclave; code exchange cannot happen anywhere else"
                    .into(),
            ));
        }

        let client = tunnel_client()?;
        let url = tunnel_url(&GITHUB_TOKEN, "/login/oauth/access_token");
        let resp = client
            .post(url)
            // GitHub's token endpoint returns form-encoded output unless
            // asked for JSON.
            .header("Accept", "application/json")
            .header("User-Agent", "memorai-enclave")
            .form(&[
                ("code", code),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("redirect_uri", redirect_uri),
                ("code_verifier", code_verifier),
            ])
            .send()
            .await
            .map_err(|e| EnclaveError::Upstream(format!("github token exchange failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(EnclaveError::Upstream(format!(
                "github rejected the authorization code: {}",
                resp.status()
            )));
        }

        let body: TokenEndpointResponse = resp
            .json()
            .await
            .map_err(|e| EnclaveError::Upstream(format!("bad github token body: {e}")))?;
        Ok(body.into())
    }
}
