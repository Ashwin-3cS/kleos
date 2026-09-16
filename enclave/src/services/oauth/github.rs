use super::OAuthProvider;
use crate::error::EnclaveError;
use crate::services::http::{tunnel_client, tunnel_url};
use async_trait::async_trait;
use serde::Deserialize;
use shared::OAuthSignal;

pub struct GitHubProvider {
    pub tunnel_port: u16,
    pub mock: bool,
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
        let url = tunnel_url(self.tunnel_port, "/user");
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
}
