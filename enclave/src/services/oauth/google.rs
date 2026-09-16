use super::OAuthProvider;
use crate::error::EnclaveError;
use crate::services::http::{tunnel_client, tunnel_url};
use async_trait::async_trait;
use serde::Deserialize;
use shared::OAuthSignal;

pub struct GoogleProvider {
    pub tunnel_port: u16,
    pub mock: bool,
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
}
