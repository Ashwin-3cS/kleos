use crate::error::GatewayError;
use shared::{IdentityVerifyRequest, IdentityVerifyResponse, SealEncryptRequest, SealEncryptResponse};
use std::time::Duration;

/// Plain TCP/HTTP client the gateway uses to reach the enclave.
///
/// There is no Rust-level VSOCK crate in this project. In `nitro` mode,
/// scripts/parent_forwarder.sh runs
/// `sudo socat TCP-LISTEN:4000,reuseaddr,fork VSOCK:$CID:4000 &`
/// on the host, so `localhost:4000` here is transparently bridged over
/// VSOCK into the enclave. In local mock mode the enclave just binds
/// `127.0.0.1:4000` directly and this client talks to it with no bridge at
/// all. Either way this struct only ever speaks plain HTTP.
pub struct EnclaveClient {
    http: reqwest::Client,
    base_url: String,
}

impl EnclaveClient {
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("failed to build enclave HTTP client"),
            base_url: format!("http://{host}:{port}"),
        }
    }

    pub async fn health(&self) -> Result<serde_json::Value, GatewayError> {
        let resp = self
            .http
            .get(format!("{}/health", self.base_url))
            .send()
            .await
            .map_err(|e| GatewayError::EnclaveUnreachable(e.to_string()))?;
        resp.json()
            .await
            .map_err(|e| GatewayError::EnclaveUnreachable(e.to_string()))
    }

    pub async fn verify_identity(
        &self,
        req: &IdentityVerifyRequest,
    ) -> Result<IdentityVerifyResponse, GatewayError> {
        let resp = self
            .http
            .post(format!("{}/identity/verify", self.base_url))
            .json(req)
            .send()
            .await
            .map_err(|e| GatewayError::EnclaveUnreachable(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(GatewayError::EnclaveUnreachable(format!(
                "enclave returned {status}: {body}"
            )));
        }

        resp.json()
            .await
            .map_err(|e| GatewayError::EnclaveUnreachable(e.to_string()))
    }

    pub async fn seal_encrypt(
        &self,
        req: &SealEncryptRequest,
    ) -> Result<SealEncryptResponse, GatewayError> {
        self.post_json("/seal/encrypt", req).await
    }

    async fn post_json<Req: serde::Serialize, Resp: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        req: &Req,
    ) -> Result<Resp, GatewayError> {
        let resp = self
            .http
            .post(format!("{}{}", self.base_url, path))
            .json(req)
            .send()
            .await
            .map_err(|e| GatewayError::EnclaveUnreachable(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(GatewayError::EnclaveUnreachable(format!(
                "enclave returned {status}: {body}"
            )));
        }

        resp.json()
            .await
            .map_err(|e| GatewayError::EnclaveUnreachable(e.to_string()))
    }
}
