use crate::keys::SigningKeys;
use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub gateway_port: u16,
    pub enclave_host: String,
    pub enclave_port: u16,
    /// Per-purpose signing keys, derived from one root secret so that no two
    /// of them are ever accidentally equal. See `keys.rs` and ADR 0004.
    pub keys: SigningKeys,
    pub session_ttl_secs: usize,
    pub oauth_state_ttl_secs: u64,
    /// Client *ids* only. The matching secrets live in the enclave's
    /// environment and deliberately not here -- see enclave/src/config.rs.
    pub google_client_id: String,
    pub google_redirect_uri: String,
    pub github_client_id: String,
    pub github_redirect_uri: String,
    /// Postgres URL for the sealed refresh-token store. Unset means the
    /// in-memory store, which is the local mock-mode default.
    pub sealed_token_store_url: Option<String>,
}

impl Config {
    /// Reads configuration from the environment.
    ///
    /// Fallible only because of the signing keys: a gateway that boots with the
    /// public development secret in `nitro` mode looks like it is working,
    /// which is worse than one that refuses to boot.
    pub fn from_env() -> anyhow::Result<Self> {
        let nitro = env::var("ENCLAVE_MODE").map(|m| m == "nitro").unwrap_or(false);
        Ok(Self {
            keys: SigningKeys::from_env(nitro)?,
            gateway_port: env::var("GATEWAY_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8080),
            // In `nitro` mode this is still `127.0.0.1` -- parent_forwarder.sh
            // bridges that local port out to the enclave's VSOCK CID (see
            // scripts/parent_forwarder.sh's port4000-bridge block), so the
            // gateway itself never needs to know the enclave's CID.
            enclave_host: env::var("ENCLAVE_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            enclave_port: env::var("ENCLAVE_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4000),
            session_ttl_secs: env::var("SESSION_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            oauth_state_ttl_secs: env::var("OAUTH_STATE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(600),
            google_client_id: env::var("GOOGLE_CLIENT_ID").unwrap_or_default(),
            google_redirect_uri: env::var("GOOGLE_REDIRECT_URI")
                .unwrap_or_else(|_| "http://127.0.0.1:8080/auth/callback".to_string()),
            github_client_id: env::var("GITHUB_CLIENT_ID").unwrap_or_default(),
            github_redirect_uri: env::var("GITHUB_REDIRECT_URI")
                .unwrap_or_else(|_| "http://127.0.0.1:8080/auth/callback".to_string()),
            sealed_token_store_url: env::var("SEALED_TOKEN_STORE_URL")
                .ok()
                .filter(|v| !v.trim().is_empty()),
        })
    }

    /// Mock/dev defaults; also what the test suites build on.
    pub fn mock() -> Self {
        Self {
            gateway_port: 8080,
            enclave_host: "127.0.0.1".to_string(),
            enclave_port: 4000,
            keys: SigningKeys::mock(),
            session_ttl_secs: 3600,
            oauth_state_ttl_secs: 600,
            google_client_id: "mock-google-client-id".to_string(),
            google_redirect_uri: "http://127.0.0.1:8080/auth/callback".to_string(),
            github_client_id: "mock-github-client-id".to_string(),
            github_redirect_uri: "http://127.0.0.1:8080/auth/callback".to_string(),
            sealed_token_store_url: None,
        }
    }

    pub fn client_id(&self, provider: shared::Provider) -> &str {
        match provider {
            shared::Provider::Google => &self.google_client_id,
            shared::Provider::GitHub => &self.github_client_id,
        }
    }

    pub fn redirect_uri(&self, provider: shared::Provider) -> &str {
        match provider {
            shared::Provider::Google => &self.google_redirect_uri,
            shared::Provider::GitHub => &self.github_redirect_uri,
        }
    }
}
