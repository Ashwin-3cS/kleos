use std::env;

/// Enclave runtime configuration, sourced from environment variables (see
/// .env.example at the workspace root). In `nitro` mode these are injected
/// via the enclave's run.sh from the .env file baked into the EIF image; in
/// `mock` mode they come from a local .env loaded by dotenvy.
#[derive(Clone)]
pub struct Config {
    pub enclave_port: u16,
    pub enclave_mode: String,
    pub google_tokeninfo_port: u16,
    pub github_api_port: u16,
    /// OAuth client credentials. The *secrets* live only here, never in the
    /// gateway's environment: holding a client secret is what lets a party
    /// exchange an authorization code, and the whole point of doing the
    /// exchange inside the TEE is that the host cannot.
    pub google_client_id: String,
    pub google_client_secret: String,
    pub github_client_id: String,
    pub github_client_secret: String,
    /// Paths on the provider tunnels (8002/8003) that serve the token
    /// endpoints. Configurable because the host-side socat target decides
    /// which provider host those ports actually reach.
    pub google_token_path: String,
    pub github_token_path: String,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("enclave_port", &self.enclave_port)
            .field("enclave_mode", &self.enclave_mode)
            .field("google_tokeninfo_port", &self.google_tokeninfo_port)
            .field("github_api_port", &self.github_api_port)
            .field("google_client_id", &self.google_client_id)
            .field("google_client_secret", &"<redacted>")
            .field("github_client_id", &self.github_client_id)
            .field("github_client_secret", &"<redacted>")
            .field("google_token_path", &self.google_token_path)
            .field("github_token_path", &self.github_token_path)
            .finish()
    }
}

impl Config {
    pub fn from_env() -> Self {
        Self {
            enclave_port: env::var("ENCLAVE_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4000),
            enclave_mode: env::var("ENCLAVE_MODE").unwrap_or_else(|_| "mock".to_string()),
            google_tokeninfo_port: env::var("GOOGLE_OAUTH_VSOCK_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8002),
            github_api_port: env::var("GITHUB_API_VSOCK_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8003),
            google_client_id: env::var("GOOGLE_CLIENT_ID").unwrap_or_default(),
            google_client_secret: env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default(),
            github_client_id: env::var("GITHUB_CLIENT_ID").unwrap_or_default(),
            github_client_secret: env::var("GITHUB_CLIENT_SECRET").unwrap_or_default(),
            google_token_path: env::var("GOOGLE_TOKEN_PATH")
                .unwrap_or_else(|_| "/token".to_string()),
            github_token_path: env::var("GITHUB_TOKEN_PATH")
                .unwrap_or_else(|_| "/login/oauth/access_token".to_string()),
        }
    }

    /// Mock-mode defaults, used by the local binary's tests and by anything
    /// that needs a Config without an environment.
    pub fn mock() -> Self {
        Self {
            enclave_port: 4000,
            enclave_mode: "mock".to_string(),
            google_tokeninfo_port: 8002,
            github_api_port: 8003,
            google_client_id: String::new(),
            google_client_secret: String::new(),
            github_client_id: String::new(),
            github_client_secret: String::new(),
            google_token_path: "/token".to_string(),
            github_token_path: "/login/oauth/access_token".to_string(),
        }
    }

    pub fn is_mock(&self) -> bool {
        self.enclave_mode != "nitro"
    }
}
