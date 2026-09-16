use std::env;

/// Enclave runtime configuration, sourced from environment variables (see
/// .env.example at the workspace root). In `nitro` mode these are injected
/// via the enclave's run.sh from the .env file baked into the EIF image; in
/// `mock` mode they come from a local .env loaded by dotenvy.
#[derive(Debug, Clone)]
pub struct Config {
    pub enclave_port: u16,
    pub enclave_mode: String,
    pub google_tokeninfo_port: u16,
    pub github_api_port: u16,
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
        }
    }

    pub fn is_mock(&self) -> bool {
        self.enclave_mode != "nitro"
    }
}
