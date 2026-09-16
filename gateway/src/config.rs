use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub gateway_port: u16,
    pub enclave_host: String,
    pub enclave_port: u16,
    pub session_jwt_secret: String,
}

impl Config {
    pub fn from_env() -> Self {
        Self {
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
            session_jwt_secret: env::var("SESSION_JWT_SECRET")
                .unwrap_or_else(|_| "dev-insecure-secret-change-me".to_string()),
        }
    }
}
