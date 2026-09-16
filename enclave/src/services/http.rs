use crate::error::EnclaveError;
use std::time::Duration;

/// The enclave has no direct network access. Every outbound call must
/// target `localhost:<port>`; in `nitro` mode that port is bridged out over
/// VSOCK to the host by socat (see scripts/parent_forwarder.sh and
/// enclave/run.sh — the bridging is shell-level, not Rust). In `mock` mode
/// there is no bridge, so callers must short-circuit before reaching here
/// (see services/oauth/*.rs), which is why this client is not itself
/// feature-gated: it's always "just HTTP to localhost", the tunnel is what
/// changes.
pub fn tunnel_client() -> Result<reqwest::Client, EnclaveError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| EnclaveError::Internal(format!("failed to build HTTP client: {e}")))
}

pub fn tunnel_url(port: u16, path: &str) -> String {
    format!("http://127.0.0.1:{port}{path}")
}
