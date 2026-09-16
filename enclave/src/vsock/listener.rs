use anyhow::Result;
use tokio::net::TcpListener;

/// Binds the plain TCP socket the enclave's Axum server listens on.
///
/// There is no Rust-level VSOCK crate involved anywhere in this project.
/// In `nitro` mode, the enclave's `run.sh` runs
/// `socat VSOCK-LISTEN:<port>,reuseaddr,fork TCP:localhost:<port> &`
/// so that inbound traffic arriving over VSOCK from the host is bridged to
/// this ordinary TCP listener. In `mock` mode there is no VSOCK at all --
/// the gateway just dials this TCP port directly on localhost. Either way,
/// this function binds the same thing: a plain TCP listener.
pub async fn bind(port: u16) -> Result<TcpListener> {
    let addr = format!("0.0.0.0:{port}");
    let listener = TcpListener::bind(&addr).await?;
    Ok(listener)
}
