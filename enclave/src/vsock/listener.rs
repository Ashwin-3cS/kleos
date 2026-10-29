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
///
/// **Loopback, not `0.0.0.0`.** Both callers are local: under `nitro` it is
/// socat inside the enclave connecting to `TCP:localhost:4000`, and under
/// `mock` it is the gateway on the same machine. Binding every interface
/// bought nothing in either mode and, on a laptop in mock mode, put the
/// enclave's seal and identity routes on the local network -- which
/// `docs/quickstart.mdx` had already been describing as loopback.
pub async fn bind(port: u16) -> Result<TcpListener> {
    let addr = format!("127.0.0.1:{port}");
    let listener = TcpListener::bind(&addr).await?;
    Ok(listener)
}
