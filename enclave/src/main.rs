use anyhow::Result;
use enclave::config::Config;
use enclave::services::attestation::generate_ephemeral_key;
use enclave::{build_router, vsock, AppState};
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let config = Config::from_env();
    info!(mode = %config.enclave_mode, port = config.enclave_port, "starting memorai enclave");

    let signing_key = generate_ephemeral_key();
    let port = config.enclave_port;
    let state = Arc::new(AppState {
        signing_key,
        config,
    });

    let router = build_router(state);
    let listener = vsock::listener::bind(port).await?;
    info!("enclave listening on {}", listener.local_addr()?);

    axum::serve(listener, router).await?;
    Ok(())
}
