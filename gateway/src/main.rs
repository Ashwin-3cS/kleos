use anyhow::Result;
use gateway::config::Config;
use gateway::vsock::client::EnclaveClient;
use gateway::{build_router, AppState};
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let config = Config::from_env();
    info!(port = config.gateway_port, "starting memorai gateway");

    let enclave = EnclaveClient::new(&config.enclave_host, config.enclave_port);
    let port = config.gateway_port;
    let state = Arc::new(AppState { config, enclave });

    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    info!("gateway listening on {}", listener.local_addr()?);

    axum::serve(listener, router).await?;
    Ok(())
}
