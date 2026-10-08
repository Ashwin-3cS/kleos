use anyhow::Result;
use gateway::config::Config;
use gateway::store::device_keys::postgres::PostgresDeviceKeyStore;
use gateway::store::device_keys::{DeviceKeyStore, InMemoryDeviceKeyStore};
use gateway::store::postgres::PostgresTokenStore;
use gateway::store::{InMemoryTokenStore, SealedTokenStore};
use gateway::vsock::client::EnclaveClient;
use gateway::{build_router, AppState};
use std::sync::Arc;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt::init();

    let config = Config::from_env()?;
    info!(port = config.gateway_port, "starting Kleos gateway");

    let enclave = EnclaveClient::new(&config.enclave_host, config.enclave_port);
    let tokens: Box<dyn SealedTokenStore> = match &config.sealed_token_store_url {
        Some(url) => Box::new(
            PostgresTokenStore::connect(url)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        ),
        None => Box::new(InMemoryTokenStore::default()),
    };
    info!(backend = tokens.backend(), "sealed oauth token store ready");

    let device_keys: Box<dyn DeviceKeyStore> = match &config.sealed_token_store_url {
        Some(url) => Box::new(
            PostgresDeviceKeyStore::connect(url)
                .await
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        ),
        None => Box::new(InMemoryDeviceKeyStore::default()),
    };
    info!(backend = device_keys.backend(), "device key store ready");

    let port = config.gateway_port;
    let state = Arc::new(AppState {
        config,
        enclave,
        pending_auth: Default::default(),
        tokens,
        device_keys,
    });

    let router = build_router(state);
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    info!("gateway listening on {}", listener.local_addr()?);

    axum::serve(listener, router).await?;
    Ok(())
}
