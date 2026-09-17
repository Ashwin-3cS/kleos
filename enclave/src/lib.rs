pub mod config;
pub mod error;
pub mod routes;
pub mod services;
pub mod vsock;

use axum::routing::{get, post};
use axum::Router;
use config::Config;
use fastcrypto::ed25519::Ed25519KeyPair;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

pub struct AppState {
    pub signing_key: Ed25519KeyPair,
    pub config: Config,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    Router::new()
        .route("/health", get(routes::health::health))
        .route("/attest", get(routes::attest::attest))
        .route("/identity/verify", post(routes::identity::verify))
        .route("/oauth/exchange", post(routes::oauth::exchange))
        .route("/seal/encrypt", post(routes::seal::encrypt))
        .route("/seal/decrypt", post(routes::seal::decrypt))
        .with_state(state)
        .layer(cors)
}
