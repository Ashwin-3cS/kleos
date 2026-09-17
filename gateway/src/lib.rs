pub mod config;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod vsock;

use axum::routing::{get, post};
use axum::Router;
use config::Config;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use vsock::client::EnclaveClient;

pub struct AppState {
    pub config: Config,
    pub enclave: EnclaveClient,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    Router::new()
        .route("/health", get(routes::health::health))
        .route("/auth/callback", get(routes::auth::callback))
        .route("/auth/session", post(routes::auth::session))
        .route("/identity/verify", post(routes::identity::verify))
        .route("/memory/seal/encrypt", post(routes::memory::seal_encrypt))
        .route("/memory/scope/grant", post(routes::memory::scope_grant))
        .route("/memory/scope/introspect", post(routes::memory::scope_introspect))
        .with_state(state)
        .layer(cors)
}
