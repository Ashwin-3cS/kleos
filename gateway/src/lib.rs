pub mod config;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod store;
pub mod vsock;

use axum::routing::{get, post};
use axum::Router;
use config::Config;
use middleware::oauth_state::PendingAuthStore;
use std::sync::Arc;
use store::SealedTokenStore;
use tower_http::cors::{Any, CorsLayer};
use vsock::client::EnclaveClient;

pub struct AppState {
    pub config: Config,
    pub enclave: EnclaveClient,
    /// Server-side half of each in-flight OAuth authorization (the PKCE
    /// verifier). In-process and single-use, so a gateway restart invalidates
    /// pending consents rather than leaving replayable ones behind.
    pub pending_auth: PendingAuthStore,
    /// Ciphertext only. See store/mod.rs.
    pub tokens: Box<dyn SealedTokenStore>,
}

pub fn build_router(state: Arc<AppState>) -> Router {
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_origin(Any);

    Router::new()
        .route("/health", get(routes::health::health))
        .route("/auth/authorize", get(routes::auth::authorize))
        .route("/auth/callback", get(routes::auth::callback))
        .route("/auth/session", post(routes::auth::session))
        .route("/identity/verify", post(routes::identity::verify))
        .route("/memory/seal/encrypt", post(routes::memory::seal_encrypt))
        .route("/memory/scope/grant", post(routes::memory::scope_grant))
        .route(
            "/memory/scope/introspect",
            post(routes::memory::scope_introspect),
        )
        .with_state(state)
        .layer(cors)
}
