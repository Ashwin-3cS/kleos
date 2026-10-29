pub mod config;
pub mod enrolment;
pub mod error;
pub mod keys;
pub mod middleware;
pub mod routes;
pub mod store;
pub mod vsock;

use axum::routing::{get, post};
use axum::Router;
use config::Config;
use middleware::oauth_state::PendingAuthStore;
use std::sync::Arc;
use store::device_keys::DeviceKeyStore;
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
    /// Registered owner device public keys -- what grants are verified against.
    /// There is no private key anywhere in this process, which is the point:
    /// the gateway can check a grant and cannot mint one. See ADR 0011.
    pub device_keys: Box<dyn DeviceKeyStore>,
    /// Local-session nonces already used (ADR 0029). In process, like the PKCE
    /// verifiers above and with the same consequence: a restart forgets them,
    /// which reopens a window two minutes wide for bytes an attacker already
    /// had to have captured.
    pub local_nonces: routes::local_auth::NonceCache,
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
        .route(
            "/auth/session/introspect",
            post(routes::auth::session_introspect),
        )
        .route("/identity/verify", post(routes::identity::verify))
        .route("/memory/act", post(routes::memory::memory_act))
        .route("/memory/assemble", post(routes::memory::memory_assemble))
        .route("/memory/evaluate", post(routes::memory::memory_evaluate))
        .route(
            "/memory/evaluate-write",
            post(routes::memory::memory_evaluate_write),
        )
        .route("/memory/seal/encrypt", post(routes::memory::seal_encrypt))
        .route("/memory/seal/decrypt", post(routes::memory::seal_decrypt))
        .route(
            "/memory/seal/unseal",
            post(routes::memory::seal_unseal_for_grant),
        )
        .route(
            "/memory/seal/for-grant",
            post(routes::memory::seal_encrypt_for_grant),
        )
        .route(
            "/memory/seal/for-resolution",
            post(routes::memory::unseal_for_resolution),
        )
        .route("/auth/device/register", post(routes::memory::device_register))
        .route("/auth/local/enrol", post(routes::local_auth::enrol))
        .route("/auth/local/session", post(routes::local_auth::session))
        .route("/auth/device/keys", get(routes::memory::device_keys))
        .route("/auth/device/revoke", post(routes::memory::device_revoke))
        .route(
            "/memory/scope/introspect",
            post(routes::memory::scope_introspect),
        )
        .with_state(state)
        .layer(cors)
}
