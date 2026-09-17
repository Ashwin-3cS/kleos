//! Per-owner store of **sealed** OAuth refresh tokens.
//!
//! The gateway is the only component that persists these rows, and it has
//! never held the plaintext: the enclave seals the refresh token before the
//! exchange response crosses back over VSOCK, so `sealed_refresh_token` is
//! ciphertext from the moment it exists on this side of the boundary. There
//! is deliberately no `decrypt` here and no route that returns a row's
//! bytes -- unsealing is `POST /seal/decrypt` on the enclave and nothing
//! else. The Python orchestrator is given no credentials for this database.

pub mod postgres;

use crate::error::GatewayError;
use async_trait::async_trait;

#[derive(Clone)]
pub struct SealedOAuthToken {
    pub owner_id: String,
    pub provider: String,
    /// Ciphertext. In mock mode this is a `MOCK_SEAL_V1:` blob, which is
    /// obfuscation and not encryption -- see enclave/src/services/seal.rs.
    pub sealed_refresh_token: Vec<u8>,
    pub key_id: String,
    pub scheme: String,
    pub scopes: Vec<String>,
    pub granted_at_ms: i64,
    pub expires_at_ms: Option<i64>,
}

impl std::fmt::Debug for SealedOAuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedOAuthToken")
            .field("owner_id", &self.owner_id)
            .field("provider", &self.provider)
            .field("sealed_bytes", &self.sealed_refresh_token.len())
            .field("key_id", &self.key_id)
            .field("scheme", &self.scheme)
            .field("scopes", &self.scopes)
            .field("granted_at_ms", &self.granted_at_ms)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

#[async_trait]
pub trait SealedTokenStore: Send + Sync {
    /// Upserts on `(owner_id, provider)`, so re-consent replaces the prior
    /// grant in place rather than accumulating stale tokens.
    async fn upsert(&self, record: &SealedOAuthToken) -> Result<(), GatewayError>;

    async fn get(
        &self,
        owner_id: &str,
        provider: &str,
    ) -> Result<Option<SealedOAuthToken>, GatewayError>;

    fn backend(&self) -> &'static str;
}

/// Used when `SEALED_TOKEN_STORE_URL` is unset: local mock runs and tests,
/// where standing up Postgres to prove a custody property adds nothing.
/// Loses everything on restart, which is correct for a dev default.
#[derive(Default)]
pub struct InMemoryTokenStore {
    rows: std::sync::Mutex<std::collections::HashMap<(String, String), SealedOAuthToken>>,
}

#[async_trait]
impl SealedTokenStore for InMemoryTokenStore {
    async fn upsert(&self, record: &SealedOAuthToken) -> Result<(), GatewayError> {
        let mut rows = self.rows.lock().expect("token store mutex poisoned");
        rows.insert(
            (record.owner_id.clone(), record.provider.clone()),
            record.clone(),
        );
        Ok(())
    }

    async fn get(
        &self,
        owner_id: &str,
        provider: &str,
    ) -> Result<Option<SealedOAuthToken>, GatewayError> {
        let rows = self.rows.lock().expect("token store mutex poisoned");
        Ok(rows
            .get(&(owner_id.to_string(), provider.to_string()))
            .cloned())
    }

    fn backend(&self) -> &'static str {
        "memory"
    }
}
