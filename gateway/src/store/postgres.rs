use super::{SealedOAuthToken, SealedTokenStore};
use crate::error::GatewayError;
use async_trait::async_trait;
use tokio_postgres::NoTls;

/// One idempotent statement, run on every boot, in the same spirit as
/// `orchestrator/src/orchestrator/storage/migrations.py`. The UNIQUE on
/// `(owner_id, provider)` is what makes re-consent an update rather than a
/// second row.
const MIGRATION: &str = "
CREATE TABLE IF NOT EXISTS memorai_sealed_oauth_tokens (
    owner_id              TEXT   NOT NULL,
    provider              TEXT   NOT NULL,
    sealed_refresh_token  BYTEA  NOT NULL,
    key_id                TEXT   NOT NULL,
    scheme                TEXT   NOT NULL,
    scopes                TEXT[] NOT NULL DEFAULT '{}',
    granted_at_ms         BIGINT NOT NULL,
    expires_at_ms         BIGINT,
    UNIQUE (owner_id, provider)
)
";

/// A connection is opened per operation rather than pooled. Writes happen
/// once per user per source, at consent time, and reads only when a
/// connector refreshes -- there is no hot path here to justify a pool.
pub struct PostgresTokenStore {
    url: String,
}

impl PostgresTokenStore {
    /// Connects once to apply the migration, so a bad URL fails at boot
    /// rather than at the first user's callback.
    pub async fn connect(url: &str) -> Result<Self, GatewayError> {
        let store = Self {
            url: url.to_string(),
        };
        let client = store.client().await?;
        client
            .batch_execute(MIGRATION)
            .await
            .map_err(|e| GatewayError::Internal(format!("token store migration failed: {e}")))?;
        Ok(store)
    }

    async fn client(&self) -> Result<tokio_postgres::Client, GatewayError> {
        let (client, connection) = tokio_postgres::connect(&self.url, NoTls)
            .await
            .map_err(|e| GatewayError::Internal(format!("token store unreachable: {e}")))?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::error!("token store connection closed: {e}");
            }
        });
        Ok(client)
    }
}

#[async_trait]
impl SealedTokenStore for PostgresTokenStore {
    async fn upsert(&self, record: &SealedOAuthToken) -> Result<(), GatewayError> {
        let client = self.client().await?;
        client
            .execute(
                "INSERT INTO memorai_sealed_oauth_tokens
                   (owner_id, provider, sealed_refresh_token, key_id, scheme, scopes,
                    granted_at_ms, expires_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (owner_id, provider) DO UPDATE SET
                   sealed_refresh_token = EXCLUDED.sealed_refresh_token,
                   key_id               = EXCLUDED.key_id,
                   scheme               = EXCLUDED.scheme,
                   scopes               = EXCLUDED.scopes,
                   granted_at_ms        = EXCLUDED.granted_at_ms,
                   expires_at_ms        = EXCLUDED.expires_at_ms",
                &[
                    &record.owner_id,
                    &record.provider,
                    &record.sealed_refresh_token,
                    &record.key_id,
                    &record.scheme,
                    &record.scopes,
                    &record.granted_at_ms,
                    &record.expires_at_ms,
                ],
            )
            .await
            .map_err(|e| GatewayError::Internal(format!("failed to persist sealed token: {e}")))?;
        Ok(())
    }

    async fn get(
        &self,
        owner_id: &str,
        provider: &str,
    ) -> Result<Option<SealedOAuthToken>, GatewayError> {
        let client = self.client().await?;
        let row = client
            .query_opt(
                "SELECT owner_id, provider, sealed_refresh_token, key_id, scheme, scopes,
                        granted_at_ms, expires_at_ms
                   FROM memorai_sealed_oauth_tokens
                  WHERE owner_id = $1 AND provider = $2",
                &[&owner_id, &provider],
            )
            .await
            .map_err(|e| GatewayError::Internal(format!("failed to read sealed token: {e}")))?;

        Ok(row.map(|r| SealedOAuthToken {
            owner_id: r.get(0),
            provider: r.get(1),
            sealed_refresh_token: r.get(2),
            key_id: r.get(3),
            scheme: r.get(4),
            scopes: r.get(5),
            granted_at_ms: r.get(6),
            expires_at_ms: r.get(7),
        }))
    }

    fn backend(&self) -> &'static str {
        "postgres"
    }
}
