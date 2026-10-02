use super::{DeviceKey, DeviceKeyStore};
use crate::error::GatewayError;
use async_trait::async_trait;
use tokio_postgres::NoTls;

/// One idempotent statement, run on every boot, in the same spirit as the sealed
/// token store beside it.
///
/// `key_id` is the primary key rather than `(owner_id, key_id)`: a key id is
/// derived from the public key, so the same key registered under two owners would
/// be the same material claiming two identities, and the verifier resolves by id
/// alone. Making that impossible at the schema level is cheaper than deciding
/// which of the two rows to believe.
const MIGRATION: &str = "
CREATE TABLE IF NOT EXISTS memorai_device_keys (
    key_id            TEXT   PRIMARY KEY,
    owner_id          TEXT   NOT NULL,
    public_key        BYTEA  NOT NULL,
    label             TEXT   NOT NULL DEFAULT '',
    registered_at_ms  BIGINT NOT NULL,
    revoked_at_ms     BIGINT
);
CREATE INDEX IF NOT EXISTS memorai_device_keys_owner
    ON memorai_device_keys (owner_id, registered_at_ms DESC)
";

/// A connection per operation rather than a pool, for the same reason as the
/// token store: registrations happen once per device, and a verification reads one
/// row. Grant verification is the closest thing to a hot path here, and it is one
/// indexed primary-key lookup.
pub struct PostgresDeviceKeyStore {
    url: String,
}

impl PostgresDeviceKeyStore {
    pub async fn connect(url: &str) -> Result<Self, GatewayError> {
        let store = Self {
            url: url.to_string(),
        };
        let client = store.client().await?;
        client
            .batch_execute(MIGRATION)
            .await
            .map_err(|e| {
                GatewayError::Internal(format!("device key store migration failed: {e}"))
            })?;
        Ok(store)
    }

    async fn client(&self) -> Result<tokio_postgres::Client, GatewayError> {
        let (client, connection) = tokio_postgres::connect(&self.url, NoTls)
            .await
            .map_err(|e| GatewayError::Internal(format!("device key store unreachable: {e}")))?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::error!("device key store connection closed: {e}");
            }
        });
        Ok(client)
    }
}

fn row_to_key(row: &tokio_postgres::Row) -> DeviceKey {
    DeviceKey {
        key_id: row.get("key_id"),
        owner_id: row.get("owner_id"),
        public_key: row.get("public_key"),
        label: row.get("label"),
        registered_at_ms: row.get("registered_at_ms"),
        revoked_at_ms: row.get("revoked_at_ms"),
    }
}

#[async_trait]
impl DeviceKeyStore for PostgresDeviceKeyStore {
    async fn register(&self, key: &DeviceKey) -> Result<DeviceKey, GatewayError> {
        let client = self.client().await?;
        // DO NOTHING rather than DO UPDATE: a registration must not be able to
        // move an existing key id to a different owner or un-revoke it. The
        // RETURNING-less insert plus a read back is what makes the idempotent case
        // return the row that is actually stored rather than the one proposed.
        client
            .execute(
                "INSERT INTO memorai_device_keys \
                 (key_id, owner_id, public_key, label, registered_at_ms, revoked_at_ms) \
                 VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (key_id) DO NOTHING",
                &[
                    &key.key_id,
                    &key.owner_id,
                    &key.public_key,
                    &key.label,
                    &key.registered_at_ms,
                    &key.revoked_at_ms,
                ],
            )
            .await
            .map_err(|e| GatewayError::Internal(format!("device key insert failed: {e}")))?;

        self.get(&key.key_id)
            .await?
            .ok_or_else(|| GatewayError::Internal("device key vanished after insert".into()))
    }

    async fn get(&self, key_id: &str) -> Result<Option<DeviceKey>, GatewayError> {
        let client = self.client().await?;
        let rows = client
            .query(
                "SELECT key_id, owner_id, public_key, label, registered_at_ms, revoked_at_ms \
                 FROM memorai_device_keys WHERE key_id = $1",
                &[&key_id],
            )
            .await
            .map_err(|e| GatewayError::Internal(format!("device key read failed: {e}")))?;
        Ok(rows.first().map(row_to_key))
    }

    async fn list(&self, owner_id: &str) -> Result<Vec<DeviceKey>, GatewayError> {
        let client = self.client().await?;
        let rows = client
            .query(
                "SELECT key_id, owner_id, public_key, label, registered_at_ms, revoked_at_ms \
                 FROM memorai_device_keys WHERE owner_id = $1 ORDER BY registered_at_ms DESC",
                &[&owner_id],
            )
            .await
            .map_err(|e| GatewayError::Internal(format!("device key list failed: {e}")))?;
        Ok(rows.iter().map(row_to_key).collect())
    }

    async fn revoke(
        &self,
        owner_id: &str,
        key_id: &str,
        revoked_at_ms: i64,
    ) -> Result<bool, GatewayError> {
        let client = self.client().await?;
        // owner_id in the WHERE, so one owner cannot revoke another's device, and
        // `revoked_at_ms IS NULL` so a second revoke reports no change rather than
        // silently moving the timestamp.
        let changed = client
            .execute(
                "UPDATE memorai_device_keys SET revoked_at_ms = $1 \
                 WHERE key_id = $2 AND owner_id = $3 AND revoked_at_ms IS NULL",
                &[&revoked_at_ms, &key_id, &owner_id],
            )
            .await
            .map_err(|e| GatewayError::Internal(format!("device key revoke failed: {e}")))?;
        Ok(changed > 0)
    }

    fn backend(&self) -> &'static str {
        "postgres"
    }
}
