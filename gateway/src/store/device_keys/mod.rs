//! Registered device public keys: the root the gateway verifies grants against.
//!
//! An owner's device generates an Ed25519 keypair, keeps the private half, and
//! registers the public half here. From then on a grant is a scope signed by that
//! key, and the gateway can verify one but cannot produce one -- there is no
//! private key on this side.
//!
//! **This store is the weak point of that design, and naming it is the point.**
//! Registration is authorised by an owner session, and owner sessions are still
//! host-signed, so a host can forge a session and register a key of its own. What
//! it cannot do is that invisibly: every registration is a row with a timestamp,
//! `list` exposes them to the owner, and a client that keeps its own key id can
//! tell at a glance that the server is reporting a key it has never seen. Reads
//! made under a grant the owner did not issue also surface in the read log by
//! fingerprint (ADR 0005).
//!
//! So the attack moves from silent minting to detectable key substitution. Making
//! it impossible needs a verification root the operator cannot substitute -- an
//! attestation-gated enclave key, or an on-chain registry. `verify_grant` in
//! `shared` takes its keys through a closure so that swap is a change of one
//! caller. See ADR 0011.
//!
//! Nothing secret is stored here. A public key is public; the reason the rows
//! matter is integrity, not confidentiality, which is the opposite of the sealed
//! token store next door.

pub mod postgres;

use crate::error::GatewayError;
use async_trait::async_trait;

#[derive(Debug, Clone)]
pub struct DeviceKey {
    pub owner_id: String,
    /// Derived from the public key; see `shared::key_id_for`.
    pub key_id: String,
    pub public_key: Vec<u8>,
    /// Raw X25519 public key, for sealing results back to this device.
    ///
    /// A **second** key rather than a reuse of the one above, because Ed25519 is
    /// a signature scheme and cannot be encrypted to. Converting one to X25519 is
    /// possible, fiddly, and widely advised against, so the device registers
    /// both. See ADR 0024.
    ///
    /// `None` for every device registered before this field existed. Those
    /// devices keep signing grants and reading exactly as they did; what they
    /// cannot do is receive a sealed assembly, and the refusal says so rather
    /// than failing somewhere deeper. Optional for that reason alone -- a new
    /// registration should always carry one.
    pub encryption_key: Option<Vec<u8>>,
    /// Whatever the owner called this device. Display only, never trusted.
    pub label: String,
    pub registered_at_ms: i64,
    /// Set when revoked, which invalidates every grant this key ever signed.
    pub revoked_at_ms: Option<i64>,
}

impl DeviceKey {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at_ms.is_some()
    }

    /// Where a sealed result for this device can be sent, if anywhere.
    ///
    /// A revoked key gets nothing, checked here rather than at each call site:
    /// revocation has to mean the device stops receiving as well as stops
    /// signing, and the two are easy to treat separately by accident.
    pub fn sealing_target(&self) -> Option<&[u8]> {
        if self.is_revoked() {
            return None;
        }
        self.encryption_key.as_deref()
    }
}

#[async_trait]
pub trait DeviceKeyStore: Send + Sync {
    /// Registers a key, or returns the existing row unchanged if this key id is
    /// already registered to this owner.
    ///
    /// Idempotent rather than an error, because a client that retries a
    /// registration it already completed has not done anything wrong -- and
    /// because making it an error would mean a client has to distinguish "already
    /// mine" from "someone else's", which it cannot.
    async fn register(&self, key: &DeviceKey) -> Result<DeviceKey, GatewayError>;

    /// One key by id, whatever its owner. The verifier compares the owner itself,
    /// so looking up by id alone is deliberate: a key id that resolves to another
    /// owner must produce `OwnerMismatch` rather than `UnknownKey`, since those
    /// are different facts and an owner debugging a failing grant deserves the
    /// accurate one.
    async fn get(&self, key_id: &str) -> Result<Option<DeviceKey>, GatewayError>;

    /// Every key for one owner, newest first, revoked ones included -- an owner
    /// auditing their devices needs to see what was revoked and when.
    async fn list(&self, owner_id: &str) -> Result<Vec<DeviceKey>, GatewayError>;

    /// Revokes one key. Scoped to the owner so a caller cannot revoke somebody
    /// else's device. Returns whether a row changed.
    async fn revoke(
        &self,
        owner_id: &str,
        key_id: &str,
        revoked_at_ms: i64,
    ) -> Result<bool, GatewayError>;

    fn backend(&self) -> &'static str;
}

/// Used when `SEALED_TOKEN_STORE_URL` is unset: local mock runs and tests.
///
/// Loses every registration on restart, which for *this* store is worse than for
/// the token store next door: forgetting a device key does not merely lose a
/// convenience, it invalidates every grant that key signed. Correct for a dev
/// default, and a reason to set a real store for anything else.
#[derive(Default)]
pub struct InMemoryDeviceKeyStore {
    rows: std::sync::Mutex<Vec<DeviceKey>>,
}

#[async_trait]
impl DeviceKeyStore for InMemoryDeviceKeyStore {
    async fn register(&self, key: &DeviceKey) -> Result<DeviceKey, GatewayError> {
        let mut rows = self.rows.lock().expect("device key mutex poisoned");
        // By key id alone, matching the Postgres primary key. Keying on
        // (owner, key) here instead would let the same material register twice
        // under two owners in dev and fail in production -- and it would hide the
        // route's own check that the stored owner is the caller, since the row it
        // read back would always be its own.
        if let Some(existing) = rows.iter().find(|r| r.key_id == key.key_id) {
            return Ok(existing.clone());
        }
        rows.push(key.clone());
        Ok(key.clone())
    }

    async fn get(&self, key_id: &str) -> Result<Option<DeviceKey>, GatewayError> {
        let rows = self.rows.lock().expect("device key mutex poisoned");
        Ok(rows.iter().find(|r| r.key_id == key_id).cloned())
    }

    async fn list(&self, owner_id: &str) -> Result<Vec<DeviceKey>, GatewayError> {
        let rows = self.rows.lock().expect("device key mutex poisoned");
        let mut out: Vec<DeviceKey> = rows
            .iter()
            .filter(|r| r.owner_id == owner_id)
            .cloned()
            .collect();
        out.sort_by_key(|r| std::cmp::Reverse(r.registered_at_ms));
        Ok(out)
    }

    async fn revoke(
        &self,
        owner_id: &str,
        key_id: &str,
        revoked_at_ms: i64,
    ) -> Result<bool, GatewayError> {
        let mut rows = self.rows.lock().expect("device key mutex poisoned");
        match rows
            .iter_mut()
            .find(|r| r.key_id == key_id && r.owner_id == owner_id && r.revoked_at_ms.is_none())
        {
            Some(row) => {
                row.revoked_at_ms = Some(revoked_at_ms);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    fn backend(&self) -> &'static str {
        "memory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(owner: &str, key_id: &str) -> DeviceKey {
        DeviceKey {
            owner_id: owner.into(),
            key_id: key_id.into(),
            public_key: vec![1, 2, 3],
            encryption_key: Some(vec![4, 5, 6]),
            label: "laptop".into(),
            registered_at_ms: 1_000,
            revoked_at_ms: None,
        }
    }

    #[tokio::test]
    async fn registration_is_idempotent() {
        let store = InMemoryDeviceKeyStore::default();
        store.register(&key("owner-1", "k1")).await.unwrap();
        store.register(&key("owner-1", "k1")).await.unwrap();
        assert_eq!(store.list("owner-1").await.unwrap().len(), 1);
    }

    /// A key id is derived from the public key, so the same id under two owners
    /// would be one piece of material claiming two identities. The store keeps
    /// the first and reports it, and the caller compares owners -- which only
    /// works if this matches the Postgres primary key rather than keying on the
    /// pair.
    #[tokio::test]
    async fn the_same_key_id_cannot_be_held_by_two_owners() {
        let store = InMemoryDeviceKeyStore::default();
        store.register(&key("owner-1", "k1")).await.unwrap();
        let returned = store.register(&key("owner-2", "k1")).await.unwrap();
        assert_eq!(returned.owner_id, "owner-1", "the first registration stands");
        assert!(store.list("owner-2").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn one_owner_cannot_revoke_anothers_key() {
        let store = InMemoryDeviceKeyStore::default();
        store.register(&key("owner-1", "k1")).await.unwrap();

        assert!(!store.revoke("owner-2", "k1", 2_000).await.unwrap());
        assert!(!store.get("k1").await.unwrap().unwrap().is_revoked());

        assert!(store.revoke("owner-1", "k1", 2_000).await.unwrap());
        assert!(store.get("k1").await.unwrap().unwrap().is_revoked());
    }

    #[tokio::test]
    async fn revoking_twice_reports_no_change() {
        let store = InMemoryDeviceKeyStore::default();
        store.register(&key("owner-1", "k1")).await.unwrap();
        assert!(store.revoke("owner-1", "k1", 2_000).await.unwrap());
        assert!(!store.revoke("owner-1", "k1", 3_000).await.unwrap());
    }

    #[tokio::test]
    async fn listing_shows_revoked_keys_too() {
        let store = InMemoryDeviceKeyStore::default();
        store.register(&key("owner-1", "k1")).await.unwrap();
        store.revoke("owner-1", "k1", 2_000).await.unwrap();
        let listed = store.list("owner-1").await.unwrap();
        assert_eq!(listed.len(), 1, "an owner auditing devices needs the revoked ones");
        assert!(listed[0].is_revoked());
    }

    #[tokio::test]
    async fn a_lookup_by_id_crosses_owners_on_purpose() {
        // So the verifier can report OwnerMismatch rather than UnknownKey.
        let store = InMemoryDeviceKeyStore::default();
        store.register(&key("owner-1", "k1")).await.unwrap();
        let found = store.get("k1").await.unwrap().unwrap();
        assert_eq!(found.owner_id, "owner-1");
    }

    #[tokio::test]
    async fn re_registering_cannot_swap_the_encryption_key() {
        // The key id is derived from the *signing* key alone, so the same device
        // could re-register naming a different X25519 key. If that replaced the
        // stored one, anyone who could forge an owner session could redirect
        // every future sealed assembly to a key they hold -- without touching the
        // signing key, so the owner's own key-id check would still agree.
        //
        // `ON CONFLICT DO NOTHING` is what prevents it, and this is the test that
        // says so. Not a property of the column; a property of the write.
        let store = InMemoryDeviceKeyStore::default();
        store.register(&key("owner-1", "k1")).await.unwrap();

        let mut attacker = key("owner-1", "k1");
        attacker.encryption_key = Some(vec![9, 9, 9]);
        let stored = store.register(&attacker).await.unwrap();

        assert_eq!(stored.encryption_key, Some(vec![4, 5, 6]));
    }

    #[tokio::test]
    async fn a_revoked_key_is_no_longer_a_sealing_target() {
        // Revocation has to mean the device stops *receiving* as well as stops
        // signing. The two are easy to treat separately by accident -- the grant
        // check and the sealing check are in different files -- so the rule lives
        // on the row rather than at each call site.
        let store = InMemoryDeviceKeyStore::default();
        store.register(&key("owner-1", "k1")).await.unwrap();
        assert!(store.get("k1").await.unwrap().unwrap().sealing_target().is_some());

        store.revoke("owner-1", "k1", 2_000).await.unwrap();

        assert!(store.get("k1").await.unwrap().unwrap().sealing_target().is_none());
    }

    #[tokio::test]
    async fn a_device_registered_before_the_column_existed_still_works() {
        // The reason the field is Option. Such a device keeps signing grants and
        // reading exactly as it did; it simply cannot be sent a sealed assembly,
        // and that is refusable rather than broken.
        let store = InMemoryDeviceKeyStore::default();
        let mut old = key("owner-1", "k-old");
        old.encryption_key = None;
        store.register(&old).await.unwrap();

        let stored = store.get("k-old").await.unwrap().unwrap();
        assert!(!stored.is_revoked(), "it is a perfectly valid signing key");
        assert!(stored.sealing_target().is_none());
    }

    #[tokio::test]
    async fn an_owner_sees_only_their_own_keys() {
        let store = InMemoryDeviceKeyStore::default();
        store.register(&key("owner-1", "k1")).await.unwrap();
        store.register(&key("owner-2", "k2")).await.unwrap();
        assert_eq!(store.list("owner-1").await.unwrap().len(), 1);
        assert_eq!(store.list("owner-2").await.unwrap().len(), 1);
    }
}
