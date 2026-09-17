use crate::error::EnclaveError;

// The enclave's only Phase 2 responsibility: encrypt raw sensitive source
// content before it is allowed to leave the TEE. The orchestrator's
// ingestion graph calls in here (via the gateway) with one piece of raw
// content at a time and stores only what comes back. Nothing agentic --
// no extraction, resolution or retrieval -- happens on this side.

/// Names the scheme of a mock blob. Mirrors `MOCK_ATTESTATION_`: a mock
/// ciphertext is self-labelling, so it can never be mistaken downstream for
/// something Seal actually encrypted.
pub const MOCK_SEAL_SCHEME: &str = "MOCK_SEAL_V1";

#[cfg(not(feature = "nitro"))]
const MOCK_SEAL_MARKER: &[u8] = b"MOCK_SEAL_V1:";

pub struct SealEncrypted {
    pub ciphertext: Vec<u8>,
    pub key_id: String,
    pub scheme: String,
}

#[cfg(feature = "nitro")]
pub async fn encrypt(owner_id: &str, plaintext: Vec<u8>) -> Result<SealEncrypted, EnclaveError> {
    let _ = (owner_id, plaintext);
    // Real Seal (Mysten's threshold IBE over Sui) needs a key-server
    // committee, an on-chain policy object for the owner, and the Seal SDK
    // reachable through a VSOCK tunnel -- none of which exist yet.
    Err(EnclaveError::Internal(
        "real Seal encryption is not wired yet: needs a Seal key-server committee and an on-chain owner policy object".into(),
    ))
}

#[cfg(feature = "nitro")]
pub async fn decrypt(owner_id: &str, blob: SealEncrypted) -> Result<Vec<u8>, EnclaveError> {
    let _ = (owner_id, blob);
    Err(EnclaveError::Internal(
        "real Seal decryption is not wired yet: needs a Seal key-server committee and an on-chain owner policy object".into(),
    ))
}

/// Deliberately fake, reversible transform used in mock mode so the full
/// ingestion round trip (orchestrator -> gateway -> enclave -> back) is
/// exercisable locally. This is obfuscation, not encryption.
#[cfg(not(feature = "nitro"))]
pub async fn encrypt(owner_id: &str, plaintext: Vec<u8>) -> Result<SealEncrypted, EnclaveError> {
    let seed = derive_seed(owner_id);
    let mut ciphertext = MOCK_SEAL_MARKER.to_vec();
    ciphertext.extend_from_slice(&xor_keystream(&seed, &plaintext));
    Ok(SealEncrypted {
        ciphertext,
        key_id: mock_key_id(&seed),
        scheme: MOCK_SEAL_SCHEME.to_string(),
    })
}

#[cfg(not(feature = "nitro"))]
pub async fn decrypt(owner_id: &str, blob: SealEncrypted) -> Result<Vec<u8>, EnclaveError> {
    let seed = derive_seed(owner_id);
    if blob.key_id != mock_key_id(&seed) {
        return Err(EnclaveError::BadRequest(
            "key_id does not belong to this owner".into(),
        ));
    }
    let body = blob
        .ciphertext
        .strip_prefix(MOCK_SEAL_MARKER)
        .ok_or_else(|| EnclaveError::BadRequest("not a MOCK_SEAL_V1 blob".into()))?;
    Ok(xor_keystream(&seed, body))
}

#[cfg(not(feature = "nitro"))]
fn derive_seed(owner_id: &str) -> [u8; 32] {
    use fastcrypto::hash::{Blake2b256, HashFunction};
    let mut hasher = Blake2b256::default();
    hasher.update(b"memorai-mock-seal-v1");
    hasher.update(owner_id.as_bytes());
    hasher.finalize().digest
}

#[cfg(not(feature = "nitro"))]
fn mock_key_id(seed: &[u8; 32]) -> String {
    format!("mock-seal-{}", hex::encode(&seed[..8]))
}

#[cfg(not(feature = "nitro"))]
fn xor_keystream(seed: &[u8; 32], input: &[u8]) -> Vec<u8> {
    use fastcrypto::hash::{Blake2b256, HashFunction};
    let mut out = Vec::with_capacity(input.len());
    for (block_index, block) in input.chunks(32).enumerate() {
        let mut hasher = Blake2b256::default();
        hasher.update(seed);
        hasher.update((block_index as u64).to_be_bytes());
        let ks = hasher.finalize().digest;
        out.extend(block.iter().zip(ks.iter()).map(|(b, k)| b ^ k));
    }
    out
}

#[cfg(all(test, not(feature = "nitro")))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_round_trip_recovers_plaintext() {
        let plaintext = b"a raw source record long enough to span several keystream blocks".to_vec();
        let sealed = encrypt("owner-1", plaintext.clone()).await.unwrap();
        assert!(sealed.ciphertext.starts_with(MOCK_SEAL_MARKER));
        assert_ne!(sealed.ciphertext[MOCK_SEAL_MARKER.len()..], plaintext[..]);
        assert_eq!(decrypt("owner-1", sealed).await.unwrap(), plaintext);
    }

    #[tokio::test]
    async fn mock_key_is_owner_bound() {
        let a = encrypt("owner-1", b"x".to_vec()).await.unwrap();
        let b = encrypt("owner-2", b"x".to_vec()).await.unwrap();
        assert_ne!(a.key_id, b.key_id);
        assert!(decrypt("owner-2", a).await.is_err());
    }
}
