use crate::error::EnclaveError;

// Phase 2: Seal encryption of memory blobs before they leave the enclave
// for Walrus. Typed stub only -- no memory ingestion exists yet to encrypt.
//
// Called from the ingestion graph (Python orchestration service, outside
// the enclave) only for raw content that needs to be encrypted inside the
// TEE; the enclave itself stays this narrow on purpose -- see README's
// "Phase 2 direction" section.

pub struct SealEncrypted {
    pub ciphertext: Vec<u8>,
    pub key_id: String,
}

pub async fn encrypt(_owner_id: &str, _plaintext: Vec<u8>) -> Result<SealEncrypted, EnclaveError> {
    todo!("Seal encryption is out of scope for Phase 1")
}

pub async fn decrypt(_owner_id: &str, _blob: SealEncrypted) -> Result<Vec<u8>, EnclaveError> {
    todo!("Seal decryption is out of scope for Phase 1")
}
