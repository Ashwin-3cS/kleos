use crate::error::EnclaveError;
use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::KeyPair;

/// Ephemeral signing key generated on enclave boot. In `nitro` mode it is
/// seeded from NSM hardware entropy; in `mock` mode from the thread RNG.
pub fn generate_ephemeral_key() -> Ed25519KeyPair {
    #[cfg(feature = "nitro")]
    {
        use aws_nitro_enclaves_nsm_api::api::{Request as NsmRequest, Response as NsmResponse};
        use aws_nitro_enclaves_nsm_api::driver;
        use rand::SeedableRng;

        let fd = driver::nsm_init();
        let response = driver::nsm_process_request(fd, NsmRequest::GetRandom);
        match response {
            NsmResponse::GetRandom { random } if random.len() >= 32 => {
                driver::nsm_exit(fd);
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&random[..32]);
                let mut rng = rand::rngs::StdRng::from_seed(seed);
                Ed25519KeyPair::generate(&mut rng)
            }
            _ => {
                driver::nsm_exit(fd);
                Ed25519KeyPair::generate(&mut rand::thread_rng())
            }
        }
    }
    #[cfg(not(feature = "nitro"))]
    {
        Ed25519KeyPair::generate(&mut rand::thread_rng())
    }
}

/// Returns a hex-encoded NSM attestation document committing to `pk_bytes`.
/// Under `nitro` this is a real NSM call; under `mock` it is a clearly-fake
/// stub so nobody mistakes local runs for a real attestation.
#[cfg(feature = "nitro")]
pub async fn get_attestation(pk_bytes: Vec<u8>) -> Result<String, EnclaveError> {
    use aws_nitro_enclaves_nsm_api::api::{Request as NsmRequest, Response as NsmResponse};
    use aws_nitro_enclaves_nsm_api::driver;

    let fd = driver::nsm_init();
    let request = NsmRequest::Attestation {
        user_data: None,
        nonce: None,
        public_key: Some(serde_bytes::ByteBuf::from(pk_bytes)),
    };
    let response = driver::nsm_process_request(fd, request);
    match response {
        NsmResponse::Attestation { document } => {
            driver::nsm_exit(fd);
            Ok(hex::encode(document))
        }
        _ => {
            driver::nsm_exit(fd);
            Err(EnclaveError::Internal("NSM attestation failed".into()))
        }
    }
}

#[cfg(not(feature = "nitro"))]
pub async fn get_attestation(pk_bytes: Vec<u8>) -> Result<String, EnclaveError> {
    // Obviously-fake prefix so a mock document can never be confused with a
    // real NSM attestation downstream.
    Ok(format!("MOCK_ATTESTATION_{}", hex::encode(pk_bytes)))
}
