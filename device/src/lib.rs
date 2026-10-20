//! The device's own cryptography: deriving its receiving key, and opening what
//! the enclave sealed to it.
//!
//! A library as well as a binary so a test can hold both ends. The round trip
//! in `tests/round_trip.rs` is the only thing that proves this agrees with
//! `enclave::services::recipient`, because the two are written out separately
//! on purpose -- see `open_as_device`.

use shared::SealedToDevice;

/// Separates the receiving key from the signing key it is derived from. A
/// constant rather than a parameter: two devices deriving differently would
/// each be unable to read the other's answers, and the failure would look like
/// corruption rather than a mismatch.
const ENCRYPTION_KEY_INFO: &[u8] = b"KLEOS_DEVICE_X25519_V1";


/// The X25519 secret this device receives on, derived from its signing key.
///
/// Takes the private bytes rather than the keypair because fastcrypto's
/// `private()` consumes it -- the same reason `keygen` reads the public half
/// before writing the file.
pub fn encryption_secret(private_bytes: &[u8]) -> x25519_dalek::StaticSecret {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let mut material = [0u8; 32];
    Hkdf::<Sha256>::new(None, private_bytes)
        .expand(ENCRYPTION_KEY_INFO, &mut material)
        .expect("32 bytes is a valid hkdf length");
    // `StaticSecret::from` clamps, so any 32 bytes are a usable scalar.
    x25519_dalek::StaticSecret::from(material)
}

pub fn encryption_public(private_bytes: &[u8]) -> x25519_dalek::PublicKey {
    x25519_dalek::PublicKey::from(&encryption_secret(private_bytes))
}

/// The receiving half of `enclave::services::recipient::seal_to_device`.
///
/// Written out here rather than imported, because this crate is the thing an
/// MCP client and a browser are checked against: importing the enclave's own
/// function would prove the enclave agrees with itself. A round-trip test holds
/// the two together.
pub fn open_as_device(
    secret: &x25519_dalek::StaticSecret,
    sealed: &SealedToDevice,
) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::PublicKey;

    if sealed.scheme != SEAL_TO_DEVICE_SCHEME {
        return Err(format!("unknown sealing scheme {:?}", sealed.scheme));
    }
    let decode = |label: &str, value: &str| {
        unb64(value).ok_or_else(|| format!("{label} is not base64"))
    };
    let ephemeral: [u8; 32] = decode("ephemeral_public_key_b64", &sealed.ephemeral_public_key_b64)?
        .try_into()
        .map_err(|_| "the ephemeral public key is not 32 bytes".to_string())?;
    let nonce = decode("nonce_b64", &sealed.nonce_b64)?;
    let ciphertext = decode("ciphertext_b64", &sealed.ciphertext_b64)?;

    let recipient_public = PublicKey::from(secret);
    let shared_secret = secret.diffie_hellman(&PublicKey::from(ephemeral));

    // Exactly the enclave's `info`, in exactly this order. A browser building
    // it differently gets a key that decrypts nothing, with no clue why.
    let mut info = Vec::new();
    info.extend_from_slice(SEAL_TO_DEVICE_SCHEME.as_bytes());
    info.extend_from_slice(&ephemeral);
    info.extend_from_slice(recipient_public.as_bytes());

    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared_secret.as_bytes())
        .expand(&info, &mut key)
        .map_err(|e| format!("hkdf expand failed: {e}"))?;

    Aes256Gcm::new_from_slice(&key)
        .map_err(|e| format!("aes key rejected: {e}"))?
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: SEAL_TO_DEVICE_SCHEME.as_bytes(),
            },
        )
        .map_err(|_| "this blob was not sealed to this device".to_string())
}

/// The scheme string, duplicated from the enclave on purpose: it is part of the
/// wire format a third implementation has to match, and a shared constant would
/// let a rename pass unnoticed on both sides at once.
pub const SEAL_TO_DEVICE_SCHEME: &str = "KLEOS_X25519_AES256GCM_V1";

fn unb64(text: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.decode(text).ok()
}
