//! Sealing an assembled answer to the device that asked for it.
//!
//! This is the one line in ADR 0024 that is actually load-bearing. "Decrypt
//! inside the enclave" buys nothing on its own: if the enclave hands plaintext
//! back to the orchestrator and the orchestrator relays it over MCP, the host
//! sees it in transit, and the decryption has moved while the exposure has not.
//! Re-encrypting to the asking device is what makes the move mean anything.
//!
//! ## Real in every build, unlike `seal.rs`
//!
//! The owner's at-rest seal next door is a reversible XOR in mock mode, because
//! real Seal needs a key-server committee and an on-chain policy object that do
//! not exist yet. **Nothing is missing for this one.** The recipient's public
//! key is in a Postgres row, the ephemeral half is generated here, and the
//! primitives are in-process. A mock version would make the only property the
//! ADR decides untestable, and would read in a log exactly like the real thing.
//!
//! So this is real AEAD under `mock` and under `nitro` alike. What mock mode
//! still does not give you is an *attested* enclave: the ciphertext is sound,
//! and the claim that it was produced somewhere the operator cannot look is
//! not. That gap closes on EC2, not here.
//!
//! ## The construction
//!
//! Ephemeral-static X25519, then HKDF-SHA256, then AES-256-GCM:
//!
//! ```text
//! eph_sk, eph_pk  <- fresh per reply
//! shared          <- X25519(eph_sk, recipient_pk)
//! key             <- HKDF-SHA256(ikm = shared, salt = none,
//!                                info = scheme || eph_pk || recipient_pk)
//! ciphertext      <- AES-256-GCM(key, nonce = 12 random bytes,
//!                                aad = scheme, plaintext)
//! ```
//!
//! Three choices worth stating:
//!
//! - **Ephemeral per reply, not per session.** Forward secrecy for the enclave
//!   half costs one scalar multiplication on a path already bounded by top-k,
//!   and it means a nonce can never repeat under a reused key, because the key
//!   never repeats.
//! - **Both public keys in the HKDF info.** Binds the derived key to the exact
//!   pair. Without it, a shared secret is just 32 bytes and an attacker who can
//!   substitute an ephemeral key gets to reuse a derivation elsewhere.
//! - **Every primitive is one WebCrypto can do.** The recipient is a browser or
//!   an MCP client, and the browser side has to work with `deriveBits` and no
//!   library: X25519 agreement, HKDF-SHA256, AES-GCM decrypt. Picking, say,
//!   ChaCha20-Poly1305 or HKDF-SHA3 would have forced a JavaScript
//!   implementation of the one step that must not be re-implemented.
//!
//! ## Dependencies this adds to the measured image
//!
//! `x25519-dalek`, `aes-gcm`, `hkdf` and `sha2` -- RustCrypto, pure Rust, no
//! C. `fastcrypto` is already here but gates AES behind a feature and exposes
//! no X25519 at all, so there was no way to reach these from what the enclave
//! already carries. An attestation is only worth what it measures, so each
//! addition is a real cost; four small crates for the ADR's central property is
//! the cheapest version of it available.

use crate::error::EnclaveError;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use shared::SealedToDevice;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Self-labelling, so a blob that reaches a log or a UI says what it is. The
/// device refuses anything else rather than guessing.
pub const SEAL_TO_DEVICE_SCHEME: &str = "KLEOS_X25519_AES256GCM_V1";

/// Encrypts `plaintext` so that only the holder of `recipient_key`'s private
/// half can read it.
///
/// `recipient_key` comes from the gateway's device registry, resolved from the
/// key that signed the grant. This function cannot check that and does not try:
/// the derivation is the gateway's job, and a second half-check in here would
/// read as though the enclave were verifying something it cannot see.
pub fn seal_to_device(
    recipient_key: &[u8],
    recipient_key_id: &str,
    plaintext: &[u8],
) -> Result<SealedToDevice, EnclaveError> {
    let recipient: [u8; 32] = recipient_key.try_into().map_err(|_| {
        EnclaveError::BadRequest(format!(
            "an X25519 public key is 32 bytes, got {}",
            recipient_key.len()
        ))
    })?;
    let recipient = PublicKey::from(recipient);

    let ephemeral_secret = EphemeralSecret::random_from_rng(rand::thread_rng());
    let ephemeral_public = PublicKey::from(&ephemeral_secret);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient);

    // An all-zero shared secret means the recipient key was a low-order point,
    // which is either a corrupt registration or someone trying to force a
    // predictable key. `x25519-dalek` does not reject it for us because the
    // contributory-behaviour check belongs to the protocol, not the primitive.
    if !shared_secret.was_contributory() {
        return Err(EnclaveError::BadRequest(
            "the registered encryption key is a low-order point and cannot receive a sealed result"
                .into(),
        ));
    }

    let mut info = Vec::with_capacity(SEAL_TO_DEVICE_SCHEME.len() + 64);
    info.extend_from_slice(SEAL_TO_DEVICE_SCHEME.as_bytes());
    info.extend_from_slice(ephemeral_public.as_bytes());
    info.extend_from_slice(recipient.as_bytes());

    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared_secret.as_bytes())
        .expand(&info, &mut key)
        .map_err(|e| EnclaveError::Internal(format!("hkdf expand failed: {e}")))?;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let ciphertext = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| EnclaveError::Internal(format!("aes key rejected: {e}")))?
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: SEAL_TO_DEVICE_SCHEME.as_bytes(),
            },
        )
        .map_err(|_| EnclaveError::Internal("sealing to the device failed".into()))?;

    Ok(SealedToDevice {
        scheme: SEAL_TO_DEVICE_SCHEME.to_string(),
        recipient_key_id: recipient_key_id.to_string(),
        ephemeral_public_key_b64: B64.encode(ephemeral_public.as_bytes()),
        nonce_b64: B64.encode(nonce_bytes),
        ciphertext_b64: B64.encode(&ciphertext),
    })
}

/// The recipient's half, as the device performs it.
///
/// Lives here and is compiled in every build because the alternative is a test
/// that checks the ciphertext is not the plaintext -- which is the assertion
/// that passes whatever the construction does. The real recipients are the MCP
/// client and the browser; this is the executable statement of what they have
/// to implement, and the thing their outputs can be checked against.
pub fn open_as_device(
    recipient_secret: &[u8; 32],
    sealed: &SealedToDevice,
) -> Result<Vec<u8>, EnclaveError> {
    use x25519_dalek::StaticSecret;

    if sealed.scheme != SEAL_TO_DEVICE_SCHEME {
        return Err(EnclaveError::BadRequest(format!(
            "unknown sealing scheme {:?}",
            sealed.scheme
        )));
    }
    let decode = |label: &str, value: &str| {
        B64.decode(value.as_bytes())
            .map_err(|e| EnclaveError::BadRequest(format!("{label} is not base64: {e}")))
    };
    let ephemeral: [u8; 32] = decode("ephemeral_public_key_b64", &sealed.ephemeral_public_key_b64)?
        .try_into()
        .map_err(|_| EnclaveError::BadRequest("the ephemeral public key is not 32 bytes".into()))?;
    let nonce = decode("nonce_b64", &sealed.nonce_b64)?;
    let ciphertext = decode("ciphertext_b64", &sealed.ciphertext_b64)?;

    let secret = StaticSecret::from(*recipient_secret);
    let recipient_public = PublicKey::from(&secret);
    let shared_secret = secret.diffie_hellman(&PublicKey::from(ephemeral));

    let mut info = Vec::new();
    info.extend_from_slice(SEAL_TO_DEVICE_SCHEME.as_bytes());
    info.extend_from_slice(&ephemeral);
    info.extend_from_slice(recipient_public.as_bytes());

    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, shared_secret.as_bytes())
        .expand(&info, &mut key)
        .map_err(|e| EnclaveError::Internal(format!("hkdf expand failed: {e}")))?;

    Aes256Gcm::new_from_slice(&key)
        .map_err(|e| EnclaveError::Internal(format!("aes key rejected: {e}")))?
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: SEAL_TO_DEVICE_SCHEME.as_bytes(),
            },
        )
        .map_err(|_| EnclaveError::BadRequest("this blob was not sealed to this device".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    fn device() -> ([u8; 32], Vec<u8>) {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret).as_bytes().to_vec();
        (secret.to_bytes(), public)
    }

    #[test]
    fn the_device_it_was_sealed_to_can_open_it() {
        let (secret, public) = device();
        let sealed = seal_to_device(&public, "key-1", b"assembled answer").unwrap();
        assert_eq!(sealed.scheme, SEAL_TO_DEVICE_SCHEME);
        assert_eq!(sealed.recipient_key_id, "key-1");
        assert_eq!(
            open_as_device(&secret, &sealed).unwrap(),
            b"assembled answer"
        );
    }

    #[test]
    fn another_device_cannot() {
        // The property the whole ADR rests on. A leaked grant names a device,
        // so the answer comes back readable by that device and nothing else.
        let (_, public) = device();
        let (other_secret, _) = device();
        let sealed = seal_to_device(&public, "key-1", b"assembled answer").unwrap();
        assert!(open_as_device(&other_secret, &sealed).is_err());
    }

    #[test]
    fn two_seals_of_one_plaintext_share_nothing() {
        // Ephemeral per reply: a repeated ciphertext would tell the host that
        // two agents got the same answer, which is content it is not entitled
        // to infer.
        let (_, public) = device();
        let a = seal_to_device(&public, "key-1", b"same answer").unwrap();
        let b = seal_to_device(&public, "key-1", b"same answer").unwrap();
        assert_ne!(a.ephemeral_public_key_b64, b.ephemeral_public_key_b64);
        assert_ne!(a.nonce_b64, b.nonce_b64);
        assert_ne!(a.ciphertext_b64, b.ciphertext_b64);
    }

    #[test]
    fn a_tampered_ciphertext_is_refused_rather_than_mangled() {
        // AEAD rather than a stream cipher, so a host that flips a bit in
        // transit produces a refusal and not a differently-worded memory.
        let (secret, public) = device();
        let mut sealed = seal_to_device(&public, "key-1", b"assembled answer").unwrap();
        let mut bytes = B64.decode(sealed.ciphertext_b64.as_bytes()).unwrap();
        bytes[0] ^= 1;
        sealed.ciphertext_b64 = B64.encode(&bytes);
        assert!(open_as_device(&secret, &sealed).is_err());
    }

    #[test]
    fn swapping_the_ephemeral_key_is_refused() {
        // Both public keys are in the HKDF info, so an ephemeral key from
        // another reply derives a different key and fails the tag.
        let (secret, public) = device();
        let mut sealed = seal_to_device(&public, "key-1", b"assembled answer").unwrap();
        let other = seal_to_device(&public, "key-1", b"assembled answer").unwrap();
        sealed.ephemeral_public_key_b64 = other.ephemeral_public_key_b64;
        assert!(open_as_device(&secret, &sealed).is_err());
    }

    #[test]
    fn a_wrongly_sized_recipient_key_is_a_bad_request() {
        // A registration is length-checked at the gateway, so reaching here
        // with the wrong size means something upstream is confused -- better a
        // named refusal than a panic inside the TEE.
        assert!(seal_to_device(&[0u8; 31], "key-1", b"x").is_err());
    }

    #[test]
    fn a_low_order_recipient_key_is_refused() {
        // All-zero is the canonical low-order point: the agreement yields a
        // predictable shared secret, so the ciphertext would be readable by
        // anyone who noticed. Refused rather than sealed.
        assert!(seal_to_device(&[0u8; 32], "key-1", b"x").is_err());
    }

    #[test]
    fn an_unknown_scheme_is_refused_rather_than_attempted() {
        let (secret, public) = device();
        let mut sealed = seal_to_device(&public, "key-1", b"x").unwrap();
        sealed.scheme = "KLEOS_X25519_AES256GCM_V2".into();
        assert!(open_as_device(&secret, &sealed).is_err());
    }
}
