//! What the enclave seals, this device opens.
//!
//! The point of this crate is to be the implementation an MCP client and a
//! browser are checked against, so its `open_as_device` is written out rather
//! than imported from the enclave. That makes a round trip the only thing that
//! proves the two agree: a test against this crate's own sealing would prove
//! only that it is self-consistent, which is exactly the failure mode a second
//! implementation exists to catch.

use device::{encryption_secret, open_as_device};
use enclave::services::recipient::seal_to_device;
use x25519_dalek::PublicKey;

/// Any 32 bytes stand in for a device's private key file.
const PRIVATE: &[u8] = b"a device private key, 32 bytes!!";

#[test]
fn the_device_opens_what_the_enclave_sealed() {
    let secret = encryption_secret(PRIVATE);
    let public = PublicKey::from(&secret);
    let message = b"project Lantern will use Neo4j for durable storage.";

    let sealed = seal_to_device(public.as_bytes(), "key-1", message).unwrap();
    let opened = open_as_device(&secret, &sealed).unwrap();

    assert_eq!(opened, message);
}

#[test]
fn another_device_cannot_open_it() {
    // The property the whole of ADR 0024 rests on: an answer sealed to one
    // device is unreadable by any other, including the host that relayed it.
    let mine = encryption_secret(PRIVATE);
    let theirs = encryption_secret(b"a different device key, 32 bytes");
    let sealed = seal_to_device(PublicKey::from(&mine).as_bytes(), "key-1", b"secret").unwrap();

    let opened = open_as_device(&theirs, &sealed);

    assert!(opened.is_err(), "a blob opened by the wrong device");
}

#[test]
fn the_derived_key_is_stable_and_specific_to_the_signing_key() {
    // Stable, because a device that derived a different key each run could
    // never read an answer sealed a moment earlier. Specific, because two
    // devices sharing a receiving key would read each other's answers.
    let once = encryption_secret(PRIVATE);
    let again = encryption_secret(PRIVATE);
    let other = encryption_secret(b"a different device key, 32 bytes");

    assert_eq!(PublicKey::from(&once).as_bytes(), PublicKey::from(&again).as_bytes());
    assert_ne!(PublicKey::from(&once).as_bytes(), PublicKey::from(&other).as_bytes());
    // And it is a derivation, not the signing key reinterpreted: the receiving
    // key must not be the Ed25519 private bytes under another name.
    assert_ne!(PublicKey::from(&once).as_bytes().as_slice(), PRIVATE);
}

#[test]
fn a_tampered_blob_is_refused_rather_than_mis_decrypted() {
    let secret = encryption_secret(PRIVATE);
    let mut sealed =
        seal_to_device(PublicKey::from(&secret).as_bytes(), "key-1", b"the answer").unwrap();
    // The scheme string is the AEAD's additional data, so changing it has to
    // fail rather than silently decrypt under a different label.
    sealed.scheme = "KLEOS_SOMETHING_ELSE".into();

    assert!(open_as_device(&secret, &sealed).is_err());
}
