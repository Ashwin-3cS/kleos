//! Verifier tests (ADR 0026), against a chain the test builds itself.
//!
//! A real Nitro document cannot be produced without real hardware, and the
//! published AWS root is not in this repository, so the happy path here runs
//! on a synthetic P-384 chain through `Policy::with_root_unchecked`. What that
//! covers is everything except the pin itself: CBOR and COSE parsing, the
//! algorithm check, the chain walk, validity windows, the signature over
//! `Sig_structure`, freshness, PCR0 and key binding. The pin is tested
//! separately, by the digest of bytes that are not the root.

#![cfg(feature = "attestation-verify")]

use std::str::FromStr;
use std::time::Duration;

use ciborium::value::Value;
use p384::ecdsa::{DerSignature, SigningKey};
use shared::attestation::{
    commitment, purpose, verify, AttestationError, Policy, Trust, Verified, MOCK_PREFIX,
    NITRO_ROOT_SHA256,
};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::der::{Decode, Encode};
use x509_cert::spki::EncodePublicKey;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use x509_cert::Certificate;

/// The real clock, because `Validity::from_now` builds the test chain against
/// it: a fixed instant here would be outside the certificates' window the day
/// after it was chosen.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_millis() as u64
}

struct Chain {
    root_der: Vec<u8>,
    leaf_der: Vec<u8>,
    leaf_key: SigningKey,
}

fn signing_key() -> SigningKey {
    SigningKey::random(&mut rand::thread_rng())
}

fn spki(key: &SigningKey) -> SubjectPublicKeyInfoOwned {
    let der = key
        .verifying_key()
        .to_public_key_der()
        .expect("verifying key to DER");
    SubjectPublicKeyInfoOwned::from_der(der.as_bytes()).expect("SPKI from DER")
}

/// A root and a leaf signed by it, both P-384, both valid around `now_ms()`.
fn chain() -> Chain {
    let root_key = signing_key();
    let leaf_key = signing_key();
    let validity = Validity::from_now(Duration::from_secs(10 * 365 * 86_400)).expect("validity");

    let root_name = Name::from_str("CN=aws.nitro-enclaves,C=US,O=Amazon,OU=AWS").expect("name");
    let root: Certificate = CertificateBuilder::new(
        Profile::Root,
        SerialNumber::from(1u32),
        validity,
        root_name.clone(),
        spki(&root_key),
        &root_key,
    )
    .expect("root builder")
    .build::<DerSignature>()
    .expect("root cert");

    let leaf_name = Name::from_str("CN=i-0123456789abcdef.eu-west-1.aws.nitro-enclaves")
        .expect("leaf name");
    let leaf: Certificate = CertificateBuilder::new(
        Profile::Leaf {
            issuer: root_name,
            enable_key_agreement: false,
            enable_key_encipherment: false,
        },
        SerialNumber::from(2u32),
        validity,
        leaf_name,
        spki(&leaf_key),
        &root_key,
    )
    .expect("leaf builder")
    .build::<DerSignature>()
    .expect("leaf cert");

    Chain {
        root_der: root.to_der().expect("root DER"),
        leaf_der: leaf.to_der().expect("leaf DER"),
        leaf_key,
    }
}

struct Doc {
    timestamp_ms: u64,
    pcr0: Vec<u8>,
    public_key: Option<Vec<u8>>,
    alg: i64,
    cabundle: Vec<Vec<u8>>,
}

impl Doc {
    fn new(chain: &Chain) -> Self {
        Self {
            timestamp_ms: now_ms(),
            pcr0: vec![0xAB; 48],
            public_key: Some(vec![7u8; 32]),
            alg: -35,
            cabundle: vec![chain.root_der.clone()],
        }
    }
}

/// Encodes and signs a COSE_Sign1 the way the Nitro hypervisor does: tagged 18,
/// ES384 in the protected header, signature over the `Sig_structure`.
fn document(chain: &Chain, doc: &Doc) -> String {
    let mut payload_fields = vec![
        (
            Value::Text("module_id".into()),
            Value::Text("i-0123456789abcdef-enc0123456789".into()),
        ),
        (
            Value::Text("timestamp".into()),
            Value::Integer(doc.timestamp_ms.into()),
        ),
        (Value::Text("digest".into()), Value::Text("SHA384".into())),
        (
            Value::Text("pcrs".into()),
            Value::Map(vec![(Value::Integer(0.into()), Value::Bytes(doc.pcr0.clone()))]),
        ),
        (
            Value::Text("certificate".into()),
            Value::Bytes(chain.leaf_der.clone()),
        ),
        (
            Value::Text("cabundle".into()),
            Value::Array(doc.cabundle.iter().cloned().map(Value::Bytes).collect()),
        ),
    ];
    if let Some(pk) = &doc.public_key {
        payload_fields.push((Value::Text("public_key".into()), Value::Bytes(pk.clone())));
    }

    let mut payload = Vec::new();
    ciborium::ser::into_writer(&Value::Map(payload_fields), &mut payload).expect("payload");

    let mut protected = Vec::new();
    ciborium::ser::into_writer(
        &Value::Map(vec![(Value::Integer(1.into()), Value::Integer(doc.alg.into()))]),
        &mut protected,
    )
    .expect("protected header");

    let mut signed = Vec::new();
    ciborium::ser::into_writer(
        &Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(protected.clone()),
            Value::Bytes(Vec::new()),
            Value::Bytes(payload.clone()),
        ]),
        &mut signed,
    )
    .expect("Sig_structure");

    let signature: p384::ecdsa::Signature =
        p384::ecdsa::signature::Signer::sign(&chain.leaf_key, &signed);

    let mut cose = Vec::new();
    ciborium::ser::into_writer(
        &Value::Tag(
            18,
            Box::new(Value::Array(vec![
                Value::Bytes(protected),
                Value::Map(Vec::new()),
                Value::Bytes(payload),
                Value::Bytes(signature.to_bytes().to_vec()),
            ])),
        ),
        &mut cose,
    )
    .expect("COSE_Sign1");

    hex::encode(cose)
}

/// The refusal, or a failure naming what verified instead. `Verified` has no
/// `PartialEq` on purpose -- nothing should be comparing whole verdicts.
fn refusal(result: Result<Verified, AttestationError>) -> AttestationError {
    match result {
        Err(e) => e,
        Ok(v) => panic!("expected a refusal, got {:?}", v.trust),
    }
}

fn policy(chain: &Chain) -> Policy {
    Policy::with_root_unchecked(chain.root_der.clone())
}

#[test]
fn a_well_formed_document_verifies_as_signed_by_aws() {
    let chain = chain();
    let doc = Doc::new(&chain);
    let hex_doc = document(&chain, &doc);
    let verified = verify(&hex_doc, &policy(&chain), now_ms()).expect("verifies");
    assert_eq!(verified.trust, Trust::SignedByAws);
    assert_eq!(verified.module_id, "i-0123456789abcdef-enc0123456789");
    assert_eq!(verified.timestamp_ms, doc.timestamp_ms);
    assert_eq!(verified.pcr0(), Some(&[0xABu8; 48][..]));
}

#[test]
fn an_expected_measurement_that_matches_is_pinned() {
    let chain = chain();
    let doc = Doc::new(&chain);
    let hex_doc = document(&chain, &doc);
    let mut p = policy(&chain);
    p.expected_pcr0 = Some(doc.pcr0.clone());
    assert_eq!(
        verify(&hex_doc, &p, now_ms()).expect("verifies").trust,
        Trust::Pinned
    );
}

#[test]
fn a_different_measurement_is_refused_rather_than_downgraded() {
    // The attack ADR 0026 is about: a real enclave running an image we did not
    // build. The chain verifies; the measurement does not match; the answer is
    // a refusal and not `SignedByAws`.
    let chain = chain();
    let hex_doc = document(&chain, &Doc::new(&chain));
    let mut p = policy(&chain);
    p.expected_pcr0 = Some(vec![0x01; 48]);
    assert_eq!(
        refusal(verify(&hex_doc, &p, now_ms())),
        AttestationError::MeasurementMismatch
    );
}

#[test]
fn a_tampered_payload_fails_the_signature() {
    let chain = chain();
    let hex_doc = document(&chain, &Doc::new(&chain));
    let mut raw = hex::decode(&hex_doc).expect("hex");
    // Flip a byte inside the payload. The COSE signature covers it.
    let middle = raw.len() / 2;
    raw[middle] ^= 0xFF;
    let result = verify(&hex::encode(raw), &policy(&chain), now_ms());
    assert!(result.is_err(), "a tampered document must not verify");
}

#[test]
fn a_leaf_signed_by_somebody_else_breaks_the_chain() {
    let ours = chain();
    let theirs = chain();
    // Their leaf, their key, our root in the bundle: the chain walk is what
    // catches it, because the leaf was not signed by the root we trust.
    let doc = Doc {
        cabundle: vec![ours.root_der.clone()],
        ..Doc::new(&theirs)
    };
    let hex_doc = document(&theirs, &doc);
    assert_eq!(
        refusal(verify(&hex_doc, &policy(&ours), now_ms())),
        AttestationError::BrokenChain(1)
    );
}

#[test]
fn a_bundle_that_does_not_start_with_our_root_is_refused() {
    let ours = chain();
    let theirs = chain();
    let hex_doc = document(&theirs, &Doc::new(&theirs));
    assert_eq!(
        refusal(verify(&hex_doc, &policy(&ours), now_ms())),
        AttestationError::RootNotInBundle
    );
}

#[test]
fn an_algorithm_other_than_es384_is_refused() {
    let chain = chain();
    let doc = Doc {
        alg: -7, // ES256
        ..Doc::new(&chain)
    };
    let hex_doc = document(&chain, &doc);
    assert_eq!(
        refusal(verify(&hex_doc, &policy(&chain), now_ms())),
        AttestationError::UnsupportedAlgorithm(-7)
    );
}

#[test]
fn a_stale_document_is_refused_when_a_limit_is_set() {
    let chain = chain();
    let hex_doc = document(&chain, &Doc::new(&chain));
    let mut p = policy(&chain);
    p.max_age_ms = 60_000;
    let later = now_ms() + 120_000;
    assert!(matches!(
        verify(&hex_doc, &p, later),
        Err(AttestationError::Stale { .. })
    ));
    // ...and accepted inside the window.
    assert!(verify(&hex_doc, &p, now_ms() + 30_000).is_ok());
}

#[test]
fn a_document_from_the_future_is_refused() {
    let chain = chain();
    let doc = Doc {
        timestamp_ms: now_ms() + 600_000,
        ..Doc::new(&chain)
    };
    let hex_doc = document(&chain, &doc);
    let mut p = policy(&chain);
    p.max_age_ms = 60_000;
    assert!(matches!(
        verify(&hex_doc, &p, now_ms()),
        Err(AttestationError::Stale { .. })
    ));
}

#[test]
fn an_expired_certificate_is_refused() {
    let chain = chain();
    let hex_doc = document(&chain, &Doc::new(&chain));
    // Twenty years on, the ten-year chain is dead.
    let far_future = now_ms() + 20 * 365 * 86_400 * 1000;
    assert!(matches!(
        verify(&hex_doc, &policy(&chain), far_future),
        Err(AttestationError::CertificateExpired(_))
    ));
}

#[test]
fn key_binding_is_what_makes_it_about_the_data() {
    let chain = chain();
    let doc = Doc::new(&chain);
    let hex_doc = document(&chain, &doc);
    let verified = verify(&hex_doc, &policy(&chain), now_ms()).expect("verifies");
    assert!(verified.binds_key(&[7u8; 32]));
    assert!(!verified.binds_key(&[8u8; 32]));
}

#[test]
fn a_document_committing_to_no_key_binds_nothing() {
    let chain = chain();
    let doc = Doc {
        public_key: None,
        ..Doc::new(&chain)
    };
    let hex_doc = document(&chain, &doc);
    let verified = verify(&hex_doc, &policy(&chain), now_ms()).expect("verifies");
    assert!(!verified.binds_key(&[7u8; 32]));
    assert!(!verified.binds_key(&[]));
}

#[test]
fn a_mock_is_refused_unless_mocks_are_allowed() {
    let chain = chain();
    let mock = format!("{MOCK_PREFIX}{}", hex::encode([7u8; 32]));
    assert_eq!(
        refusal(verify(&mock, &policy(&chain), now_ms())),
        AttestationError::MockNotAllowed
    );
    let verified = verify(&mock, &Policy::mock_only(), now_ms()).expect("mock verifies");
    assert_eq!(verified.trust, Trust::Mock);
    assert!(verified.binds_key(&[7u8; 32]));
}

#[test]
fn a_mock_never_reaches_a_stronger_verdict() {
    // Even with an expected measurement configured, a mock is a mock. The
    // prefix stopped being a comment the moment this held.
    let mock = format!("{MOCK_PREFIX}{}", hex::encode([7u8; 32]));
    let mut p = Policy::mock_only();
    p.expected_pcr0 = Some(vec![0xAB; 48]);
    let verified = verify(&mock, &p, now_ms()).expect("mock verifies");
    assert_eq!(verified.trust, Trust::Mock);
    assert!(!verified.trust.at_least(Trust::SignedByAws));
}

#[test]
fn a_real_document_is_refused_when_no_root_is_configured() {
    let chain = chain();
    let hex_doc = document(&chain, &Doc::new(&chain));
    assert_eq!(
        refusal(verify(&hex_doc, &Policy::mock_only(), now_ms())),
        AttestationError::NoRootConfigured
    );
}

#[test]
fn the_pinned_fingerprint_rejects_a_certificate_that_is_not_the_aws_root() {
    let chain = chain();
    assert_eq!(
        Policy::with_root(chain.root_der.clone()).err(),
        Some(AttestationError::RootFingerprintMismatch)
    );
    assert_eq!(
        Policy::with_root(Vec::new()).err(),
        Some(AttestationError::NoRootConfigured)
    );
    // The constant is the published fingerprint, byte for byte.
    assert_eq!(
        hex::encode_upper(NITRO_ROOT_SHA256),
        "641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B"
    );
}

#[test]
fn the_commitment_matches_the_python_vector() {
    // The one cross-language check that matters. `commitment` is *computed* on
    // both sides -- the enclave writes it here, the device and the orchestrator
    // recompute it -- so a disagreement is not a verification that fails but
    // one that passes on one side only. Same vector in
    // `orchestrator/tests/test_attestation.py::test_commitment_matches_the_rust_vector`.
    let digest = commitment(purpose::ASSEMBLE, &[b"\x01\x02", b"key-id", b"ciphertext"]);
    assert_eq!(hex::encode(digest), "ad50054e35c925b99d0323219d2b90b0caf93e95680609f397baec68c6e9b5dbb03101c5dae1a1afa3e0460236f5d678");
}

#[test]
fn the_commitment_is_unambiguous_about_where_the_parts_divide() {
    // Length-prefixing, which the concatenation this replaced did not have:
    // `pk || key_id || ciphertext` can be re-split at a different boundary to
    // give the same bytes from different parts.
    assert_ne!(commitment("p", &[b"ab", b"c"]), commitment("p", &[b"a", b"bc"]));
    assert_ne!(commitment("p", &[b"abc"]), commitment("p", &[b"ab", b"c"]));
}

#[test]
fn the_purpose_is_inside_the_commitment() {
    // So a document produced for a sealed field cannot be replayed as one
    // produced for an assembly.
    let parts: [&[u8]; 2] = [b"pk", b"key-id"];
    assert_ne!(
        commitment(purpose::ASSEMBLE, &parts),
        commitment(purpose::SEAL_ENCRYPT, &parts)
    );
}

#[test]
fn garbage_is_refused_without_panicking() {
    let chain = chain();
    let p = policy(&chain);
    for junk in ["", "zz", "00", "deadbeef", MOCK_PREFIX] {
        assert!(verify(junk, &p, now_ms()).is_err(), "{junk:?} must not verify");
    }
}
