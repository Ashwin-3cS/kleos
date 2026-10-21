//! Verifying a Nitro attestation document (ADR 0026).
//!
//! Five enclave routes produce one of these and every one of them was, until
//! this module existed, a string nobody read. The consequence was not subtle:
//! an operator who swapped the enclave for an HTTP service that permits
//! everything and answers `"MOCK_ATTESTATION_"` would pass every test in this
//! repository, which makes ADR 0022's brokered actions and ADR 0024's
//! assemble-and-reseal claims unfalsifiable.
//!
//! Three things about the shape, all of them ADR 0026:
//!
//! **It returns what verified, not whether it verified.** A `bool` would let
//! "signed by the AWS Nitro PKI" stand in for "signed by *our* enclave image",
//! and the distance between those two is the whole attack: any Nitro enclave on
//! earth produces a document that chains to the AWS root, including one running
//! an image the operator built this morning. Only PCR0 separates them, so the
//! outcome is a [`Trust`] and a caller that needs [`Trust::Pinned`] asks for it.
//!
//! **It binds the document to a key, or it establishes nothing.** A verified
//! document says some enclave attested to some public key at some time. Whether
//! that key is the one that sealed the thing in front of you is a separate
//! check, and [`Verified::binds_key`] is it. Freshness is the same argument:
//! a replayed document from a decommissioned enclave verifies perfectly.
//!
//! **The root certificate's fingerprint is pinned here; the certificate is
//! not.** Embedding the DER looks stronger and is weaker, because a reviewer
//! cannot tell correct certificate bytes from incorrect ones, whereas
//! [`NITRO_ROOT_SHA256`] is one line to check against one line of AWS
//! documentation. A wrong certificate becomes a startup error instead of a
//! chain that verifies to the wrong root.
//!
//! Deliberately not enabled in the enclave's own build: it has no reason to
//! verify its own document, and `services/actions.rs` is explicit that an
//! attestation is worth what the image it measures is small enough to audit.

#[cfg(feature = "attestation-verify")]
use sha2::Sha256;
use sha2::{Digest, Sha384};

#[cfg(feature = "attestation-verify")]
use std::collections::BTreeMap;

#[cfg(feature = "attestation-verify")]
use ciborium::value::Value;
#[cfg(feature = "attestation-verify")]
use p384::ecdsa::signature::Verifier;
#[cfg(feature = "attestation-verify")]
use p384::ecdsa::{Signature, VerifyingKey};
#[cfg(feature = "attestation-verify")]
use x509_cert::der::{Decode, Encode};
#[cfg(feature = "attestation-verify")]
use x509_cert::Certificate;

/// Domain separation for [`commitment`]. Bumped if the layout below changes.
const COMMITMENT_DOMAIN: &[u8] = b"KLEOS_ATTEST_V1";

/// The names of the things an enclave route commits to. One per route, so a
/// document produced for an assembly cannot be replayed as one produced for a
/// sealed field: the purpose is inside the digest.
pub mod purpose {
    pub const ASSEMBLE: &str = "assemble";
    pub const IDENTITY: &str = "identity";
    pub const OAUTH: &str = "oauth";
    pub const SEAL_ENCRYPT: &str = "seal_encrypt";
    pub const ATTEST_DIGEST: &str = "attest_digest";
}

/// What an enclave route puts in a document's `public_key` field: SHA-384 over
/// a purpose and a list of length-prefixed parts.
///
/// Two reasons it is a digest and not the parts themselves, and the first is a
/// bug this replaces.
///
/// **NSM caps `public_key` at 1024 bytes.** `assemble` was committing the
/// enclave key, the recipient key id *and the whole base64 ciphertext*, which
/// for a real answer is several kilobytes -- so that route would have been
/// refused by the NSM driver the first time it ran on real hardware, and the
/// mock path could never have shown it. A digest is 48 bytes whatever it covers.
///
/// **Concatenation is ambiguous.** `pk || key_id || ciphertext` can be re-split
/// at a different boundary to produce the same bytes from different parts, so
/// the commitment did not uniquely determine what it committed to. Each part is
/// length-prefixed here, and the purpose is mixed in first.
pub fn commitment(purpose: &str, parts: &[&[u8]]) -> [u8; 48] {
    let mut hasher = Sha384::new();
    hasher.update(COMMITMENT_DOMAIN);
    hasher.update((purpose.len() as u64).to_be_bytes());
    hasher.update(purpose.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    let out = hasher.finalize();
    let mut bytes = [0u8; 48];
    bytes.copy_from_slice(&out);
    bytes
}

/// The prefix `enclave/src/services/attestation.rs` puts on a mock document.
pub const MOCK_PREFIX: &str = "MOCK_ATTESTATION_";

/// SHA-256 of the DER of the AWS Nitro Enclaves root certificate, as published
/// at <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>:
///
/// ```text
/// 64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B
/// ```
pub const NITRO_ROOT_SHA256: [u8; 32] = [
    0x64, 0x1A, 0x03, 0x21, 0xA3, 0xE2, 0x44, 0xEF, 0xE4, 0x56, 0x46, 0x31, 0x95, 0xD6, 0x06, 0x31,
    0x7E, 0xD7, 0xCD, 0xCC, 0x3C, 0x17, 0x56, 0xE0, 0x98, 0x93, 0xF3, 0xC6, 0x8F, 0x79, 0xBB, 0x5B,
];

#[cfg(feature = "attestation-verify")]
/// COSE algorithm id for ECDSA with SHA-384, the only one a Nitro document uses.
const COSE_ALG_ES384: i64 = -35;

/// What a verification established. Ordered weakest to strongest, and compared
/// as such -- see [`Trust::at_least`].
#[cfg(feature = "attestation-verify")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Trust {
    /// A mock stub, and the policy allowed mocks. Says nothing about anything.
    Mock,
    /// The chain verifies to the pinned AWS Nitro root. Excludes a host process
    /// pretending to be an enclave; does not exclude an enclave the operator
    /// built.
    SignedByAws,
    /// ...and PCR0 matches a measurement the caller expected.
    Pinned,
}

#[cfg(feature = "attestation-verify")]
impl Trust {
    pub fn at_least(self, floor: Trust) -> bool {
        self >= floor
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Trust::Mock => "mock",
            Trust::SignedByAws => "signed_by_aws",
            Trust::Pinned => "pinned",
        }
    }
}

/// Every way this refuses. Enumerated rather than stringly-typed because the
/// Python mirror has to refuse for the same reasons by the same names (ADR
/// 0026), and a message is not a contract.
#[cfg(feature = "attestation-verify")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationError {
    /// A mock document arrived and the policy did not allow mocks. The common
    /// one in production, and the point of the prefix.
    MockNotAllowed,
    /// No root certificate was configured, so nothing could be checked against.
    NoRootConfigured,
    /// The configured root does not hash to [`NITRO_ROOT_SHA256`].
    RootFingerprintMismatch,
    NotHex,
    MalformedCbor(&'static str),
    /// The protected header asked for an algorithm that is not ES384.
    UnsupportedAlgorithm(i64),
    MissingField(&'static str),
    /// The document's `cabundle` does not start with the configured root.
    RootNotInBundle,
    /// A certificate in the chain was not signed by the one above it.
    BrokenChain(usize),
    /// A certificate in the chain is not yet valid or has expired.
    CertificateExpired(usize),
    /// The COSE signature does not verify under the leaf certificate's key.
    BadSignature,
    /// The document is older than the policy allows, or dated in the future.
    Stale { age_ms: i64, max_age_ms: u64 },
    /// PCR0 was required and did not match.
    MeasurementMismatch,
}

#[cfg(feature = "attestation-verify")]
impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MockNotAllowed => write!(
                f,
                "this is a mock attestation and mocks are not allowed here. \
                 Set allow_mock only for local runs."
            ),
            Self::NoRootConfigured => write!(
                f,
                "no Nitro root certificate configured, so there is nothing to \
                 verify against. Fetch AWS_NitroEnclaves_Root-G1 and point the \
                 config at it."
            ),
            Self::RootFingerprintMismatch => write!(
                f,
                "the configured root certificate does not match the published \
                 AWS fingerprint"
            ),
            Self::NotHex => write!(f, "the document is not hex"),
            Self::MalformedCbor(what) => write!(f, "malformed CBOR: {what}"),
            Self::UnsupportedAlgorithm(alg) => {
                write!(f, "unsupported COSE algorithm {alg}; a Nitro document is ES384")
            }
            Self::MissingField(name) => write!(f, "the document has no {name}"),
            Self::RootNotInBundle => write!(
                f,
                "the document's CA bundle does not start with the configured root"
            ),
            Self::BrokenChain(i) => {
                write!(f, "certificate {i} in the chain was not signed by the one above it")
            }
            Self::CertificateExpired(i) => {
                write!(f, "certificate {i} in the chain is outside its validity period")
            }
            Self::BadSignature => write!(f, "the COSE signature does not verify"),
            Self::Stale { age_ms, max_age_ms } => write!(
                f,
                "the document is {age_ms}ms old and the limit is {max_age_ms}ms"
            ),
            Self::MeasurementMismatch => {
                write!(f, "PCR0 does not match the expected measurement")
            }
        }
    }
}

#[cfg(feature = "attestation-verify")]
impl std::error::Error for AttestationError {}

/// What a verifier is willing to accept. Deny-by-default in the sense that
/// matters: `allow_mock` is off, `root_der` is empty, and both have to be
/// turned on by configuration rather than defaulted into existence.
#[cfg(feature = "attestation-verify")]
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// DER of the AWS Nitro root certificate, checked against
    /// [`NITRO_ROOT_SHA256`] before it is used.
    pub root_der: Vec<u8>,
    /// The expected measurement of our own enclave image. `None` caps the
    /// outcome at [`Trust::SignedByAws`], which is the honest state until an
    /// `.eif` has been built on real hardware.
    pub expected_pcr0: Option<Vec<u8>>,
    /// How old a document may be. A document is a statement about the past.
    pub max_age_ms: u64,
    pub allow_mock: bool,
}

#[cfg(feature = "attestation-verify")]
impl Policy {
    /// A local-development policy: mocks allowed, nothing else is.
    pub fn mock_only() -> Self {
        Self {
            allow_mock: true,
            max_age_ms: 0,
            ..Default::default()
        }
    }

    /// A policy trusting `root_der`, refused unless it hashes to
    /// [`NITRO_ROOT_SHA256`].
    ///
    /// The digest is checked here and not in [`verify`] on purpose: a wrong
    /// certificate should be a startup error, not a per-document refusal that
    /// looks like a bad document.
    pub fn with_root(root_der: Vec<u8>) -> Result<Self, AttestationError> {
        if root_der.is_empty() {
            return Err(AttestationError::NoRootConfigured);
        }
        if Sha256::digest(&root_der).as_slice() != NITRO_ROOT_SHA256 {
            return Err(AttestationError::RootFingerprintMismatch);
        }
        Ok(Self {
            root_der,
            ..Default::default()
        })
    }

    /// A policy trusting `root_der` without checking its fingerprint.
    ///
    /// Two legitimate callers and no others: the tests, which have to be able
    /// to build a chain they control, and a non-commercial AWS partition, whose
    /// Nitro root is a different certificate with a different published
    /// fingerprint from the one this crate pins.
    pub fn with_root_unchecked(root_der: Vec<u8>) -> Self {
        Self {
            root_der,
            ..Default::default()
        }
    }
}

/// What the document said, once it was established that it said it.
#[cfg(feature = "attestation-verify")]
#[derive(Debug, Clone)]
pub struct Verified {
    pub trust: Trust,
    pub module_id: String,
    pub timestamp_ms: u64,
    pub pcrs: BTreeMap<u8, Vec<u8>>,
    /// The `public_key` the document commits to.
    ///
    /// For a mock, this is whatever bytes the stub committed -- which is a key
    /// on `/attest` and is not one on the other routes. Harmless because
    /// `trust` is [`Trust::Mock`] and no caller can read strength into it.
    pub public_key: Option<Vec<u8>>,
    pub user_data: Option<Vec<u8>>,
}

#[cfg(feature = "attestation-verify")]
impl Verified {
    /// Whether this document commits to `key`.
    ///
    /// The step that makes verification mean anything about the data in front
    /// of the caller rather than about some enclave somewhere. Deliberately a
    /// method and not left to each call site, because the one call site that
    /// forgets it is the one that matters.
    pub fn binds_key(&self, key: &[u8]) -> bool {
        self.public_key.as_deref() == Some(key)
    }

    pub fn pcr0(&self) -> Option<&[u8]> {
        self.pcrs.get(&0).map(|v| v.as_slice())
    }
}

/// Verifies `document_hex` under `policy`, as of `now_ms`.
///
/// `now_ms` is a parameter rather than a clock read so the function stays pure
/// and total -- the same reason `permissions::evaluate` takes everything it
/// decides on. A test that cannot control time cannot test expiry.
#[cfg(feature = "attestation-verify")]
pub fn verify(
    document_hex: &str,
    policy: &Policy,
    now_ms: u64,
) -> Result<Verified, AttestationError> {
    if let Some(rest) = document_hex.strip_prefix(MOCK_PREFIX) {
        if !policy.allow_mock {
            return Err(AttestationError::MockNotAllowed);
        }
        return Ok(Verified {
            trust: Trust::Mock,
            module_id: "mock".to_string(),
            timestamp_ms: now_ms,
            pcrs: BTreeMap::new(),
            public_key: hex::decode(rest).ok(),
            user_data: None,
        });
    }

    if policy.root_der.is_empty() {
        return Err(AttestationError::NoRootConfigured);
    }
    let root = &policy.root_der;
    let raw = hex::decode(document_hex).map_err(|_| AttestationError::NotHex)?;

    let (protected, payload, signature) = cose_sign1(&raw)?;
    check_algorithm(&protected)?;

    let doc = cbor_map(&payload, "attestation document")?;
    let module_id = text(&doc, "module_id")?;
    let timestamp_ms = uint(&doc, "timestamp")?;
    let pcrs = pcr_map(&doc)?;
    let leaf_der = bytes_field(&doc, "certificate")?;
    let cabundle = cert_bundle(&doc)?;

    // AWS orders the bundle [root, intermediate_1, ... intermediate_n] and the
    // leaf arrives separately, so the chain to walk is the bundle followed by
    // the leaf -- each signed by the one before it.
    let mut chain: Vec<Certificate> = Vec::with_capacity(cabundle.len() + 1);
    for der in &cabundle {
        chain.push(parse_cert(der)?);
    }
    chain.push(parse_cert(&leaf_der)?);

    let bundle_root = cabundle.first().ok_or(AttestationError::MissingField("cabundle"))?;
    if bundle_root.as_slice() != root.as_slice() {
        return Err(AttestationError::RootNotInBundle);
    }

    verify_chain(&chain, now_ms)?;

    let leaf = chain.last().expect("chain has the leaf");
    verify_cose_signature(leaf, &protected, &payload, &signature)?;

    let age_ms = now_ms as i64 - timestamp_ms as i64;
    if policy.max_age_ms > 0 && (age_ms < 0 || age_ms as u64 > policy.max_age_ms) {
        return Err(AttestationError::Stale {
            age_ms,
            max_age_ms: policy.max_age_ms,
        });
    }

    let trust = match &policy.expected_pcr0 {
        None => Trust::SignedByAws,
        Some(expected) => {
            let actual = pcrs.get(&0).ok_or(AttestationError::MissingField("pcr0"))?;
            if actual != expected {
                return Err(AttestationError::MeasurementMismatch);
            }
            Trust::Pinned
        }
    };

    Ok(Verified {
        trust,
        module_id,
        timestamp_ms,
        pcrs,
        public_key: bytes_field(&doc, "public_key").ok(),
        user_data: bytes_field(&doc, "user_data").ok(),
    })
}

/// Splits a COSE_Sign1 into the three pieces a signature is computed over.
///
/// Tagged (CBOR tag 18) and untagged both occur; AWS emits the tagged form and
/// several tools strip it, so accepting either is not laxity.
/// The three pieces of a COSE_Sign1 that a signature is computed over:
/// protected header, payload, signature.
#[cfg(feature = "attestation-verify")]
type Sign1 = (Vec<u8>, Vec<u8>, Vec<u8>);

#[cfg(feature = "attestation-verify")]
fn cose_sign1(raw: &[u8]) -> Result<Sign1, AttestationError> {
    let value: Value = ciborium::de::from_reader(raw)
        .map_err(|_| AttestationError::MalformedCbor("not CBOR"))?;
    let array = match value {
        Value::Tag(18, inner) => match *inner {
            Value::Array(a) => a,
            _ => return Err(AttestationError::MalformedCbor("tag 18 is not an array")),
        },
        Value::Array(a) => a,
        _ => return Err(AttestationError::MalformedCbor("not a COSE_Sign1 array")),
    };
    if array.len() != 4 {
        return Err(AttestationError::MalformedCbor("COSE_Sign1 is not 4 elements"));
    }
    let protected = byte_string(&array[0], "protected header")?;
    let payload = byte_string(&array[2], "payload")?;
    let signature = byte_string(&array[3], "signature")?;
    Ok((protected, payload, signature))
}

#[cfg(feature = "attestation-verify")]
fn check_algorithm(protected: &[u8]) -> Result<(), AttestationError> {
    let header: Value = ciborium::de::from_reader(protected)
        .map_err(|_| AttestationError::MalformedCbor("protected header is not CBOR"))?;
    let Value::Map(entries) = header else {
        return Err(AttestationError::MalformedCbor("protected header is not a map"));
    };
    for (k, v) in entries {
        // COSE label 1 is `alg`.
        if let Value::Integer(label) = k {
            if i128::from(label) == 1 {
                let alg = match v {
                    Value::Integer(a) => i128::from(a) as i64,
                    _ => return Err(AttestationError::MalformedCbor("alg is not an integer")),
                };
                if alg != COSE_ALG_ES384 {
                    return Err(AttestationError::UnsupportedAlgorithm(alg));
                }
                return Ok(());
            }
        }
    }
    Err(AttestationError::MissingField("alg"))
}

/// Verifies the COSE signature over `Sig_structure`.
///
/// RFC 8152 §4.4: the signed bytes are the CBOR encoding of
/// `["Signature1", protected, external_aad, payload]`, with an empty
/// `external_aad`. Signing the payload alone would leave the protected header
/// unauthenticated, which is where the algorithm lives.
#[cfg(feature = "attestation-verify")]
fn verify_cose_signature(
    leaf: &Certificate,
    protected: &[u8],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), AttestationError> {
    let sig_structure = Value::Array(vec![
        Value::Text("Signature1".to_string()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]);
    let mut signed = Vec::new();
    ciborium::ser::into_writer(&sig_structure, &mut signed)
        .map_err(|_| AttestationError::MalformedCbor("could not re-encode Sig_structure"))?;

    let key = verifying_key(leaf)?;
    // COSE carries ECDSA as raw r||s, not the DER a certificate uses.
    let sig = Signature::from_slice(signature).map_err(|_| AttestationError::BadSignature)?;
    key.verify(&signed, &sig)
        .map_err(|_| AttestationError::BadSignature)
}

/// Walks the chain root-first, checking each certificate was signed by the one
/// above it and that every one of them is inside its validity period.
///
/// Revocation is deliberately not checked: AWS documents that CRLs must be
/// disabled for this chain.
#[cfg(feature = "attestation-verify")]
fn verify_chain(chain: &[Certificate], now_ms: u64) -> Result<(), AttestationError> {
    let now_secs = now_ms / 1000;
    for (i, cert) in chain.iter().enumerate() {
        let validity = &cert.tbs_certificate.validity;
        let not_before = validity.not_before.to_unix_duration().as_secs();
        let not_after = validity.not_after.to_unix_duration().as_secs();
        if now_secs < not_before || now_secs > not_after {
            return Err(AttestationError::CertificateExpired(i));
        }
    }
    for i in 1..chain.len() {
        let parent = verifying_key(&chain[i - 1])?;
        let child = &chain[i];
        let tbs = child
            .tbs_certificate
            .to_der()
            .map_err(|_| AttestationError::BrokenChain(i))?;
        let sig_bytes = child
            .signature
            .as_bytes()
            .ok_or(AttestationError::BrokenChain(i))?;
        let sig = p384::ecdsa::DerSignature::try_from(sig_bytes)
            .map_err(|_| AttestationError::BrokenChain(i))?;
        parent
            .verify(&tbs, &sig)
            .map_err(|_| AttestationError::BrokenChain(i))?;
    }
    Ok(())
}

#[cfg(feature = "attestation-verify")]
fn verifying_key(cert: &Certificate) -> Result<VerifyingKey, AttestationError> {
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or(AttestationError::BadSignature)?;
    VerifyingKey::from_sec1_bytes(point).map_err(|_| AttestationError::BadSignature)
}

#[cfg(feature = "attestation-verify")]
fn parse_cert(der: &[u8]) -> Result<Certificate, AttestationError> {
    Certificate::from_der(der).map_err(|_| AttestationError::MalformedCbor("not a certificate"))
}

#[cfg(feature = "attestation-verify")]
fn cbor_map(raw: &[u8], what: &'static str) -> Result<Vec<(Value, Value)>, AttestationError> {
    let value: Value =
        ciborium::de::from_reader(raw).map_err(|_| AttestationError::MalformedCbor(what))?;
    match value {
        Value::Map(entries) => Ok(entries),
        _ => Err(AttestationError::MalformedCbor(what)),
    }
}

#[cfg(feature = "attestation-verify")]
fn lookup<'a>(doc: &'a [(Value, Value)], key: &str) -> Option<&'a Value> {
    doc.iter().find_map(|(k, v)| match k {
        Value::Text(t) if t == key => Some(v),
        _ => None,
    })
}

#[cfg(feature = "attestation-verify")]
fn text(doc: &[(Value, Value)], key: &'static str) -> Result<String, AttestationError> {
    match lookup(doc, key) {
        Some(Value::Text(t)) => Ok(t.clone()),
        _ => Err(AttestationError::MissingField(key)),
    }
}

#[cfg(feature = "attestation-verify")]
fn uint(doc: &[(Value, Value)], key: &'static str) -> Result<u64, AttestationError> {
    match lookup(doc, key) {
        Some(Value::Integer(i)) => {
            u64::try_from(i128::from(*i)).map_err(|_| AttestationError::MissingField(key))
        }
        _ => Err(AttestationError::MissingField(key)),
    }
}

#[cfg(feature = "attestation-verify")]
fn bytes_field(doc: &[(Value, Value)], key: &'static str) -> Result<Vec<u8>, AttestationError> {
    match lookup(doc, key) {
        Some(Value::Bytes(b)) => Ok(b.clone()),
        _ => Err(AttestationError::MissingField(key)),
    }
}

#[cfg(feature = "attestation-verify")]
fn byte_string(value: &Value, what: &'static str) -> Result<Vec<u8>, AttestationError> {
    match value {
        Value::Bytes(b) => Ok(b.clone()),
        // An absent COSE payload encodes as null; a document without one is
        // malformed rather than empty.
        _ => Err(AttestationError::MalformedCbor(what)),
    }
}

#[cfg(feature = "attestation-verify")]
fn cert_bundle(doc: &[(Value, Value)]) -> Result<Vec<Vec<u8>>, AttestationError> {
    match lookup(doc, "cabundle") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| byte_string(item, "cabundle entry"))
            .collect(),
        _ => Err(AttestationError::MissingField("cabundle")),
    }
}

#[cfg(feature = "attestation-verify")]
fn pcr_map(doc: &[(Value, Value)]) -> Result<BTreeMap<u8, Vec<u8>>, AttestationError> {
    let Some(Value::Map(entries)) = lookup(doc, "pcrs") else {
        return Err(AttestationError::MissingField("pcrs"));
    };
    let mut out = BTreeMap::new();
    for (k, v) in entries {
        let index = match k {
            Value::Integer(i) => u8::try_from(i128::from(*i))
                .map_err(|_| AttestationError::MalformedCbor("pcr index out of range"))?,
            _ => return Err(AttestationError::MalformedCbor("pcr index is not an integer")),
        };
        out.insert(index, byte_string(v, "pcr value")?);
    }
    Ok(out)
}
