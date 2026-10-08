//! Owner-signed grant tokens.
//!
//! A grant is the capability that governs every read of a person's memory. Until
//! now the **gateway** signed them, with a key derived from the same root that
//! signs owner sessions. That left the threat model inconsistent in a way no
//! amount of key separation fixes: the gateway is untrusted for
//! *confidentiality* -- which is why OAuth code exchange happens inside the
//! enclave -- and was fully trusted for *authorization*. An operator could not
//! read your mailbox and could mint themselves a grant over your entire resolved
//! memory, with any scope and any sensitivity ceiling, which the permission check
//! would then correctly honour, because a grant **is** its signature.
//!
//! So the signature moves to a key the owner holds. The gateway verifies and
//! cannot mint, because it has no private key to mint with.
//!
//! ## What this does and does not prevent
//!
//! Stated precisely, because the difference matters and is easy to overclaim.
//!
//! **Prevented:** silent minting. There is no key on the host that produces a
//! valid grant. An operator who wants one has to either substitute the registered
//! public key or lie in introspection, and both leave evidence.
//!
//! **Not prevented:** key substitution. Registration is authorised by an owner
//! session, and owner sessions are still host-signed, so a host can forge a
//! session and register its own key. What it cannot do is that *invisibly* -- the
//! registration is a stored, timestamped row the owner's client can list and
//! compare against the key it actually holds, and reads made under an unrecognised
//! grant show up in the read log by fingerprint (ADR 0005).
//!
//! That is the honest increment: an undetectable attack becomes a detectable one.
//! Making it impossible needs a verification root the operator cannot
//! substitute -- an enclave key gated on attestation, or an on-chain grant object.
//! `verify_grant` takes its keys through a closure precisely so that swapping the
//! root is a change of one caller, not a redesign.
//!
//! ## Format
//!
//! ```text
//! kgrant.v1.<base64url(payload json)>.<base64url(signature)>
//! ```
//!
//! Self-describing and versioned, so a later scheme can coexist during a
//! rollover. The signature covers **the payload bytes as received**, never a
//! re-serialisation of the parsed struct: re-serialising to verify means the
//! verifier checks a signature over bytes the signer never produced, and any
//! difference in field order or number formatting silently becomes a forgery
//! oracle.

use crate::permissions::Scope;
use fastcrypto::ed25519::{Ed25519PublicKey, Ed25519Signature};
use fastcrypto::traits::{ToFromBytes, VerifyingKey};
use serde::{Deserialize, Serialize};

const PREFIX: &str = "kgrant";
const VERSION: &str = "v1";
const TOKEN_TYPE: &str = "grant";

/// What the owner signs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GrantClaims {
    /// States what this token is, so it cannot be presented as something else.
    /// Carried even though the format is already grant-specific, because the
    /// cost is nothing and the previous generation of tokens learned this the
    /// hard way.
    pub typ: String,
    /// Which registered device key signed this. The verifier needs it before it
    /// can check anything, so it travels in the payload rather than out of band.
    pub key_id: String,
    pub scope: Scope,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    /// Makes two grants with identical scope and timing distinguishable, so the
    /// read log can tell them apart and an owner can revoke their recollection of
    /// one without ambiguity.
    pub nonce: String,
}

/// A device key as the verifier finds it.
#[derive(Debug, Clone)]
pub struct RegisteredKey {
    pub owner_id: String,
    pub public_key: Vec<u8>,
    pub revoked: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum GrantError {
    Malformed(&'static str),
    UnknownVersion,
    UnknownKey,
    KeyRevoked,
    BadSignature,
    WrongTokenType,
    Expired,
    /// The scope claims an owner the signing key does not belong to.
    OwnerMismatch,
}

impl std::fmt::Display for GrantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            GrantError::Malformed(what) => return write!(f, "malformed grant: {what}"),
            GrantError::UnknownVersion => "unsupported grant version",
            GrantError::UnknownKey => "grant signed by an unregistered device key",
            GrantError::KeyRevoked => "grant signed by a revoked device key",
            GrantError::BadSignature => "grant signature does not verify",
            GrantError::WrongTokenType => "token is not an agent grant",
            GrantError::Expired => "grant has expired",
            GrantError::OwnerMismatch => "grant scope names an owner this key cannot speak for",
        };
        f.write_str(text)
    }
}

impl std::error::Error for GrantError {}

/// Derives a stable, public identifier for a device public key.
///
/// A hash rather than the key itself, so a key id can appear in a log or a URL
/// without publishing material anyone could check signatures against -- the key
/// is not secret, but an identifier should not be load-bearing material either.
pub fn key_id_for(public_key: &[u8]) -> String {
    use fastcrypto::hash::{Blake2b256, HashFunction};
    let mut hasher = Blake2b256::default();
    hasher.update(b"kleos/device-key/v1");
    hasher.update(public_key);
    hex::encode(&hasher.finalize().digest[..16])
}

/// Splits a token into its payload bytes and signature without verifying either.
///
/// Public because the verifier needs the `key_id` out of the payload in order to
/// find the key that checks the signature, which is unavoidable: you cannot
/// authenticate a message before you know which key it claims.
pub fn parse_unverified(token: &str) -> Result<(GrantClaims, Vec<u8>, Vec<u8>), GrantError> {
    let mut parts = token.split('.');
    match (parts.next(), parts.next()) {
        (Some(PREFIX), Some(VERSION)) => {}
        (Some(PREFIX), Some(_)) => return Err(GrantError::UnknownVersion),
        _ => return Err(GrantError::Malformed("expected kgrant.v1 prefix")),
    }
    let payload_b64 = parts.next().ok_or(GrantError::Malformed("no payload"))?;
    let sig_b64 = parts.next().ok_or(GrantError::Malformed("no signature"))?;
    if parts.next().is_some() {
        return Err(GrantError::Malformed("trailing segments"));
    }

    let payload = b64_decode(payload_b64).ok_or(GrantError::Malformed("payload is not base64"))?;
    let signature = b64_decode(sig_b64).ok_or(GrantError::Malformed("signature is not base64"))?;
    let claims: GrantClaims =
        serde_json::from_slice(&payload).map_err(|_| GrantError::Malformed("payload is not a grant"))?;
    Ok((claims, payload, signature))
}

/// Verifies a grant and returns the scope it carries.
///
/// `lookup` resolves a key id to a registered key. Taking it as a closure keeps
/// this function free of any storage concern, and is what makes the verification
/// root replaceable: today it reads a Postgres row, later it can read an
/// attestation-gated key or an on-chain object, and nothing here changes.
///
/// Order matters. The signature is checked before any claim inside the payload is
/// trusted for a decision, and the owner binding is checked after -- because a
/// valid signature from Alice's key over a scope claiming to be Bob's is the
/// interesting attack, not a malformed token.
pub fn verify_grant<F>(token: &str, lookup: F, now_ms: u64) -> Result<Scope, GrantError>
where
    F: FnOnce(&str) -> Option<RegisteredKey>,
{
    let (claims, payload, signature) = parse_unverified(token)?;

    let key = lookup(&claims.key_id).ok_or(GrantError::UnknownKey)?;
    if key.revoked {
        // Checked before the signature so a revoked key cannot be distinguished
        // from an unregistered one by timing. Revoking a device key invalidates
        // every grant it ever signed, which is the only revocation lever that
        // exists today -- see ADR 0011.
        return Err(GrantError::KeyRevoked);
    }

    let public_key =
        Ed25519PublicKey::from_bytes(&key.public_key).map_err(|_| GrantError::UnknownKey)?;
    let sig = Ed25519Signature::from_bytes(&signature).map_err(|_| GrantError::BadSignature)?;
    public_key
        .verify(&payload, &sig)
        .map_err(|_| GrantError::BadSignature)?;

    if claims.typ != TOKEN_TYPE {
        return Err(GrantError::WrongTokenType);
    }
    if now_ms >= claims.expires_at_ms {
        return Err(GrantError::Expired);
    }
    if claims.scope.owner_id != key.owner_id {
        return Err(GrantError::OwnerMismatch);
    }

    let mut scope = claims.scope;
    // The token's own expiry bounds the scope's: a scope that outlived the token
    // signing it would let a stale capability keep passing the per-object check.
    scope.expires_at_ms = Some(match scope.expires_at_ms {
        Some(existing) => existing.min(claims.expires_at_ms),
        None => claims.expires_at_ms,
    });
    Ok(scope)
}

/// Signs a grant. The owner's side of the protocol.
///
/// Lives here so the signer and the verifier cannot disagree about what is
/// covered: anything that changes the payload bytes changes both at once.
pub fn sign_grant(
    scope: &Scope,
    keypair: &fastcrypto::ed25519::Ed25519KeyPair,
    issued_at_ms: u64,
    ttl_ms: u64,
    nonce: &str,
) -> Result<String, GrantError> {
    use fastcrypto::traits::{KeyPair, Signer};

    let public = keypair.public();
    let claims = GrantClaims {
        typ: TOKEN_TYPE.to_string(),
        key_id: key_id_for(public.as_bytes()),
        scope: scope.clone(),
        issued_at_ms,
        expires_at_ms: issued_at_ms + ttl_ms,
        nonce: nonce.to_string(),
    };
    let payload =
        serde_json::to_vec(&claims).map_err(|_| GrantError::Malformed("scope will not serialise"))?;
    let signature: Ed25519Signature = keypair.sign(&payload);
    Ok(format!(
        "{PREFIX}.{VERSION}.{}.{}",
        b64_encode(&payload),
        b64_encode(signature.as_ref())
    ))
}

// base64url without padding, written out rather than pulled in: `shared` has no
// base64 dependency and this is the only place it needs one.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[n as usize & 63] as char);
        }
    }
    out
}

fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    for ch in text.bytes() {
        let value = B64.iter().position(|c| *c == ch)? as u32;
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    // Leftover bits must be zero padding; anything else is a second encoding of
    // the same bytes, and a token with two spellings is a token that can be
    // replayed past a deduplicating log.
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{EntityKind, SourceId};
    use crate::permissions::Sensitivity;
    use fastcrypto::ed25519::Ed25519KeyPair;
    use fastcrypto::traits::KeyPair;

    const NOW: u64 = 1_767_571_200_000;
    const HOUR: u64 = 3_600_000;

    fn keypair() -> Ed25519KeyPair {
        Ed25519KeyPair::generate(&mut rand::thread_rng())
    }

    fn scope(owner: &str) -> Scope {
        Scope {
            agent_id: "agent-1".into(),
            owner_id: owner.into(),
            sources: vec![SourceId::parse("mock").unwrap()],
            entity_kinds: vec![EntityKind::Project],
            not_before_ms: None,
            not_after_ms: None,
            max_sensitivity: Sensitivity::Personal,
            expires_at_ms: None,
            // Read-only, and deliberately spelled this way: a capability added
            // to `Scope` later must not quietly become granted in a test that
            // never mentioned it.
            ..Default::default()
        }
    }

    fn registered(kp: &Ed25519KeyPair, owner: &str) -> RegisteredKey {
        RegisteredKey {
            owner_id: owner.into(),
            public_key: kp.public().as_bytes().to_vec(),
            revoked: false,
        }
    }

    #[test]
    fn a_signed_grant_verifies_and_carries_its_scope() {
        let kp = keypair();
        let token = sign_grant(&scope("owner-1"), &kp, NOW, HOUR, "n1").unwrap();
        let out = verify_grant(&token, |_| Some(registered(&kp, "owner-1")), NOW).unwrap();
        assert_eq!(out.agent_id, "agent-1");
        assert_eq!(out.expires_at_ms, Some(NOW + HOUR));
    }

    #[test]
    fn a_token_signed_by_an_unregistered_key_is_refused() {
        let kp = keypair();
        let token = sign_grant(&scope("owner-1"), &kp, NOW, HOUR, "n1").unwrap();
        assert_eq!(
            verify_grant(&token, |_| None, NOW).unwrap_err(),
            GrantError::UnknownKey
        );
    }

    /// The whole point of the change: the host has no key that produces a valid
    /// grant, so a grant it signs itself fails verification.
    #[test]
    fn a_grant_signed_by_a_different_key_is_refused() {
        let owner_key = keypair();
        let host_key = keypair();
        let forged = sign_grant(&scope("owner-1"), &host_key, NOW, HOUR, "n1").unwrap();

        // The host even names the owner's key id in the payload.
        let (claims, _, _) = parse_unverified(&forged).unwrap();
        assert_ne!(claims.key_id, key_id_for(owner_key.public().as_bytes()));

        assert_eq!(
            verify_grant(&forged, |_| Some(registered(&owner_key, "owner-1")), NOW).unwrap_err(),
            GrantError::BadSignature
        );
    }

    /// Revoking a device key invalidates every grant it ever signed. The only
    /// revocation lever that exists -- coarse, and better than none.
    #[test]
    fn a_revoked_key_invalidates_its_grants() {
        let kp = keypair();
        let token = sign_grant(&scope("owner-1"), &kp, NOW, HOUR, "n1").unwrap();
        let mut key = registered(&kp, "owner-1");
        key.revoked = true;
        assert_eq!(
            verify_grant(&token, |_| Some(key.clone()), NOW).unwrap_err(),
            GrantError::KeyRevoked
        );
    }

    /// The interesting forgery: a real signature from a real registered key, over
    /// a scope naming somebody else's memory.
    #[test]
    fn a_key_cannot_sign_for_another_owner() {
        let kp = keypair();
        let token = sign_grant(&scope("owner-2"), &kp, NOW, HOUR, "n1").unwrap();
        assert_eq!(
            verify_grant(&token, |_| Some(registered(&kp, "owner-1")), NOW).unwrap_err(),
            GrantError::OwnerMismatch
        );
    }

    #[test]
    fn an_expired_grant_is_refused() {
        let kp = keypair();
        let token = sign_grant(&scope("owner-1"), &kp, NOW, HOUR, "n1").unwrap();
        assert_eq!(
            verify_grant(&token, |_| Some(registered(&kp, "owner-1")), NOW + HOUR).unwrap_err(),
            GrantError::Expired
        );
    }

    /// A tampered payload must fail even though it still parses, which is the
    /// property that only holds because the signature covers the received bytes
    /// rather than a re-serialisation of the parsed struct.
    #[test]
    fn widening_the_scope_after_signing_breaks_the_signature() {
        let kp = keypair();
        let token = sign_grant(&scope("owner-1"), &kp, NOW, HOUR, "n1").unwrap();
        let (mut claims, _, signature) = parse_unverified(&token).unwrap();

        claims.scope.max_sensitivity = Sensitivity::Restricted;
        let tampered = format!(
            "{PREFIX}.{VERSION}.{}.{}",
            b64_encode(&serde_json::to_vec(&claims).unwrap()),
            b64_encode(&signature)
        );
        assert_eq!(
            verify_grant(&tampered, |_| Some(registered(&kp, "owner-1")), NOW).unwrap_err(),
            GrantError::BadSignature
        );
    }

    #[test]
    fn the_scope_expiry_never_outlives_the_token() {
        let kp = keypair();
        let mut wide = scope("owner-1");
        wide.expires_at_ms = Some(NOW + 100 * HOUR);
        let token = sign_grant(&wide, &kp, NOW, HOUR, "n1").unwrap();
        let out = verify_grant(&token, |_| Some(registered(&kp, "owner-1")), NOW).unwrap();
        assert_eq!(out.expires_at_ms, Some(NOW + HOUR));
    }

    #[test]
    fn malformed_tokens_are_refused_rather_than_panicking() {
        let kp = keypair();
        for bad in [
            "",
            "kgrant",
            "kgrant.v1",
            "kgrant.v1.only-payload",
            "kgrant.v2.aaaa.bbbb",
            "notkgrant.v1.aaaa.bbbb",
            "kgrant.v1.!!!!.bbbb",
            "kgrant.v1.aaaa.bbbb.cccc",
        ] {
            let result = verify_grant(bad, |_| Some(registered(&kp, "owner-1")), NOW);
            assert!(result.is_err(), "{bad:?} should not verify");
        }
    }

    #[test]
    fn base64_round_trips_every_length() {
        for len in 0..200 {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
            assert_eq!(b64_decode(&b64_encode(&bytes)).unwrap(), bytes, "len {len}");
        }
    }

    #[test]
    fn a_key_id_is_stable_and_not_the_key() {
        let kp = keypair();
        let raw = kp.public().as_bytes().to_vec();
        let id = key_id_for(&raw);
        assert_eq!(id, key_id_for(&raw));
        assert_eq!(id.len(), 32);
        assert_ne!(id, hex::encode(&raw));
    }
}
