//! The browser signs grants too. This is what says the two signers agree.
//!
//! `ui/src/lib/grants.ts` is a second implementation of `grants.rs`, and it
//! exists because of ADR 0011: a grant is signed by a key the **owner** holds,
//! so a dashboard that let the server sign would collapse the project's
//! confidentiality story to "trust the host". The owner's key therefore lives in
//! their browser, and the browser has to produce this format exactly.
//!
//! Two implementations of one wire format drift, and this pair drifts *silently*.
//! Base64url padding, a field omitted from the payload, a wrong domain separator
//! in the key id, an integer serialised as a float -- none of those raise
//! anything on the JavaScript side. They present as an owner issuing grants that
//! nothing accepts, with nothing to say which half is wrong.
//!
//! So the discipline is the one `test_schema_parity.py` already applies to the
//! Python mirror: the other side checks. `ui/scripts/sign-fixture.mjs` writes
//! `fixtures/browser_grant.json` from a committed seed and scope; this verifies
//! it with the real `verify_grant`, which is the same function the gateway calls.
//!
//! **If this fails, do not regenerate the fixture to make it pass.** Regenerating
//! is correct only when the format changed on purpose. Otherwise the browser
//! signer has drifted, and the fixture is the evidence of what it now produces.

use shared::grants::parse_unverified;
use shared::{key_id_for, verify_grant, GrantError, RegisteredKey, Sensitivity};

/// Written by `ui/scripts/sign-fixture.mjs`, read at compile time so a missing
/// fixture is a build failure rather than a skipped test.
const FIXTURE: &str = include_str!("fixtures/browser_grant.json");

struct Fixture {
    token: String,
    public_key: Vec<u8>,
    key_id: String,
    owner_id: String,
    issued_at_ms: u64,
    /// What the scope asked for: deliberately far beyond the token's own TTL.
    scope_expires_at_ms: u64,
    /// What `verify_grant` should hand back instead -- the token's expiry.
    clamped_expires_at_ms: u64,
}

fn fixture() -> Fixture {
    let v: serde_json::Value = serde_json::from_str(FIXTURE).expect("fixture is not valid JSON");
    Fixture {
        token: v["token"].as_str().expect("token").to_string(),
        public_key: hex::decode(v["public_key_hex"].as_str().expect("public_key_hex"))
            .expect("public key is not hex"),
        key_id: v["key_id"].as_str().expect("key_id").to_string(),
        owner_id: v["expect_scope"]["owner_id"]
            .as_str()
            .expect("owner_id")
            .to_string(),
        issued_at_ms: v["issued_at_ms"].as_u64().expect("issued_at_ms"),
        scope_expires_at_ms: v["expect_scope"]["expires_at_ms"]
            .as_u64()
            .expect("expect_scope.expires_at_ms"),
        clamped_expires_at_ms: v["expect_clamped_expires_at_ms"]
            .as_u64()
            .expect("expect_clamped_expires_at_ms"),
    }
}

fn registered(f: &Fixture) -> RegisteredKey {
    RegisteredKey {
        owner_id: f.owner_id.clone(),
        public_key: f.public_key.clone(),
        revoked: false,
    }
}

#[test]
fn a_grant_signed_in_the_browser_verifies_here() {
    let f = fixture();
    let scope = verify_grant(&f.token, |_| Some(registered(&f)), f.issued_at_ms)
        .expect("the browser's grant must verify with the gateway's own verifier");

    assert_eq!(scope.owner_id, f.owner_id);
    assert_eq!(scope.agent_id, "chatgpt");
}

#[test]
fn every_appended_capability_survives_the_round_trip() {
    // The seven fields added for the harness are `#[serde(default)]`, so a signer
    // that dropped all of them would still produce a *verifiable* token -- just a
    // read-only one. That is why the fixture's scope has them switched on: the
    // default would make this test pass while the signer was broken.
    let f = fixture();
    let scope = verify_grant(&f.token, |_| Some(registered(&f)), f.issued_at_ms).unwrap();

    assert!(scope.may_write, "may_write was lost in transit");
    assert!(scope.may_unseal, "may_unseal was lost in transit");
    assert!(!scope.may_supersede_owner);
    assert!(scope.may_act, "may_act was lost in transit");
    assert_eq!(
        scope.write_sources.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
        vec!["agent"]
    );
    assert_eq!(scope.memory_kinds.len(), 3, "memory_kinds was lost in transit");
    assert_eq!(scope.act_actions, vec!["attest.digest"]);
    assert_eq!(scope.max_sensitivity, Sensitivity::Confidential);
    assert_eq!(scope.sources.len(), 2);
    assert_eq!(scope.entity_kinds.len(), 5);
}

#[test]
fn the_browsers_key_id_is_the_one_this_side_derives() {
    // The register response hands the browser its key id, so the UI *could*
    // simply believe it. It must not: registration is authorised by a host-signed
    // owner session, so a host that forges one can register a key of its own.
    // Nothing prevents that; what detects it is a client that derives the id from
    // the public key it holds. This asserts the two derivations agree, which is
    // what makes that check meaningful.
    let f = fixture();
    assert_eq!(key_id_for(&f.public_key), f.key_id);

    let (claims, _, _) = parse_unverified(&f.token).unwrap();
    assert_eq!(claims.key_id, f.key_id);
}

#[test]
fn the_token_expiry_clamps_the_scopes_own() {
    // The fixture's scope asks for an expiry far beyond the token's, which is
    // the case that matters: a UI could otherwise compose a long-lived scope and
    // a short token and be wrong about which one wins.
    let f = fixture();
    let scope = verify_grant(&f.token, |_| Some(registered(&f)), f.issued_at_ms).unwrap();

    assert_eq!(
        scope.expires_at_ms,
        Some(f.clamped_expires_at_ms),
        "the scope comes back carrying the token's expiry, not its own"
    );
    assert!(
        f.clamped_expires_at_ms < f.scope_expires_at_ms,
        "the fixture has to ask for more than the token allows, or this proves nothing"
    );
}

#[test]
fn a_tampered_payload_does_not_verify() {
    // The property the whole screen rests on. If a byte of the scope could be
    // changed after signing, the owner's intent would be advisory.
    let f = fixture();
    let parts: Vec<&str> = f.token.split('.').collect();
    let mut payload = parts[2].to_string();
    // Flip one character of the base64url payload, keeping its length.
    let last = payload.pop().unwrap();
    payload.push(if last == 'A' { 'B' } else { 'A' });
    let tampered = format!("{}.{}.{}.{}", parts[0], parts[1], payload, parts[3]);

    let result = verify_grant(&tampered, |_| Some(registered(&f)), f.issued_at_ms);
    assert!(
        matches!(result, Err(GrantError::BadSignature | GrantError::Malformed(_))),
        "a tampered grant must be refused, got {result:?}"
    );
}

#[test]
fn an_unregistered_browser_key_is_refused() {
    let f = fixture();
    assert_eq!(
        verify_grant(&f.token, |_| None, f.issued_at_ms).unwrap_err(),
        GrantError::UnknownKey
    );
}

#[test]
fn revoking_the_browsers_key_invalidates_what_it_signed() {
    // The dashboard's whole revocation story: there is no per-grant revocation,
    // so "revoke this agent" is revoking the key that signed for it. This is
    // that lever working on a token the browser produced.
    let f = fixture();
    let mut key = registered(&f);
    key.revoked = true;
    assert_eq!(
        verify_grant(&f.token, |_| Some(key.clone()), f.issued_at_ms).unwrap_err(),
        GrantError::KeyRevoked
    );
}

#[test]
fn another_owners_key_cannot_sign_this_scope() {
    let f = fixture();
    let mut key = registered(&f);
    key.owner_id = "someone-else".into();
    assert_eq!(
        verify_grant(&f.token, |_| Some(key.clone()), f.issued_at_ms).unwrap_err(),
        GrantError::OwnerMismatch
    );
}
