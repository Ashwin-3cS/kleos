//! A device: the half of Kleos that holds keys and reads answers.
//!
//! Two jobs, and they use different primitives for different reasons.
//!
//! **Ed25519 signs grants.** A grant is signed by a key the owner holds, so
//! something has to hold it. In a finished product that is a browser or a
//! phone; here it is a file and this command, which exists so the smoke script
//! and a person at a terminal can do what a real client would. The private key
//! never leaves this machine and is never sent to the gateway -- the whole of
//! ADR 0011: the gateway can verify a grant and has nothing to mint one with.
//!
//! **X25519 receives sealed answers.** Under ADR 0024 the enclave re-encrypts
//! an assembled answer to the device that asked, so a device that cannot
//! decrypt cannot read its own memory. Before this, `kleos-device` had only a
//! signing key and the sealed path could not be run outside the browser at all.
//!
//! ```text
//! kleos-device keygen  --key ~/.kleos/device.key           # once, per device
//! kleos-device pubkey  --key ~/.kleos/device.key           # the signing half
//! kleos-device pubkey  --key ~/.kleos/device.key --encryption   # the receiving half
//! kleos-device sign    --key ~/.kleos/device.key --scope scope.json --ttl-secs 3600
//! kleos-device unseal  --key ~/.kleos/device.key --allow-mock < answer.json
//! kleos-device verify  --root AWS_NitroEnclaves_Root-G1.der < answer.json
//! ```
//!
//! **`unseal` verifies before it opens** (ADR 0026). The device is the one
//! party in this system that is not the operator, so it is the one place where
//! checking the attestation means something: a host that stood up an ordinary
//! HTTP service in place of the enclave gets a refusal here and nowhere else.
//! A mock document needs `--allow-mock`, a real one needs `--root`, and an
//! answer with no attestation at all needs `--allow-unattested` -- which is
//! the old behaviour, now something you have to ask for.
//!
//! **The encryption key is derived from the signing key, not stored beside
//! it.** One file, one thing to lose, no state where a device holds half its
//! identity -- and the precedent is ADR 0004, which derives per-purpose keys
//! from one root for the same reason. The derivation is HKDF-SHA256 over the
//! Ed25519 private bytes under a purpose label, so it is a key derivation and
//! not a curve conversion: nothing about the signing key is recoverable from
//! the encryption key, and the two cannot be confused for each other.
//!
//! **What `unseal` is for.** It is the reference implementation that an MCP
//! client and a browser are checked against. Every primitive was chosen so
//! WebCrypto can do the same with no library: `deriveBits` X25519 against the
//! ephemeral public key, `deriveBits` HKDF-SHA256 with no salt and
//! `info = scheme || eph_pk || recipient_pk`, then AES-GCM with the scheme
//! string as `additionalData`.

use fastcrypto::ed25519::Ed25519KeyPair;
use fastcrypto::traits::{KeyPair, ToFromBytes};
use device::{encryption_public, encryption_secret, open_as_device};
use shared::attestation::{commitment, purpose, Policy, Trust};
use shared::{Scope, SealedToDevice};
use std::io::Read;

fn main() {
    if let Err(message) = run() {
        eprintln!("kleos-device: {message}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");
    let key_path = flag(&args, "--key").unwrap_or_else(|| ".local/device.key".to_string());

    match command {
        "keygen" => keygen(&key_path),
        "pubkey" => {
            let keypair = load(&key_path)?;
            if args.iter().any(|a| a == "--encryption") {
                println!("{}", b64(encryption_public(&load_bytes(&key_path)?).as_bytes()));
            } else {
                println!("{}", b64(keypair.public().as_bytes()));
            }
            Ok(())
        }
        "key-id" => {
            let keypair = load(&key_path)?;
            println!("{}", shared::key_id_for(keypair.public().as_bytes()));
            Ok(())
        }
        "sign" => sign(&args, &key_path),
        "enrol" | "enroll" => enrol(&args, &key_path),
        "sign-session" => sign_session(&key_path),
        "unseal" => unseal(&args, &key_path),
        "verify" => verify_only(&args),
        _ => {
            eprintln!(
                "usage: kleos-device \
                 <keygen|pubkey|key-id|sign|unseal|verify|enrol|sign-session> [--key PATH] \
                 [--encryption] [--scope FILE|-] [--ttl-secs N] \
                 [--root PATH] [--allow-mock] [--allow-unattested] [--pcr0 HEX] \
                 [--max-age-secs N]"
            );
            Err("unknown command".into())
        }
    }
}

fn keygen(path: &str) -> Result<(), String> {
    // Refuses to overwrite. Losing a device key invalidates every grant it signed,
    // so a clobbering keygen would be a way to revoke everything by accident.
    if std::path::Path::new(path).exists() {
        return Err(format!("{path} already exists; delete it deliberately to replace the key"));
    }
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let keypair = Ed25519KeyPair::generate(&mut rand::thread_rng());
    // Read the public half before writing, because `private()` consumes the pair.
    let public = keypair.public().as_bytes().to_vec();
    std::fs::write(path, b64(keypair.private().as_bytes())).map_err(|e| e.to_string())?;
    restrict(path)?;
    println!("wrote {path}");
    println!("public key:     {}", b64(&public));
    // Printed by keygen so a device is registered with both halves in one go.
    // Registration is immutable by design (ADR step 2a): a signing key already
    // registered without an encryption half cannot gain one later, so the
    // moment to have it is now.
    println!(
        "encryption key: {}",
        b64(encryption_public(&load_bytes(path)?).as_bytes())
    );
    println!("key id:         {}", shared::key_id_for(&public));
    Ok(())
}

/// The raw private key on disk. Separate from `load` because deriving the
/// encryption half needs the bytes and `Ed25519KeyPair::private` consumes.
fn load_bytes(path: &str) -> Result<Vec<u8>, String> {
    let encoded =
        std::fs::read_to_string(path).map_err(|e| format!("could not read {path}: {e}"))?;
    unb64(encoded.trim()).ok_or_else(|| format!("{path} is not valid base64"))
}

/// Opens an answer the enclave sealed to this device.
///
/// Reads the `sealed` object from stdin -- the shape `query_memory` returns
/// under sealing -- and writes the plaintext to stdout. Deliberately a filter:
/// a device that wrote the answer to a file by default would leave plaintext on
/// disk as a side effect of reading it.
/// What `query_memory` hands back under sealing, or a bare envelope.
///
/// Both shapes are accepted because both occur in practice: the orchestrator's
/// answer carries the sealed envelope beside the attestation and the enclave
/// key, and older captures are the envelope alone. The difference is not
/// cosmetic -- the second cannot be verified, and says so.
struct Answer {
    sealed: SealedToDevice,
    attestation: Option<String>,
    enclave_public_key: Option<String>,
}

fn read_answer() -> Result<Answer, String> {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .map_err(|e| format!("could not read the sealed answer from stdin: {e}"))?;
    let raw = raw.trim();
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("stdin is not JSON: {e}"))?;

    if let Some(inner) = value.get("sealed") {
        if inner.is_null() {
            return Err("this answer is not sealed; there is nothing to open".into());
        }
        return Ok(Answer {
            sealed: serde_json::from_value(inner.clone())
                .map_err(|e| format!("the `sealed` field is not a sealed envelope: {e}"))?,
            attestation: value
                .get("attestation")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            enclave_public_key: value
                .get("enclave_public_key")
                .and_then(|v| v.as_str())
                .map(str::to_string),
        });
    }
    Ok(Answer {
        sealed: serde_json::from_str(raw)
            .map_err(|e| format!("stdin is not a sealed answer: {e}"))?,
        attestation: None,
        enclave_public_key: None,
    })
}

/// The policy the flags describe, deny-by-default.
///
/// `--allow-mock` and `--root` both have to be asked for, and neither is
/// defaulted into existence: a verifier that trusts mocks unless told not to
/// would make the `MOCK_ATTESTATION_` prefix decorative again.
fn policy_from(args: &[String]) -> Result<(Policy, Trust), String> {
    let allow_mock = args.iter().any(|a| a == "--allow-mock");
    let mut policy = match flag(args, "--root") {
        Some(path) => {
            let der = read_root(&path)?;
            Policy::with_root(der).map_err(|e| format!("{path}: {e}"))?
        }
        None => Policy::default(),
    };
    policy.allow_mock = allow_mock;
    if let Some(hex_pcr0) = flag(args, "--pcr0") {
        policy.expected_pcr0 = Some(
            hex::decode(hex_pcr0.trim()).map_err(|_| "--pcr0 must be hex".to_string())?,
        );
    }
    if let Some(secs) = flag(args, "--max-age-secs") {
        let secs: u64 = secs
            .parse()
            .map_err(|_| "--max-age-secs must be a number".to_string())?;
        policy.max_age_ms = secs * 1000;
    }
    // The floor: a mock satisfies it only because the caller said mocks are
    // acceptable here. `--pcr0` raises it to `Pinned` on its own, inside
    // `verify`, by refusing a measurement that does not match.
    let floor = if allow_mock {
        Trust::Mock
    } else {
        Trust::SignedByAws
    };
    Ok((policy, floor))
}

/// The root certificate, DER or PEM.
fn read_root(path: &str) -> Result<Vec<u8>, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("could not read {path}: {e}"))?;
    let text = String::from_utf8_lossy(&bytes);
    if text.contains("-----BEGIN CERTIFICATE-----") {
        let body: String = text
            .lines()
            .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
            .skip(1)
            .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
            .collect();
        return unb64(&body).ok_or_else(|| format!("{path} is not valid PEM"));
    }
    Ok(bytes)
}

/// Checks the attestation over an assembled answer, and reports what verified.
///
/// Two checks, and the second is the one that is easy to leave out: the
/// document has to verify, *and* it has to commit to this ciphertext sealed to
/// this device. A document that only verifies says an enclave exists.
fn check_attestation(args: &[String], answer: &Answer) -> Result<(), String> {
    let Some(document) = &answer.attestation else {
        if args.iter().any(|a| a == "--allow-unattested") {
            eprintln!(
                "kleos-device: warning: no attestation with this answer, and                  --allow-unattested was passed. Nothing here establishes that an                  enclave produced it."
            );
            return Ok(());
        }
        return Err("this answer carries no attestation, so nothing establishes that an                     enclave produced it. Pass --allow-unattested to open it anyway."
            .into());
    };

    let (policy, floor) = policy_from(args)?;
    let verified = shared::attestation::verify(document, &policy, now_ms()?)
        .map_err(|e| format!("the attestation did not verify: {e}"))?;
    if !verified.trust.at_least(floor) {
        return Err(format!(
            "the attestation verified only as `{}`, and this device requires at least `{}`",
            verified.trust.as_str(),
            floor.as_str()
        ));
    }

    let Some(encoded) = &answer.enclave_public_key else {
        return Err("the answer does not carry the enclave public key, so the attestation                     cannot be tied to this ciphertext"
            .into());
    };
    let pk = unb64(encoded).ok_or("the enclave public key is not base64")?;
    let expected = commitment(
        purpose::ASSEMBLE,
        &[
            &pk,
            answer.sealed.recipient_key_id.as_bytes(),
            answer.sealed.ciphertext_b64.as_bytes(),
        ],
    );
    if !verified.binds_key(&expected) {
        return Err("the attestation does not commit to this answer: it verified, but it is                     about some other assembly. A relayed or substituted blob looks exactly                     like this."
            .into());
    }

    eprintln!(
        "kleos-device: attestation {} (module {}), committed to this answer",
        verified.trust.as_str(),
        verified.module_id
    );
    Ok(())
}

fn unseal(args: &[String], key_path: &str) -> Result<(), String> {
    let private = load_bytes(key_path)?;
    let answer = read_answer()?;
    check_attestation(args, &answer)?;
    let sealed = answer.sealed;

    let plaintext = open_as_device(&encryption_secret(&private), &sealed)?;
    println!(
        "{}",
        String::from_utf8(plaintext)
            .map_err(|_| "the answer is not valid UTF-8".to_string())?
    );
    Ok(())
}


/// Verifies without opening anything.
///
/// Separate from `unseal` because the question "is this enclave the one I
/// expect" is worth asking before a device holds a key at all -- and because a
/// verdict is a thing to print in a script.
fn verify_only(args: &[String]) -> Result<(), String> {
    let answer = read_answer()?;
    check_attestation(args, &answer)?;
    println!("ok");
    Ok(())
}

fn now_ms() -> Result<u64, String> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock before unix epoch".to_string())?
        .as_millis() as u64)
}

#[cfg(unix)]
fn restrict(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("could not restrict {path}: {e}"))
}

#[cfg(not(unix))]
fn restrict(_path: &str) -> Result<(), String> {
    Ok(())
}

fn sign(args: &[String], key_path: &str) -> Result<(), String> {
    let keypair = load(key_path)?;
    let source = flag(args, "--scope").unwrap_or_else(|| "-".to_string());
    let raw = if source == "-" {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("could not read scope from stdin: {e}"))?;
        buf
    } else {
        std::fs::read_to_string(&source).map_err(|e| format!("could not read {source}: {e}"))?
    };
    let scope: Scope =
        serde_json::from_str(&raw).map_err(|e| format!("scope is not valid JSON: {e}"))?;

    let ttl_secs: u64 = flag(args, "--ttl-secs")
        .map(|v| v.parse().map_err(|_| "--ttl-secs must be a number".to_string()))
        .transpose()?
        .unwrap_or(3600);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system clock before unix epoch".to_string())?
        .as_millis() as u64;

    // A fresh nonce per grant, so two grants with identical scope and timing are
    // still distinguishable in the read log.
    let nonce = {
        let bytes = Ed25519KeyPair::generate(&mut rand::thread_rng());
        hex::encode(&bytes.public().as_bytes()[..8])
    };

    let token = shared::sign_grant(&scope, &keypair, now_ms, ttl_secs * 1000, &nonce)
        .map_err(|e| e.to_string())?;
    println!("{token}");
    Ok(())
}

/// The body for `POST /auth/local/enrol`, printed rather than posted.
///
/// This crate deliberately has no HTTP client -- its job is to hold a key and
/// produce bytes -- so enrolment is a body you pipe into curl. ADR 0029 chose
/// a signed assertion over a challenge round trip partly to keep that true.
///
///   kleos-device enrol --key ~/.kleos/device.key --code <code> \
///     | curl -sS -X POST http://127.0.0.1:8080/auth/local/enrol \
///         -H 'content-type: application/json' --data @-
fn enrol(args: &[String], key_path: &str) -> Result<(), String> {
    let code = flag(args, "--code")
        .ok_or("enrol needs --code, the enrolment code the gateway printed on first start")?;
    let keypair = load(key_path)?;
    let private = load_bytes(key_path)?;
    let label = flag(args, "--label").unwrap_or_else(|| "this device".to_string());
    let body = serde_json::json!({
        "enrolment_code": code,
        "public_key_b64": b64(keypair.public().as_bytes()),
        // Always sent. A device enrolled without it can sign and read but can
        // never be sent a sealed answer, and registration is immutable -- so
        // the moment to have it is now (the same argument keygen makes).
        "encryption_key_b64": b64(encryption_public(&private).as_bytes()),
        "label": label,
    });
    println!("{body}");
    Ok(())
}

/// A signed assertion for `POST /auth/local/session`.
///
/// The signed bytes are built the same way `gateway::routes::local_auth::
/// assertion_bytes` builds them, and the format is prefixed and versioned so
/// these can never be read as something else this key signs -- a grant above
/// all. A signature is only as specific as what it covers.
fn sign_session(key_path: &str) -> Result<(), String> {
    use fastcrypto::traits::Signer;

    let keypair = load(key_path)?;
    let key_id = shared::key_id_for(keypair.public().as_bytes());
    let issued_at_ms = now_ms()? as i64;
    let nonce = {
        let bytes = Ed25519KeyPair::generate(&mut rand::thread_rng());
        hex::encode(&bytes.public().as_bytes()[..12])
    };
    let message = format!("kleos-local-session|v1|{key_id}|{issued_at_ms}|{nonce}");
    let signature = keypair.sign(message.as_bytes());

    println!(
        "{}",
        serde_json::json!({
            "key_id": key_id,
            "issued_at_ms": issued_at_ms,
            "nonce": nonce,
            "signature_b64": b64(signature.as_ref()),
        })
    );
    Ok(())
}

fn load(path: &str) -> Result<Ed25519KeyPair, String> {
    let encoded =
        std::fs::read_to_string(path).map_err(|e| format!("could not read {path}: {e}"))?;
    let bytes = unb64(encoded.trim()).ok_or_else(|| format!("{path} is not valid base64"))?;
    Ed25519KeyPair::from_bytes(&bytes).map_err(|e| format!("{path} is not an Ed25519 key: {e}"))
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn b64(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(bytes)
}

fn unb64(text: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.decode(text).ok()
}
