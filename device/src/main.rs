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
//! kleos-device unseal  --key ~/.kleos/device.key < sealed.json
//! ```
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
        "unseal" => unseal(&key_path),
        _ => {
            eprintln!(
                "usage: kleos-device <keygen|pubkey|key-id|sign|unseal> [--key PATH] \
                 [--encryption] [--scope FILE|-] [--ttl-secs N]"
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
fn unseal(key_path: &str) -> Result<(), String> {
    let private = load_bytes(key_path)?;
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .map_err(|e| format!("could not read the sealed answer from stdin: {e}"))?;
    let sealed: SealedToDevice = serde_json::from_str(raw.trim())
        .map_err(|e| format!("stdin is not a sealed answer: {e}"))?;

    let plaintext = open_as_device(&encryption_secret(&private), &sealed)?;
    println!(
        "{}",
        String::from_utf8(plaintext)
            .map_err(|_| "the answer is not valid UTF-8".to_string())?
    );
    Ok(())
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
