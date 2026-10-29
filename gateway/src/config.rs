use crate::keys::SigningKeys;
use std::env;

use shared::attestation::Policy as AttestationPolicy;

#[derive(Debug, Clone)]
pub struct Config {
    pub gateway_port: u16,
    /// The interface the gateway listens on. **Loopback by default.**
    ///
    /// It used to be `0.0.0.0`, hard-coded, which on a laptop in mock mode put
    /// the whole gateway on the local network -- and mock mode accepts
    /// `mock_google_<subject>` as a sign-in, so anyone on the same wifi could
    /// mint an owner session, register a device key under it and sign
    /// themselves a grant. A personal install should be reachable by the
    /// person, and a deployment that wants more says so.
    pub gateway_bind: String,
    pub enclave_host: String,
    pub enclave_port: u16,
    /// Per-purpose signing keys, derived from one root secret so that no two
    /// of them are ever accidentally equal. See `keys.rs` and ADR 0004.
    pub keys: SigningKeys,
    pub session_ttl_secs: usize,
    pub oauth_state_ttl_secs: u64,
    /// Client *ids* only. The matching secrets live in the enclave's
    /// environment and deliberately not here -- see enclave/src/config.rs.
    pub google_client_id: String,
    pub google_redirect_uri: String,
    pub github_client_id: String,
    pub github_redirect_uri: String,
    /// Postgres URL for the sealed refresh-token store. Unset means the
    /// in-memory store, which is the local mock-mode default.
    pub sealed_token_store_url: Option<String>,
    /// Where the local enrolment code lives, when local sign-in is enabled
    /// (ADR 0029). `None` disables `/auth/local/*` entirely, which is what a
    /// hosted deployment wants: it uses OAuth, and an open enrolment route
    /// there would mint owners for anyone who can reach it.
    pub local_enrolment: Option<crate::enrolment::Enrolment>,
    /// Whether `mock_google_<subject>` is accepted as a sign-in.
    ///
    /// Off unless asked for, the same shape `ATTESTATION_ALLOW_MOCK` has. It
    /// was effectively on for every mock-mode gateway, and the owner id is a
    /// deterministic hash of the subject, so it minted any identity on
    /// request. The scripts and the test suites set it; a person running Kleos
    /// has a local owner and does not need it.
    pub allow_mock_identity: bool,

    /// What this gateway accepts as an attestation (ADR 0026).
    ///
    /// Built at boot, so a root certificate that is not the AWS root stops the
    /// service starting instead of failing every document at runtime in a way
    /// that reads like a bad document. `None` means verification is off, which
    /// is a configuration choice and not a default: see `from_env`.
    ///
    /// Note what a check *here* is worth. The gateway is the host — the
    /// component an operator substituting a fake enclave would substitute — so
    /// this catches misconfiguration and not an attack. The device's check is
    /// the one that is not the operator's.
    pub attestation: Option<AttestationPolicy>,
}

impl Config {
    /// Reads configuration from the environment.
    ///
    /// Fallible only because of the signing keys: a gateway that boots with the
    /// public development secret in `nitro` mode looks like it is working,
    /// which is worse than one that refuses to boot.
    pub fn from_env() -> anyhow::Result<Self> {
        let nitro = env::var("ENCLAVE_MODE").map(|m| m == "nitro").unwrap_or(false);
        Ok(Self {
            keys: SigningKeys::from_env(nitro)?,
            gateway_bind: env::var("GATEWAY_BIND")
                .unwrap_or_else(|_| "127.0.0.1".to_string()),
            gateway_port: env::var("GATEWAY_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(8080),
            // In `nitro` mode this is still `127.0.0.1` -- parent_forwarder.sh
            // bridges that local port out to the enclave's VSOCK CID (see
            // scripts/parent_forwarder.sh's port4000-bridge block), so the
            // gateway itself never needs to know the enclave's CID.
            enclave_host: env::var("ENCLAVE_HOST").unwrap_or_else(|_| "127.0.0.1".to_string()),
            enclave_port: env::var("ENCLAVE_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(4000),
            session_ttl_secs: env::var("SESSION_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600),
            oauth_state_ttl_secs: env::var("OAUTH_STATE_TTL_SECS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(600),
            google_client_id: env::var("GOOGLE_CLIENT_ID").unwrap_or_default(),
            google_redirect_uri: env::var("GOOGLE_REDIRECT_URI")
                .unwrap_or_else(|_| "http://127.0.0.1:8080/auth/callback".to_string()),
            github_client_id: env::var("GITHUB_CLIENT_ID").unwrap_or_default(),
            github_redirect_uri: env::var("GITHUB_REDIRECT_URI")
                .unwrap_or_else(|_| "http://127.0.0.1:8080/auth/callback".to_string()),
            sealed_token_store_url: env::var("SEALED_TOKEN_STORE_URL")
                .ok()
                .filter(|v| !v.trim().is_empty()),
            attestation: attestation_policy()?,
            local_enrolment: local_enrolment()?,
            allow_mock_identity: env::var("ALLOW_MOCK_IDENTITY")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
        })
    }

    /// Mock/dev defaults; also what the test suites build on.
    pub fn mock() -> Self {
        Self {
            gateway_bind: "127.0.0.1".to_string(),
            gateway_port: 8080,
            enclave_host: "127.0.0.1".to_string(),
            enclave_port: 4000,
            keys: SigningKeys::mock(),
            // Mocks allowed, and nothing else: the mock enclave produces
            // nothing else. The tests build on this.
            attestation: Some(AttestationPolicy::mock_only()),
            // The test suites sign in with `mock_google_<subject>`; that is
            // what `Config::mock()` is for, and a person's install is not
            // built from it.
            local_enrolment: None,
            allow_mock_identity: true,
            session_ttl_secs: 3600,
            oauth_state_ttl_secs: 600,
            google_client_id: "mock-google-client-id".to_string(),
            google_redirect_uri: "http://127.0.0.1:8080/auth/callback".to_string(),
            github_client_id: "mock-github-client-id".to_string(),
            github_redirect_uri: "http://127.0.0.1:8080/auth/callback".to_string(),
            sealed_token_store_url: None,
        }
    }

    pub fn client_id(&self, provider: shared::Provider) -> &str {
        match provider {
            shared::Provider::Google => &self.google_client_id,
            shared::Provider::GitHub => &self.github_client_id,
        }
    }

    pub fn redirect_uri(&self, provider: shared::Provider) -> &str {
        match provider {
            shared::Provider::Google => &self.google_redirect_uri,
            shared::Provider::GitHub => &self.github_redirect_uri,
        }
    }
}

/// The attestation policy from the environment.
///
/// Fallible on purpose, in the same spirit as `SigningKeys::from_env`: a
/// gateway that boots with a root certificate it cannot verify looks like it is
/// working, which is worse than one that refuses to boot.
fn attestation_policy() -> anyhow::Result<Option<AttestationPolicy>> {
    let on = env::var("VERIFY_ATTESTATION")
        .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
        .unwrap_or(true);
    if !on {
        tracing::warn!(
            "VERIFY_ATTESTATION is off: this gateway relays attestation documents \
             without reading them"
        );
        return Ok(None);
    }

    let allow_mock = env::var("ATTESTATION_ALLOW_MOCK")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let mut policy = match env::var("ATTESTATION_ROOT_PATH").ok().filter(|p| !p.trim().is_empty()) {
        Some(path) => {
            let der = read_certificate(&path)?;
            AttestationPolicy::with_root(der)
                .map_err(|e| anyhow::anyhow!("ATTESTATION_ROOT_PATH {path}: {e}"))?
        }
        None => AttestationPolicy::default(),
    };
    policy.allow_mock = allow_mock;
    if let Some(hex_pcr0) = env::var("ATTESTATION_EXPECTED_PCR0").ok().filter(|v| !v.trim().is_empty())
    {
        policy.expected_pcr0 = Some(
            hex::decode(hex_pcr0.trim())
                .map_err(|_| anyhow::anyhow!("ATTESTATION_EXPECTED_PCR0 must be hex"))?,
        );
    }
    policy.max_age_ms = env::var("ATTESTATION_MAX_AGE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(300)
        * 1000;
    Ok(Some(policy))
}

/// A certificate from disk, DER or PEM.
fn read_certificate(path: &str) -> anyhow::Result<Vec<u8>> {
    let bytes = std::fs::read(path)?;
    let text = String::from_utf8_lossy(&bytes);
    if text.contains("-----BEGIN CERTIFICATE-----") {
        use base64::Engine;
        let body: String = text
            .lines()
            .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE-----"))
            .skip(1)
            .take_while(|l| !l.starts_with("-----END CERTIFICATE-----"))
            .collect();
        return Ok(base64::engine::general_purpose::STANDARD.decode(body)?);
    }
    Ok(bytes)
}

/// Local enrolment, when it is enabled.
///
/// On by default in `mock` mode and off in `nitro`: a personal install is the
/// case mock mode exists for, and a deployment behind a real enclave uses
/// OAuth. Either default can be overridden, because "local" is about who runs
/// it rather than which enclave is underneath.
fn local_enrolment() -> anyhow::Result<Option<crate::enrolment::Enrolment>> {
    let nitro = env::var("ENCLAVE_MODE").map(|m| m == "nitro").unwrap_or(false);
    let enabled = match env::var("LOCAL_ENROLMENT") {
        Ok(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        Err(_) => !nitro,
    };
    if !enabled {
        return Ok(None);
    }
    let path = env::var("ENROLMENT_CODE_PATH")
        .unwrap_or_else(|_| ".local/enrolment-code".to_string());
    Ok(Some(crate::enrolment::Enrolment::open(path)?))
}
