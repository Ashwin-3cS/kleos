use crate::identity::OwnerIdentity;
use crate::permissions::Scope;
use serde::{Deserialize, Serialize};

/// Request envelope the gateway sends over its VSOCK-bridged TCP client to
/// the enclave's /identity/verify route. Raw tokens cross this boundary
/// unverified on purpose -- verification must happen inside the enclave,
/// never on the gateway, or the attestation over the result is meaningless.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IdentityVerifyRequest {
    pub google_token: Option<String>,
    pub github_token: Option<String>,
    pub wallet_signature: Option<String>,
    pub domain_proof: Option<String>,
}

/// Response envelope returned by the enclave (and relayed verbatim by the
/// gateway) containing the attested identity result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityVerifyResponse {
    pub identity: OwnerIdentity,
    /// Hex-encoded NSM attestation document (or mock-prefixed stub) covering
    /// the identity verification that just happened inside the enclave.
    pub attestation: String,
}

/// Request to encrypt one piece of raw source content inside the enclave,
/// before it is allowed to leave the TEE. Sent by the gateway to the
/// enclave's /seal/encrypt route on behalf of the orchestrator's ingestion
/// graph. `plaintext_b64` is base64 because JSON has no byte type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SealEncryptRequest {
    pub owner_id: String,
    pub plaintext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SealEncryptResponse {
    pub ciphertext_b64: String,
    pub key_id: String,
    /// Names the encryption scheme actually used. In mock mode this is
    /// `MOCK_SEAL_V1`, never a real Seal scheme id.
    pub scheme: String,
    /// Attestation covering the fact that this encryption happened inside
    /// the enclave.
    pub attestation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SealDecryptRequest {
    pub owner_id: String,
    pub ciphertext_b64: String,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SealDecryptResponse {
    pub plaintext_b64: String,
}

/// Owner-authorised grant of a query scope to a named agent. Minted by the
/// gateway against an authenticated owner session; the resulting token is
/// what the orchestrator's query graph presents back for introspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ScopeGrantRequest {
    pub scope: Scope,
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ScopeGrantResponse {
    pub grant_token: String,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ScopeIntrospectRequest {
    pub grant_token: String,
}

/// The authoritative scope for a query. The orchestrator never trusts a
/// scope handed to it by a caller; it introspects the grant here and
/// enforces what comes back.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ScopeIntrospectResponse {
    pub active: bool,
    pub scope: Scope,
}
