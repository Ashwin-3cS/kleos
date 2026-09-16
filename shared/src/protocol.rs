use crate::identity::OwnerIdentity;
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
