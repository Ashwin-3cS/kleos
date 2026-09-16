use crate::error::EnclaveError;
use shared::{OAuthSignal, OwnerIdentity, TrustTier};

/// Verifies a raw wallet signature over a fixed challenge string and
/// returns the recovered address as a signal. Real signature recovery
/// (secp256k1/ed25519 depending on chain) is Phase 2 work once a wallet
/// flow is wired up; the type/route shape is settled now so Phase 2 only
/// has to fill this in.
pub fn verify_wallet_signature(signature: &str) -> Result<OAuthSignal, EnclaveError> {
    todo!("wallet signature recovery not implemented in Phase 1: {signature}")
}

/// Verifies a domain-ownership proof (e.g. DNS TXT record or well-known
/// file) and returns it as a signal. Phase 2 work, same rationale as above.
pub fn verify_domain_proof(proof: &str) -> Result<OAuthSignal, EnclaveError> {
    todo!("domain proof verification not implemented in Phase 1: {proof}")
}

/// Derives a stable owner id and trust tier from the set of signals
/// verified for this request.
pub fn compute_identity(owner_id: String, signals: Vec<OAuthSignal>) -> OwnerIdentity {
    let trust_tier = TrustTier::from_signals(&signals);
    OwnerIdentity {
        owner_id,
        signals,
        trust_tier,
    }
}
