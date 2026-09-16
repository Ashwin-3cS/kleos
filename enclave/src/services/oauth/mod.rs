pub mod github;
pub mod google;

use crate::error::EnclaveError;
use async_trait::async_trait;
use shared::OAuthSignal;

/// A provider that turns a raw OAuth token into a verified `OAuthSignal`.
/// Implementations must perform the actual verification call themselves
/// (against the provider's API, through a VSOCK-bridged tunnel) -- the
/// gateway is never trusted to have done this, since only a verification
/// that happens inside the enclave is covered by the NSM attestation.
#[async_trait]
pub trait OAuthProvider {
    async fn verify(&self, token: &str) -> Result<OAuthSignal, EnclaveError>;
}
