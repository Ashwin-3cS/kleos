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

/// Unseal a body for an *agent*, authorised by the grant it already holds.
///
/// The owner is **not** a field. It comes from the verified grant, exactly as
/// [`SealDecryptRequest`]'s comes from the owner session: a caller that could
/// name the owner could name somebody else's.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GrantUnsealRequest {
    pub grant_token: String,
    pub ciphertext_b64: String,
    pub key_id: String,
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
    /// The registered device key whose signature was just checked.
    ///
    /// Deliberately here and not on [`Scope`]. The scope is the thing the device
    /// *signs*, so a device id inside it would be self-asserted, and the verifier
    /// would then have to cross-check it against the token's own key id -- two
    /// sources of truth for one fact, with a forgery oracle in the gap. The
    /// signing key is a property of the token, which is what this response is
    /// about. It also keeps `Scope` shaped to become an on-chain grant object
    /// verbatim, and a signer's key is not part of a grant object's contents
    /// anywhere that signatures work.
    ///
    /// This is the only cryptographically authenticated identity in an agent's
    /// request. `Scope.agent_id` is a label the owner typed before signing and
    /// nothing checks it.
    pub key_id: String,
}

/// An agent asking for something sensitive to be *done*, rather than read.
///
/// The shape is the whole point. An agent submits an **intent** -- which action,
/// with which arguments -- and never receives the credential the action needs.
/// The enclave resolves that itself: it unseals the owner's refresh token,
/// obtains a short-lived access token in-TEE, performs the call, and drops both
/// before replying. Nothing outside the TEE sees either.
///
/// `owner_id` is set by the gateway from the verified grant, never by the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ActionIntent {
    pub owner_id: String,
    /// Resolved against a registry compiled into the enclave. An unknown id is
    /// refused rather than forwarded, for the same reason upstream hostnames are
    /// compile-time constants: the enclave's environment is supplied by the host,
    /// so a host-settable action is an operator-repointable one.
    pub action_id: String,
    /// JSON, interpreted only by the named action.
    pub args: serde_json::Value,
    pub at_ms: u64,
}

// There is deliberately no grant fingerprint here, and no grant token. The
// enclave has no use for either: it decides *what may be done in here*, while
// *who is asking* was already decided by the gateway, and the audit record is
// written by the orchestrator against the fingerprint it computed itself. Giving
// the TEE a credential it would only carry is how a boundary accumulates things
// it does not need.

/// What an agent gets back: an acknowledgement, not the material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ActionAck {
    pub ok: bool,
    pub action_id: String,
    pub at_ms: u64,
    /// A hash over what the action actually did, so two acks can be compared and
    /// a replay recognised, without the content crossing the boundary.
    pub digest: String,
    /// One line, bounded, safe to put in an agent's context. Not the response
    /// body: an action that produced something large says so and seals it.
    pub summary: String,
    /// Set when the result was too large to summarise. The agent must then pass
    /// the `may_unseal` gate to read any of it -- acknowledgement by default,
    /// disclosure as a second and separately granted step.
    #[serde(default)]
    pub sealed_ref: Option<crate::memory::EncryptedContentRef>,
    /// Present only when `ok` is false. The reason, never the provider's raw
    /// error: a provider error can carry request URLs and token prefixes.
    #[serde(default)]
    pub error: Option<String>,
}

/// Request the gateway sends to the enclave's `/oauth/exchange` route.
///
/// The authorization `code` crosses this boundary because the gateway must
/// receive the provider's redirect, but the *exchange* deliberately does
/// not happen here: a code is single-use and short-lived, whereas the
/// refresh token it buys is standing access to the user's mailbox. Only the
/// enclave holds the client secret and only the enclave ever sees the
/// refresh token in plaintext.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OAuthExchangeRequest {
    pub provider: String,
    pub code: String,
    pub redirect_uri: String,
    /// PKCE verifier held by the gateway between /auth/authorize and the
    /// callback; never leaves the host except to the provider, via here.
    pub code_verifier: String,
}

// `code` and `code_verifier` are single-use credentials. Deriving Debug
// would put them into any tracing/error formatting that touches the struct.
impl std::fmt::Debug for OAuthExchangeRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthExchangeRequest")
            .field("provider", &self.provider)
            .field("code", &"<redacted>")
            .field("redirect_uri", &self.redirect_uri)
            .field("code_verifier", &"<redacted>")
            .finish()
    }
}

/// What the enclave gives back after exchanging a code. Everything here is
/// either non-sensitive metadata or ciphertext.
///
/// Note what is *absent*: the access token. It is used inside the enclave to
/// verify the account identity and then dropped, because a host that holds
/// an access token can read the mailbox for its lifetime.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct OAuthExchangeResponse {
    pub provider: String,
    pub identity: OwnerIdentity,
    /// Base64 of the sealed refresh token. `None` when the provider issued
    /// no refresh token (e.g. Google without `access_type=offline`, or a
    /// re-consent that reuses an existing grant).
    pub sealed_refresh_token_b64: Option<String>,
    pub sealed_key_id: Option<String>,
    /// Scheme id of the seal applied. `MOCK_SEAL_V1` in mock mode -- see
    /// enclave/src/services/seal.rs; that is obfuscation, not encryption.
    pub seal_scheme: Option<String>,
    pub scopes: Vec<String>,
    pub granted_at_ms: u64,
    /// Expiry of the *access* token the enclave discarded, kept only so the
    /// host can tell how stale a grant is. Refresh tokens have no fixed
    /// expiry at either provider.
    pub access_token_expires_at_ms: Option<u64>,
    pub attestation: String,
}
