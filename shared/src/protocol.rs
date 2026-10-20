use crate::identity::OwnerIdentity;
use crate::memory::MemoryNode;
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

/// Seal content for an *agent*, authorised by the grant it already holds.
///
/// The symmetric half of [`GrantUnsealRequest`], and it exists for the same
/// reason: [`SealEncryptRequest`] takes the owner from an **owner session**,
/// and an agent has none. Without this, turning on content-at-rest encryption
/// stops an agent writing at all -- the seal on the way into storage fails with
/// "no owner session" long before anything reaches the database.
///
/// The owner is not a field here either. A caller that could name the owner
/// could seal content under somebody else's key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct GrantSealRequest {
    pub grant_token: String,
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

// ---------------------------------------------------------------------------
// Assembly: the enclave unseals, filters, assembles and re-seals (ADR 0024)
// ---------------------------------------------------------------------------

/// What the host asks the enclave to turn into an answer.
///
/// The host has already done the part it can do without reading anything:
/// ranked on embeddings and structure, both in the clear, and picked the top-k
/// candidates. It sends them here still sealed. It does **not** send a
/// permission verdict -- that is computed in here, against the content, which
/// is the difference between the enclave assembling and the enclave decrypting.
///
/// Three fields are set by the gateway from the verified grant and are refused
/// from a caller: `owner_id`, `recipient_key_b64` and `recipient_key_id`. See
/// the note on `recipient_key_b64`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AssembleRequest {
    pub owner_id: String,
    /// The verified scope the grant carried. Verified by the gateway, which is
    /// the only thing holding a device key registry; re-checking the signature
    /// in here would need that registry inside the measured image for no gain,
    /// since the host chooses what reaches this route either way.
    pub scope: Scope,
    /// Raw X25519 public key of the device the answer is sealed to, base64.
    ///
    /// **Derived, never supplied.** The gateway looks this up from the
    /// registration row of the key that signed the grant. A caller-supplied
    /// recipient would mean anyone holding a leaked grant could ask for the
    /// answer sealed to a key they control, which is the whole system in one
    /// field. Same rule `owner_id` already follows on every route.
    pub recipient_key_b64: String,
    /// The signing key id the recipient was resolved from, echoed back in the
    /// response so the device can check the answer came back to the key it
    /// asked with rather than to another of the owner's devices.
    pub recipient_key_id: String,
    /// Carried through so the assembled answer can state what it answers.
    /// Content, so it is inside the sealed payload and not in the response.
    pub question: String,
    pub candidates: Vec<AssembleCandidate>,
}

/// One ranked candidate, as the host holds it: structure in the clear, content
/// still sealed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AssembleCandidate {
    pub node: MemoryNode,
    /// The host's ranking score.
    ///
    /// Carried for the record and acted on by nothing. The assembled lines keep
    /// the order the host sent, because the host did the ranking either way --
    /// re-sorting in here on a number the host computed would look like the
    /// enclave had an opinion about relevance, and it has none.
    pub score: f64,
}

/// What comes back: an opaque blob, plus the structure the host is entitled to.
///
/// The split is the ADR 0024 line drawn on one struct. `sealed` is the content
/// and the host cannot read it. Everything beside it -- which ids were
/// disclosed, which were denied and why, how many were considered -- is
/// structure the host already had, and the orchestrator needs it to write the
/// read log (ADR 0005). Withholding it would not hide anything and would make
/// the disclosure record unwritable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AssembleResponse {
    pub sealed: SealedToDevice,
    pub disclosed_ids: Vec<String>,
    pub denials: Vec<AssembleDenial>,
    pub considered: usize,
    /// Covers the enclave public key, the recipient key and the ciphertext, so
    /// a verifier can tell this assembly happened in here and was sealed to
    /// that device. Unverified by anything today -- step 3 of the roadmap.
    pub attestation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AssembleDenial {
    pub id: String,
    pub reason: crate::permissions::DenyReason,
}

/// A payload encrypted to one device's X25519 key.
///
/// Not [`SealEncryptResponse`], which is the owner's at-rest seal and in mock
/// mode is a reversible XOR. This one is real AEAD in every build, because
/// nothing external is missing for it: the recipient key is in a Postgres row
/// and the ephemeral half is generated here. Keeping it mock would make the
/// one thing ADR 0024 actually decides untestable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SealedToDevice {
    /// Self-labelling, in the spirit of `MOCK_SEAL_V1` and `KSEAL1`.
    pub scheme: String,
    pub recipient_key_id: String,
    /// The enclave's single-use X25519 public key for this reply. The device
    /// agrees against it; nothing else ever uses it again.
    pub ephemeral_public_key_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

/// What is inside [`SealedToDevice::ciphertext_b64`] once the device opens it.
///
/// Declared here rather than left as free-form JSON because three
/// implementations have to agree on it: the enclave writes it, the MCP client
/// reads it, and the dashboard reads it. The shape mirrors the orchestrator's
/// `QueryAnswer` minus the fields that stayed outside -- `denied` and
/// `considered` are in the response, in the clear, where the read log needs
/// them.
///
/// **Formatting, not synthesis.** ADR 0024 pins this: a synthesising assembler
/// would put a model call inside the enclave, because that is where the
/// plaintext is. The agent has its own model, and citations it can check beat
/// prose it has to trust.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AssembledAnswer {
    pub question: String,
    pub answered: bool,
    pub text: String,
    pub citations: Vec<AssembledCitation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AssembledCitation {
    pub object_id: String,
    pub label: String,
    pub source: String,
    pub url: Option<String>,
    pub occurred_at_ms: u64,
    pub ingested_at_ms: Option<u64>,
}
