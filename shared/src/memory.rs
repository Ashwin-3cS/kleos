use crate::permissions::ObjectAcl;
use serde::{Deserialize, Serialize};

// The resolved memory schema. Types only, no logic -- every object here is
// produced and stored by the Python orchestration service (Neo4j), and this
// module exists so the Rust side speaks the exact same wire format. The
// Python mirror is orchestrator/src/orchestrator/schema.py; field names must
// stay identical on both sides.

/// Which connector a piece of memory originated from.
///
/// Deliberately an **open** identifier rather than an enum. This type is
/// compiled into the enclave, so a closed enum would put every new connector
/// on the critical path of an enclave rebuild -- and a rebuild changes the
/// measurement the attestation commits to. An opaque id means the trust
/// boundary never has to know the universe of sources.
///
/// It also has to be plural-capable downstream: an object derived from two
/// sources (a Slack thread and a Notion page about the same decision) has no
/// representable origin under a single closed variant. See
/// [`crate::permissions::ObjectAcl::sources`].
///
/// The host-side registry of *known* sources lives outside the trust
/// boundary, where it validates grants and labels things for display. That
/// split is the point: validation is a product concern, evaluation is a
/// security one, and only the latter runs in the enclave.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(transparent)]
pub struct SourceId(String);

impl SourceId {
    /// Rejects ids that could collide or confuse once they are compared as
    /// opaque strings in a permission check: a permission model whose
    /// identifiers can differ by case or whitespace invites a scope that
    /// looks like it matches but does not.
    pub fn parse(raw: &str) -> Option<Self> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.len() > 64 {
            return None;
        }
        if trimmed != raw {
            return None;
        }
        let valid = raw
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-');
        valid.then(|| Self(raw.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A pointer back into the originating source, carrying both timestamps the
/// timeline needs: when the thing happened, and when we learned about it.
/// Collapsing those two into one field is what makes a memory layer unable
/// to answer "what did I know, and when did I know it".
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SourceRef {
    pub connector: SourceId,
    pub external_id: String,
    pub url: Option<String>,
    pub occurred_at_ms: u64,
    pub ingested_at_ms: u64,
}

/// One link in a citation chain: a stored object points at the source event
/// it was derived from, which in turn points at raw source material.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Citation {
    pub event_id: String,
    pub source: SourceRef,
    pub quote: Option<String>,
}

/// Why an object is believed, expressed as a chain back to source events
/// rather than an opaque score. `confidence` is advisory only; an object
/// with no citations is not storable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Provenance {
    pub citations: Vec<Citation>,
    /// Which extractor/resolver produced this, e.g. "mock-extractor@v1".
    pub derived_by: String,
    pub confidence: f32,
    pub created_at_ms: u64,
}

/// Pointer to raw content that was Seal-encrypted inside the enclave before
/// leaving it. `blob_id` is the eventual Walrus blob; until Walrus is wired
/// the ciphertext is carried by the orchestrator and `blob_id` is `None`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EncryptedContentRef {
    pub key_id: String,
    pub scheme: String,
    pub blob_id: Option<String>,
    pub byte_len: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Person,
    Project,
    Artifact,
    Organization,
    Topic,
}

/// A person, project, artifact or organization referenced across sources.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Entity {
    pub id: String,
    pub owner_id: String,
    pub kind: EntityKind,
    pub name: String,
    pub aliases: Vec<String>,
    pub first_seen_at_ms: u64,
    pub last_seen_at_ms: u64,
    pub provenance: Provenance,
    pub acl: ObjectAcl,
}

/// An atomic ingested fact: one message, commit, calendar entry, document
/// revision. Events are never rewritten; corrections arrive as new events
/// and are reconciled at the `Claim` layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Event {
    pub id: String,
    pub owner_id: String,
    pub summary: String,
    pub body: Option<String>,
    pub entity_ids: Vec<String>,
    pub source: SourceRef,
    /// Present when the raw body was sensitive enough to be encrypted in the
    /// enclave rather than stored in the clear.
    pub encrypted_content: Option<EncryptedContentRef>,
    pub provenance: Provenance,
    pub acl: ObjectAcl,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    /// Current best understanding.
    Active,
    /// A later claim supersedes this one; kept, not deleted.
    Superseded,
    /// Conflicts with another active claim, unresolved.
    Contradicted,
    /// Folded into a reconciling claim; see `reconciled_into`.
    Reconciled,
}

/// A resolved, higher-level statement derived from one or more events --
/// the decisions/claims layer. Conflicting versions stay linked rather than
/// being overwritten, so the record can answer "when did this change, and
/// what did it replace".
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Claim {
    pub id: String,
    pub owner_id: String,
    pub statement: String,
    pub subject_entity_ids: Vec<String>,
    pub status: ClaimStatus,
    /// Claims this one replaces. The replaced claims stay stored with
    /// status `superseded`.
    pub supersedes: Vec<String>,
    /// Claims this one is in unresolved conflict with.
    pub contradicts: Vec<String>,
    /// Set on a claim whose conflict has been resolved, pointing at the
    /// claim that reconciled it.
    pub reconciled_into: Option<String>,
    pub asserted_at_ms: u64,
    pub provenance: Provenance,
    pub acl: ObjectAcl,
}

/// Tagged union of everything storable, used on the wire when an API
/// returns a heterogeneous result set.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "object_type")]
pub enum MemoryNode {
    Entity(Entity),
    Event(Event),
    Claim(Claim),
}

impl MemoryNode {
    pub fn id(&self) -> &str {
        match self {
            MemoryNode::Entity(e) => &e.id,
            MemoryNode::Event(e) => &e.id,
            MemoryNode::Claim(c) => &c.id,
        }
    }

    pub fn acl(&self) -> &ObjectAcl {
        match self {
            MemoryNode::Entity(e) => &e.acl,
            MemoryNode::Event(e) => &e.acl,
            MemoryNode::Claim(c) => &c.acl,
        }
    }

    pub fn provenance(&self) -> &Provenance {
        match self {
            MemoryNode::Entity(e) => &e.provenance,
            MemoryNode::Event(e) => &e.provenance,
            MemoryNode::Claim(c) => &c.provenance,
        }
    }
}
