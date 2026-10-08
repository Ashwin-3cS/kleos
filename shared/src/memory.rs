use crate::permissions::{ObjectAcl, Sensitivity};
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
/// leaving it.
///
/// Two identifiers, because a sealed record body is a *small* blob and small
/// blobs get batched. `blob_id` names what the store holds -- a Walrus Quilt,
/// or a standalone blob -- and `patch_id` locates this body inside it.
/// `patch_id` is `None` when the body was stored on its own. See ADR 0008.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EncryptedContentRef {
    pub key_id: String,
    pub scheme: String,
    pub blob_id: Option<String>,
    /// One body within a batch. A Quilt holds up to ~660 patches and each is
    /// readable without fetching the rest, so this field is the entire
    /// addressing cost of batching.
    pub patch_id: Option<String>,
    pub byte_len: u64,
}

/// The emotional register of a piece of content, as a **closed** vocabulary.
///
/// Closed on purpose, and this is the whole design. The obvious shape for
/// "what kind of content is this" is free-text tags, and free text is how an
/// extractor eventually writes `"anxious about the biopsy results"` into a field
/// built for filtering -- putting the most sensitive sentence in the record into
/// the one place that gets indexed, logged and read without opening the body.
/// A fixed vocabulary cannot carry content. It can only say which of ten coarse
/// registers a body sits in, which is enough to answer "what was I anxious about
/// last spring" and not enough to be a leak.
///
/// It is also never written to the blob store. Walrus Quilt supports immutable
/// per-patch tags, which is exactly where this would naturally go and exactly
/// where it must not: plaintext, public and permanent, beside the ciphertext
/// that was the point. See ADR 0009.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AffectTone {
    Neutral,
    Joy,
    Relief,
    Affection,
    Frustration,
    Anger,
    Anxiety,
    Sadness,
    Shame,
    Grief,
}

impl AffectTone {
    /// The lowest sensitivity a body in this register may be stored at.
    ///
    /// Affect **raises** the floor and never lowers it, which makes the label
    /// self-protecting: tagging a transcript as grief narrows who can read it
    /// rather than widening it. A connector declares sensitivity from the
    /// source it came from and cannot know that one conversation in the export
    /// was about a death; this is where that is corrected.
    pub fn sensitivity_floor(&self) -> Sensitivity {
        match self {
            // Ordinary register. Still Personal -- nothing here is public.
            AffectTone::Neutral
            | AffectTone::Joy
            | AffectTone::Relief
            | AffectTone::Frustration
            | AffectTone::Anger => Sensitivity::Personal,
            // Discloses something about a relationship or a state of mind.
            AffectTone::Affection | AffectTone::Anxiety | AffectTone::Sadness => {
                Sensitivity::Confidential
            }
            // The two registers a person is least likely to want an agent in.
            AffectTone::Shame | AffectTone::Grief => Sensitivity::Restricted,
        }
    }
}

/// The affective facet of an [`Event`]: what register its content sits in.
///
/// A facet rather than a node type, for the same reason [`Commitment`] is one:
/// it is a property of something already stored, and a parallel node type would
/// duplicate the provenance and ACL machinery that already governs it.
///
/// Deliberately has no free-text field of any kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Affect {
    pub tone: AffectTone,
    /// How strongly, in `0.0..=1.0`. Separate from `tone` because "mildly
    /// frustrated" and "furious" are the same register and want different
    /// ordering; not separate enough to be its own axis.
    pub intensity: f32,
    pub confidence: f32,
    /// Which extractor decided, e.g. "mock-extractor@v1". Same contract as
    /// [`Provenance::derived_by`]: an affect label is a derived claim about
    /// content, and a reader is entitled to know what derived it.
    pub detected_by: String,
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

/// What kind of long-term memory a claim is.
///
/// A hierarchy rather than one pile, because the three answer different
/// questions and an agent can reasonably be granted one and not another:
/// "you may read how I do things, not what I did" is a sentence a person would
/// say, and [`crate::permissions::Scope`] can only express it if the kinds are
/// named.
///
/// A **field on `Claim` rather than three node types.** A procedure is a claim
/// in every respect that matters -- it can be superseded ("we deploy with X
/// now, not Y"), contradicted, and reconciled -- and the resolver already
/// implements exactly that machinery. Three parallel node types would duplicate
/// the resolver, the promoted columns, the ACL flattening, `:Memory`
/// membership, four read paths and the permission node: four things to keep in
/// step with one. The same argument [`Commitment`] is a facet for.
///
/// A **closed vocabulary rather than a string**, for the reason [`AffectTone`]
/// is one: a free-text field built for filtering is where an extractor
/// eventually writes a sentence, and this one is promoted to an indexed column
/// and read by a grant filter.
///
/// Short-term memory is deliberately **not** a variant. It is a different
/// *state*, not a kind of long-term memory -- stored, and not searchable until
/// consolidated -- and a fourth value here would put session scratchpads in the
/// same vector index as consolidated facts, which is precisely the distinction
/// that split exists to draw. See `storage/sessions.py`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MemoryKind {
    /// A distilled decision, fact or insight: a preference, a convention, what
    /// was chosen and when.
    Episodic,
    /// A reusable workflow -- *how* a task is done.
    Procedural,
    /// A consolidated heuristic the person never stated outright.
    Tacit,
}

impl MemoryKind {
    /// The lowest sensitivity a claim of this kind may carry.
    ///
    /// Same self-protecting property as [`AffectTone::sensitivity_floor`]:
    /// labelling content can only ever *narrow* who may read it, never widen
    /// it. A `Tacit` claim is an inference *about* a person rather than
    /// something they said, assembled by watching them -- so naming it has to
    /// cost reach.
    pub fn sensitivity_floor(&self) -> crate::permissions::Sensitivity {
        use crate::permissions::Sensitivity;
        match self {
            MemoryKind::Episodic | MemoryKind::Procedural => Sensitivity::Personal,
            MemoryKind::Tacit => Sensitivity::Confidential,
        }
    }
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
    /// What register the body is in, when an extractor could tell. Sits next to
    /// `encrypted_content` because together they are the answer to "what kind of
    /// thing is in that blob" -- which is the question the blob store itself
    /// must never be able to answer. See ADR 0009.
    pub affect: Option<Affect>,
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

/// Whether the promised thing actually happened. Deliberately a *separate*
/// axis from [`ClaimStatus`]: that one is epistemic (is this still our best
/// understanding of who owes what), this one is a lifecycle (did it get
/// done). A commitment can be `Active`/`Fulfilled`, or `Superseded`/`Open`
/// -- reassigned to someone else and still outstanding. Collapsing the two
/// makes both unanswerable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FulfillmentStatus {
    /// Outstanding. Past due is `Open` plus a `due_at_ms` in the past, not
    /// a status of its own -- "overdue" is a function of the clock, and
    /// storing it would mean a writer somewhere has to keep it true.
    Open,
    /// The thing was done.
    Fulfilled,
    /// Abandoned without being done, explicitly rather than by silence.
    Dropped,
}

/// The commitment facet of a [`Claim`]: present when the claim asserts that
/// someone owes something.
///
/// A facet rather than a node type because "Alice will ship the migration by
/// Friday" is a claim in every respect that matters -- it can be superseded
/// ("actually Bob will"), contradicted and reconciled, and the resolver
/// already implements exactly that machinery over claims. A parallel node
/// type would duplicate all of it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Commitment {
    /// Entity id of whoever owes it.
    pub owed_by_entity_id: String,
    /// Entity id of whoever it is owed to. Optional: plenty of commitments
    /// are to oneself.
    pub owed_to_entity_id: Option<String>,
    /// Optional: plenty of commitments have no deadline.
    pub due_at_ms: Option<u64>,
    pub fulfillment: FulfillmentStatus,
    /// When fulfillment last moved off `Open`.
    pub settled_at_ms: Option<u64>,
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
    /// Set when this claim is also a commitment. Everything above stays the
    /// epistemic axis; this is the lifecycle one.
    pub commitment: Option<Commitment>,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole design rests on: an affect label can only ever
    /// narrow who may read a body. If any tone mapped below `Personal`, tagging
    /// a transcript would be a way to *widen* access to it.
    #[test]
    fn no_tone_lowers_the_floor_below_personal() {
        for tone in [
            AffectTone::Neutral,
            AffectTone::Joy,
            AffectTone::Relief,
            AffectTone::Affection,
            AffectTone::Frustration,
            AffectTone::Anger,
            AffectTone::Anxiety,
            AffectTone::Sadness,
            AffectTone::Shame,
            AffectTone::Grief,
        ] {
            assert!(
                tone.sensitivity_floor() >= Sensitivity::Personal,
                "{tone:?} would make tagging a way to widen access"
            );
        }
    }

    #[test]
    fn the_heaviest_registers_are_restricted() {
        assert_eq!(AffectTone::Grief.sensitivity_floor(), Sensitivity::Restricted);
        assert_eq!(AffectTone::Shame.sensitivity_floor(), Sensitivity::Restricted);
    }

    /// An affect facet must not be able to carry content. Checked structurally
    /// rather than by reading the struct: the risk is a future field, and a test
    /// that enumerates today's fields would pass right through one.
    #[test]
    fn the_only_strings_in_an_affect_are_its_tone_and_its_extractor() {
        let affect = Affect {
            tone: AffectTone::Grief,
            intensity: 0.9,
            confidence: 0.5,
            detected_by: "mock-extractor@v1".into(),
        };
        let json = serde_json::to_value(&affect).expect("serialises");
        let mut string_fields: Vec<&str> = json
            .as_object()
            .expect("an object")
            .iter()
            .filter(|(_, value)| value.is_string())
            .map(|(key, _)| key.as_str())
            .collect();
        string_fields.sort_unstable();
        assert_eq!(
            string_fields,
            ["detected_by", "tone"],
            "a new string field on Affect is a place for an extractor to write content"
        );
    }

    /// A tone this binary has never heard of must fail to deserialise rather
    /// than being silently admitted: unlike a source id, the vocabulary is
    /// closed on purpose, and an unknown value means the writer had a field we
    /// cannot reason about the sensitivity of.
    #[test]
    fn an_unknown_tone_is_rejected() {
        let json = r#"{"tone":"existential_dread","intensity":0.5,"confidence":0.5,"detected_by":"x"}"#;
        assert!(serde_json::from_str::<Affect>(json).is_err());
    }
}
