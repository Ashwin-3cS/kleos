//! Where a sealed content field is, and how to recognise one.
//!
//! This is the Rust half of a format Python owns. `storage/content.py` decides
//! which fields of a stored object carry content, seals each one in place and
//! writes it back as a self-labelling string:
//!
//! ```text
//! KSEAL1:<key_id>:<base64 ciphertext>
//! ```
//!
//! Until ADR 0024 nothing on this side had to read that, because unsealing
//! happened in the orchestrator. Under A1 the enclave is what unseals, so it
//! needs to know the same two things Python knows: how to parse one of these,
//! and **which fields are ever one**.
//!
//! ## Why the registry lives here rather than in the enclave
//!
//! It is a mirror, and a mirror that drifts is worse than no mirror. A field
//! added to the Python list and not to this one is stored sealed and handed to
//! the device still sealed -- not an error anywhere, just unreadable text in an
//! agent's context. A field added here and not there is harmless but a lie. So
//! the registry sits in `shared`, next to the schema it describes, with one
//! parity test (`test_schema_parity.py`) reading both sources.
//!
//! [`content_fields`] hands back `&mut String` rather than names, which is what
//! lets the registry be a single `match` that both a sealer and an unsealer can
//! walk. Naming the fields as strings instead would need reflection Rust does
//! not have, and a second match somewhere to act on the names.

use crate::memory::{MemoryNode, Provenance};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

/// The version is in the prefix so a future scheme can coexist with stored
/// data. Must equal `MARKER` in `storage/content.py`.
pub const MARKER: &str = "KSEAL1:";

#[derive(Debug)]
pub enum ContentError {
    /// The field is not sealed at all, or is sealed under a scheme this build
    /// does not know.
    NotSealed,
    /// Right prefix, wrong contents. Deliberately distinct from `NotSealed`: a
    /// plaintext field is an ordinary state, a corrupt sealed one is not.
    Malformed(String),
}

impl std::fmt::Display for ContentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContentError::NotSealed => write!(f, "not a {MARKER} field"),
            ContentError::Malformed(why) => write!(f, "malformed sealed field: {why}"),
        }
    }
}

pub fn is_sealed(value: &str) -> bool {
    value.starts_with(MARKER)
}

pub fn pack(key_id: &str, ciphertext: &[u8]) -> String {
    format!("{MARKER}{key_id}:{}", B64.encode(ciphertext))
}

/// Splits a sealed field into the key it was sealed under and the bytes.
///
/// The key id travels with the field because unsealing needs it and only the
/// enclave can use it -- so a store full of these discloses which key, and
/// nothing else.
pub fn unpack(value: &str) -> Result<(String, Vec<u8>), ContentError> {
    let body = value.strip_prefix(MARKER).ok_or(ContentError::NotSealed)?;
    let (key_id, payload) = body
        .split_once(':')
        .ok_or_else(|| ContentError::Malformed("no separator after the key id".into()))?;
    if key_id.is_empty() || payload.is_empty() {
        return Err(ContentError::Malformed(
            "a sealed field needs both a key id and a payload".into(),
        ));
    }
    let ciphertext = B64
        .decode(payload.as_bytes())
        .map_err(|e| ContentError::Malformed(format!("payload is not base64: {e}")))?;
    Ok((key_id.to_string(), ciphertext))
}

/// Every content-bearing string in this node, by mutable reference.
///
/// **The one place that decides what counts as content.** Adding a field to the
/// schema means deciding whether it belongs here; a field absent from this list
/// is a field stored in the clear, and that is a choice rather than an
/// oversight.
///
/// Left out on purpose, and the reason is the same each time -- the host needs
/// them to do its half of a read: ids, owner ids, timestamps, labels, edge
/// types, ACL fields, claim status, commitment dates, entity references, and
/// embeddings. See ADR 0024 on what stays visible.
pub fn content_fields(node: &mut MemoryNode) -> Vec<&mut String> {
    let mut out: Vec<&mut String> = Vec::new();
    match node {
        MemoryNode::Entity(entity) => {
            out.push(&mut entity.name);
            out.extend(entity.aliases.iter_mut());
            out.extend(citation_quotes(&mut entity.provenance));
        }
        MemoryNode::Event(event) => {
            out.push(&mut event.summary);
            if let Some(body) = event.body.as_mut() {
                out.push(body);
            }
            out.extend(citation_quotes(&mut event.provenance));
        }
        MemoryNode::Claim(claim) => {
            out.push(&mut claim.statement);
            out.extend(citation_quotes(&mut claim.provenance));
        }
    }
    out
}

/// A citation quote is verbatim source text, so it is content wherever it hangs.
///
/// The one place this registry has to know about structure rather than just
/// field names, which is why it is a helper and not three more lines above.
fn citation_quotes(provenance: &mut Provenance) -> impl Iterator<Item = &mut String> {
    provenance
        .citations
        .iter_mut()
        .filter_map(|citation| citation.quote.as_mut())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::{Citation, Claim, ClaimStatus, Entity, EntityKind, Event, SourceId, SourceRef};
    use crate::permissions::{ObjectAcl, Sensitivity};

    fn acl() -> ObjectAcl {
        ObjectAcl {
            owner_id: "owner-1".into(),
            sources: vec![SourceId::parse("text").unwrap()],
            sensitivity: Sensitivity::Personal,
            entity_kinds: vec![EntityKind::Project],
            occurred_at_ms: 1_000,
            denied_agents: vec![],
            memory_kind: None,
        }
    }

    fn provenance(quote: Option<&str>) -> Provenance {
        Provenance {
            citations: vec![Citation {
                event_id: "e1".into(),
                source: SourceRef {
                    connector: SourceId::parse("text").unwrap(),
                    external_id: "x1".into(),
                    url: None,
                    occurred_at_ms: 1_000,
                    ingested_at_ms: 1_000,
                },
                quote: quote.map(str::to_string),
            }],
            derived_by: "test".into(),
            confidence: 1.0,
            created_at_ms: 1_000,
            authority: None,
            actor_agent_id: None,
            actor_device_id: None,
            actor_session_id: None,
        }
    }

    #[test]
    fn a_packed_field_round_trips() {
        let packed = pack("mock-seal-abcd", b"ciphertext bytes");
        assert!(is_sealed(&packed));
        let (key_id, bytes) = unpack(&packed).unwrap();
        assert_eq!(key_id, "mock-seal-abcd");
        assert_eq!(bytes, b"ciphertext bytes");
    }

    #[test]
    fn plaintext_is_not_sealed_and_says_so_distinctly() {
        // A field that was never sealed is an ordinary state -- content sealing
        // is off by default -- so it must not look like corruption.
        assert!(!is_sealed("we decided on Neo4j"));
        assert!(matches!(
            unpack("we decided on Neo4j"),
            Err(ContentError::NotSealed)
        ));
    }

    #[test]
    fn a_truncated_sealed_field_is_malformed_rather_than_plaintext() {
        assert!(matches!(
            unpack("KSEAL1:keyonly"),
            Err(ContentError::Malformed(_))
        ));
        assert!(matches!(unpack("KSEAL1::payload"), Err(ContentError::Malformed(_))));
        assert!(matches!(
            unpack("KSEAL1:key:not base64!!"),
            Err(ContentError::Malformed(_))
        ));
    }

    #[test]
    fn every_content_field_of_a_claim_is_reachable() {
        let mut node = MemoryNode::Claim(Claim {
            id: "c1".into(),
            owner_id: "owner-1".into(),
            statement: "statement".into(),
            subject_entity_ids: vec![],
            status: ClaimStatus::Active,
            supersedes: vec![],
            contradicts: vec![],
            reconciled_into: None,
            commitment: None,
            asserted_at_ms: 1_000,
            memory_kind: None,
            provenance: provenance(Some("quote")),
            acl: acl(),
        });
        let found: Vec<String> = content_fields(&mut node).iter().map(|f| f.to_string()).collect();
        assert_eq!(found, vec!["statement", "quote"]);
    }

    #[test]
    fn an_events_body_is_content_and_its_absence_is_not_an_empty_one() {
        // `body` is Option, so a bodyless event must yield one field rather than
        // one field and an empty string -- an empty string would be handed to
        // the unsealer, fail to parse, and have to be special-cased there.
        let mut event = Event {
            id: "e1".into(),
            owner_id: "owner-1".into(),
            summary: "summary".into(),
            body: None,
            entity_ids: vec![],
            source: SourceRef {
                connector: SourceId::parse("text").unwrap(),
                external_id: "x1".into(),
                url: None,
                occurred_at_ms: 1_000,
                ingested_at_ms: 1_000,
            },
            encrypted_content: None,
            affect: None,
            provenance: provenance(None),
            acl: acl(),
        };
        let mut node = MemoryNode::Event(event.clone());
        assert_eq!(content_fields(&mut node).len(), 1);

        event.body = Some("body".into());
        let mut node = MemoryNode::Event(event);
        let found: Vec<String> = content_fields(&mut node).iter().map(|f| f.to_string()).collect();
        assert_eq!(found, vec!["summary", "body"]);
    }

    #[test]
    fn an_entitys_aliases_are_each_content() {
        let mut node = MemoryNode::Entity(Entity {
            id: "n1".into(),
            owner_id: "owner-1".into(),
            kind: EntityKind::Project,
            name: "Kleos".into(),
            aliases: vec!["kleos".into(), "the harness".into()],
            first_seen_at_ms: 1_000,
            last_seen_at_ms: 1_000,
            provenance: provenance(None),
            acl: acl(),
        });
        let found: Vec<String> = content_fields(&mut node).iter().map(|f| f.to_string()).collect();
        assert_eq!(found, vec!["Kleos", "kleos", "the harness"]);
    }

    #[test]
    fn writing_through_the_references_changes_the_node() {
        // The whole point of handing back `&mut`: one registry, walked by both
        // the sealer and the unsealer.
        let mut node = MemoryNode::Entity(Entity {
            id: "n1".into(),
            owner_id: "owner-1".into(),
            kind: EntityKind::Project,
            name: "Kleos".into(),
            aliases: vec![],
            first_seen_at_ms: 1_000,
            last_seen_at_ms: 1_000,
            provenance: provenance(Some("quote")),
            acl: acl(),
        });
        for field in content_fields(&mut node) {
            *field = pack("k", field.as_bytes());
        }
        match &node {
            MemoryNode::Entity(entity) => {
                assert!(is_sealed(&entity.name));
                assert!(is_sealed(entity.provenance.citations[0].quote.as_ref().unwrap()));
            }
            _ => unreachable!(),
        }
    }
}
