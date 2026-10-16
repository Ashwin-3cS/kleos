//! The Rust half of the assembled-line format.
//!
//! ADR 0024 moved the assembler into the enclave, which means the strings an
//! agent reads are produced here now and were produced in `graphs/query.py`
//! until now -- and still are on the paths A1 has not reached. Two
//! implementations of one format drift, and the drift is silent: nothing
//! errors, the citations simply stop lining up with the lines they belong to.
//!
//! Neither side owns the format. `shared/fixtures/assembled_lines.json` does,
//! and `orchestrator/tests/test_assembled_answer_parity.py` reads the same
//! file. A change to the wording has to be made in the fixture first, and until
//! both follow, both suites fail.

use enclave::services::assemble::{citation_of, decline_text, line_of};
use serde_json::Value;
use shared::memory::{
    Claim, ClaimStatus, Entity, EntityKind, Event, MemoryNode, Provenance, SourceRef,
};
use shared::{AssembleDenial, ObjectAcl, Sensitivity, SourceId};

fn fixture() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../shared/fixtures/assembled_lines.json");
    serde_json::from_slice(&std::fs::read(&path).expect("the fixture is readable")).unwrap()
}

fn source() -> SourceId {
    SourceId::parse("text").unwrap()
}

fn acl() -> ObjectAcl {
    ObjectAcl {
        owner_id: "owner-1".into(),
        sources: vec![source()],
        sensitivity: Sensitivity::Personal,
        entity_kinds: vec![EntityKind::Project],
        occurred_at_ms: 1_000,
        denied_agents: vec![],
        memory_kind: None,
    }
}

fn provenance() -> Provenance {
    Provenance {
        citations: vec![],
        derived_by: "parity".into(),
        confidence: 1.0,
        created_at_ms: 1_000,
        authority: None,
        actor_agent_id: None,
        actor_device_id: None,
        actor_session_id: None,
    }
}

/// Builds the node one fixture case describes. The Python side builds the same
/// node from the same descriptor, which is what makes the comparison mean
/// something -- a shared serialised *node* would only prove the two agree about
/// serde.
fn node_of(case: &Value) -> MemoryNode {
    let id = case["id"].as_str().unwrap().to_string();
    let text = case["text"].as_str().unwrap().to_string();
    match case["kind"].as_str().unwrap() {
        "claim" => MemoryNode::Claim(Claim {
            id,
            owner_id: "owner-1".into(),
            statement: text,
            subject_entity_ids: vec![],
            status: serde_json::from_value::<ClaimStatus>(case["status"].clone()).unwrap(),
            supersedes: vec![],
            contradicts: vec![],
            reconciled_into: None,
            commitment: None,
            asserted_at_ms: 1_000,
            memory_kind: None,
            provenance: provenance(),
            acl: acl(),
        }),
        "event" => MemoryNode::Event(Event {
            id,
            owner_id: "owner-1".into(),
            summary: text,
            // Deliberately set, and deliberately not expected in any line: an
            // event's body is content that the formatter must not reach for.
            body: Some("a body no line may ever contain".into()),
            entity_ids: vec![],
            source: SourceRef {
                connector: source(),
                external_id: "x1".into(),
                url: None,
                occurred_at_ms: 1_000,
                ingested_at_ms: 2_000,
            },
            encrypted_content: None,
            affect: None,
            provenance: provenance(),
            acl: acl(),
        }),
        "entity" => MemoryNode::Entity(Entity {
            id,
            owner_id: "owner-1".into(),
            kind: serde_json::from_value::<EntityKind>(case["entity_kind"].clone()).unwrap(),
            name: text,
            aliases: vec![],
            first_seen_at_ms: 1_000,
            last_seen_at_ms: 1_000,
            provenance: provenance(),
            acl: acl(),
        }),
        other => panic!("the fixture names an unknown node kind {other:?}"),
    }
}

#[test]
fn every_line_matches_the_fixture() {
    let fixture = fixture();
    let cases = fixture["lines"].as_array().expect("lines");
    assert!(!cases.is_empty(), "an empty fixture would pass vacuously");

    for case in cases {
        let why = case["case"].as_str().unwrap_or("");
        assert_eq!(
            line_of(&node_of(case)),
            case["expected"].as_str().unwrap(),
            "{why}"
        );
    }
}

#[test]
fn every_decline_matches_the_fixture() {
    let fixture = fixture();
    let cases = fixture["declines"].as_array().expect("declines");
    assert!(!cases.is_empty(), "an empty fixture would pass vacuously");

    for case in cases {
        let denials: Vec<AssembleDenial> = case["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, reason)| AssembleDenial {
                id: format!("obj-{i}"),
                reason: serde_json::from_value(reason.clone()).unwrap(),
            })
            .collect();
        let considered = case["considered"].as_u64().unwrap() as usize;
        assert_eq!(
            decline_text(considered, &denials),
            case["expected"].as_str().unwrap(),
            "{}",
            case["case"].as_str().unwrap_or("")
        );
    }
}

#[test]
fn a_citation_names_the_object_and_never_quotes_it() {
    // The citation is the half an agent can check, so what it must carry is
    // identity and provenance -- and what it must not carry is the statement,
    // which is already in the line and would be a second copy to keep in step.
    let fixture = fixture();
    for case in fixture["lines"].as_array().unwrap() {
        let node = node_of(case);
        let citation = citation_of(&node);
        assert_eq!(citation.object_id, case["id"].as_str().unwrap());
        assert_eq!(citation.source, "text");
        let rendered = serde_json::to_string(&citation).unwrap();
        assert!(
            !rendered.contains(case["text"].as_str().unwrap()),
            "a citation repeated the content: {rendered}"
        );
    }
}
