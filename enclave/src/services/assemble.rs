//! Unseal, filter, assemble, re-seal. The read path of ADR 0024.
//!
//! The host ranked on embeddings and structure, both in the clear, and picked
//! the top-k candidates without reading one of them. What arrives here is those
//! candidates with their content still sealed. What leaves is a blob only the
//! asking device can open, plus the structure the host already had.
//!
//! ## Why this is small, and must stay small
//!
//! The read path calls no model. The orchestrator's `assemble` retrieves,
//! ranks, permission-checks and *formats* -- so moving it in here is unseal,
//! filter, format, seal, and no LLM client comes with it. ADR 0024 pins that:
//! a synthesising assembler would put a model call inside the enclave, because
//! this is where the plaintext is, turning a routine you can read in one
//! sitting into one containing an inference stack. An attestation is only worth
//! what it measures.
//!
//! ## The order of the four steps is a decision
//!
//! Permission is evaluated **before** anything is unsealed, not after. The ACL
//! is structural and in the clear, so the check needs no plaintext -- which
//! means the number of objects decrypted equals the number about to be
//! disclosed. The decrypt budget is the disclosure budget (ADR 0010), and it
//! only stays that way if the filter runs first.
//!
//! What moved inside is *where the verdict is computed*. Until now
//! `graphs/query.py` evaluated it in Python on the host, so an operator who
//! controlled the host controlled every "may this agent see this" decision and
//! the enclave was handed the answer. Now the enclave decides and the host
//! learns the outcome.
//!
//! ## The formatting is a mirror
//!
//! `_line_of` and `_citation_of` in `graphs/query.py` produced these exact
//! strings, and existing clients parse them. The duplication is real and is the
//! price of the assembler being somewhere the host cannot read; it is bounded,
//! because this is the whole of it, and
//! `test_assembled_answer_parity.py` holds the two in step.

use crate::error::EnclaveError;
use crate::services::seal::{self, SealEncrypted};
use shared::content;
use shared::memory::{ClaimStatus, MemoryNode};
use shared::{
    evaluate, AssembleCandidate, AssembleDenial, AssembledAnswer, AssembledCitation, ObjectAcl,
    PermissionDecision, Scope,
};

/// Everything the route needs to answer, once the content has been dealt with.
pub struct Assembly {
    pub answer: AssembledAnswer,
    pub disclosed_ids: Vec<String>,
    pub denials: Vec<AssembleDenial>,
    pub considered: usize,
}

/// Decides, unseals and formats. Does not encrypt -- the route seals what comes
/// back, so that this function is testable against its plaintext output and the
/// sealing has one call site.
pub async fn assemble(
    owner_id: &str,
    scope: &Scope,
    question: &str,
    candidates: Vec<AssembleCandidate>,
) -> Result<Assembly, EnclaveError> {
    // The enclave's own clock, deliberately, rather than a timestamp in the
    // request. `ActionIntent` takes `at_ms` from the gateway because the ack
    // records when the host asked; a permission verdict is different -- a grant
    // expiry checked against a time the host supplied is a grant expiry the
    // host can rewind. Under `nitro` the clock is still seeded from outside, so
    // this narrows the window rather than closing it.
    let now_ms = now_ms();

    // The owner is taken from the verified grant one layer up and passed in; a
    // scope naming a different one would mean the gateway resolved two
    // different owners for one request, which is a bug rather than an attack,
    // and `evaluate` would deny every object anyway. Checked here so it reads
    // as a refusal instead of an empty answer.
    if scope.owner_id != owner_id {
        return Err(EnclaveError::BadRequest(
            "the scope's owner does not match the owner this request was resolved to".into(),
        ));
    }

    let considered = candidates.len();
    let mut permitted = Vec::new();
    let mut denials = Vec::new();

    for candidate in candidates {
        let node = candidate.node;
        match evaluate(scope, node.acl(), now_ms) {
            PermissionDecision::Allow => permitted.push(node),
            PermissionDecision::Deny(reason) => denials.push(AssembleDenial {
                id: node.id().to_string(),
                reason,
            }),
        }
    }

    let disclosed_ids: Vec<String> = permitted.iter().map(|n| n.id().to_string()).collect();

    if permitted.is_empty() {
        return Ok(Assembly {
            answer: AssembledAnswer {
                question: question.to_string(),
                answered: false,
                text: decline_text(considered, &denials),
                citations: Vec::new(),
            },
            disclosed_ids,
            denials,
            considered,
        });
    }

    let mut lines = Vec::with_capacity(permitted.len());
    let mut citations = Vec::with_capacity(permitted.len());
    for mut node in permitted {
        unseal_content(owner_id, &mut node).await?;
        lines.push(line_of(&node));
        citations.push(citation_of(&node));
    }

    Ok(Assembly {
        answer: AssembledAnswer {
            question: question.to_string(),
            answered: true,
            text: lines.join("\n"),
            citations,
        },
        disclosed_ids,
        denials,
        considered,
    })
}

/// Turns every sealed field of one node back into plaintext, in place.
///
/// A field that is not sealed is left alone rather than treated as an error:
/// `ENCRYPT_CONTENT_AT_REST` is off by default, so a store holding plaintext is
/// an ordinary state and a mixed store is what a deployment turning it on looks
/// like mid-flight.
async fn unseal_content(owner_id: &str, node: &mut MemoryNode) -> Result<(), EnclaveError> {
    // Collected before the loop because `content_fields` borrows the node
    // mutably, and the unseal is a future that must not hold that borrow across
    // an await for every field at once.
    let sealed: Vec<(usize, String)> = content::content_fields(node)
        .iter()
        .enumerate()
        .filter(|(_, value)| content::is_sealed(value))
        .map(|(index, value)| (index, value.to_string()))
        .collect();

    let mut plaintexts = Vec::with_capacity(sealed.len());
    for (index, value) in sealed {
        let (key_id, ciphertext) = content::unpack(&value)
            .map_err(|e| EnclaveError::BadRequest(format!("{} in {}", e, node.id())))?;
        let plaintext = seal::decrypt(
            owner_id,
            SealEncrypted {
                ciphertext,
                key_id,
                scheme: String::new(),
            },
        )
        .await?;
        let text = String::from_utf8(plaintext).map_err(|_| {
            EnclaveError::Internal(format!("a sealed field of {} is not utf-8", node.id()))
        })?;
        plaintexts.push((index, text));
    }

    let mut fields = content::content_fields(node);
    for (index, text) in plaintexts {
        *fields[index] = text;
    }
    Ok(())
}

/// One assembled line. Mirrors `_line_of` in `graphs/query.py`, character for
/// character -- clients parse these.
pub fn line_of(node: &MemoryNode) -> String {
    match node {
        MemoryNode::Claim(claim) => {
            let marker = match claim.status {
                ClaimStatus::Active => String::new(),
                other => format!(" [{}]", status_name(other)),
            };
            format!("- {}{} ({})", claim.statement, marker, claim.id)
        }
        MemoryNode::Event(event) => format!("- {} ({})", event.summary, event.id),
        MemoryNode::Entity(entity) => format!(
            "- {}: {} ({})",
            entity_kind_name(entity),
            entity.name,
            entity.id
        ),
    }
}

/// Mirrors `_citation_of`. The first citation only, because that is the one the
/// Python assembler used and a client comparing the two must see the same list.
pub fn citation_of(node: &MemoryNode) -> AssembledCitation {
    let first = node.provenance().citations.first();
    let acl: &ObjectAcl = node.acl();
    AssembledCitation {
        object_id: node.id().to_string(),
        label: label_of(node).to_string(),
        source: acl
            .sources
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(","),
        url: first.and_then(|c| c.source.url.clone()),
        occurred_at_ms: acl.occurred_at_ms,
        ingested_at_ms: first.map(|c| c.source.ingested_at_ms),
    }
}

/// Mirrors `_decline_text`.
///
/// It names the deny reasons, which is a disclosure and an intended one: an
/// agent told "outside time window" can ask for a different window, and an
/// agent told nothing retries blind. The reasons are properties of the grant
/// the owner signed, so they say nothing about the memory behind them.
pub fn decline_text(considered: usize, denials: &[AssembleDenial]) -> String {
    if considered == 0 {
        return "No memory matches this question.".to_string();
    }
    let mut reasons: Vec<String> = denials
        .iter()
        .map(|d| deny_reason_name(d.reason).replace('_', " "))
        .collect();
    reasons.sort();
    reasons.dedup();
    format!(
        "Declining to answer: {} candidate memory object(s) matched, \
         but none are within the requesting agent's scope ({}).",
        considered,
        reasons.join(", ")
    )
}

fn label_of(node: &MemoryNode) -> &'static str {
    match node {
        MemoryNode::Entity(_) => "Entity",
        MemoryNode::Event(_) => "Event",
        MemoryNode::Claim(_) => "Claim",
    }
}

/// The serde name, which is what Python's enum values are. Via `serde_json`
/// rather than a hand-written match, so a variant added to the schema cannot
/// pick up a different spelling on this side.
fn serde_name<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

fn status_name(status: ClaimStatus) -> String {
    serde_name(&status)
}

fn deny_reason_name(reason: shared::DenyReason) -> String {
    serde_name(&reason)
}

fn entity_kind_name(entity: &shared::Entity) -> String {
    serde_name(&entity.kind)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as u64
}

#[cfg(all(test, not(feature = "nitro")))]
mod tests {
    use super::*;
    use shared::memory::{Citation, Claim, Entity, EntityKind, Event, Provenance, SourceRef};
    use shared::{DenyReason, MemoryKind, SourceId, Sensitivity};

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

    fn scope() -> Scope {
        Scope {
            agent_id: "agent-1".into(),
            owner_id: "owner-1".into(),
            sources: vec![source()],
            entity_kinds: vec![EntityKind::Project],
            max_sensitivity: Sensitivity::Confidential,
            memory_kinds: vec![MemoryKind::Episodic, MemoryKind::Procedural],
            ..Default::default()
        }
    }

    fn provenance() -> Provenance {
        Provenance {
            citations: vec![Citation {
                event_id: "e1".into(),
                source: SourceRef {
                    connector: source(),
                    external_id: "x1".into(),
                    url: Some("https://example.invalid/1".into()),
                    occurred_at_ms: 1_000,
                    ingested_at_ms: 2_000,
                },
                quote: Some("a verbatim quote".into()),
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

    fn claim(id: &str, statement: &str) -> Claim {
        Claim {
            id: id.into(),
            owner_id: "owner-1".into(),
            statement: statement.into(),
            subject_entity_ids: vec![],
            status: ClaimStatus::Active,
            supersedes: vec![],
            contradicts: vec![],
            reconciled_into: None,
            commitment: None,
            asserted_at_ms: 1_000,
            memory_kind: None,
            provenance: provenance(),
            acl: acl(),
        }
    }

    fn candidate(node: MemoryNode) -> AssembleCandidate {
        AssembleCandidate { node, score: 0.5 }
    }

    /// Seals every content field of a node the way `storage/content.py` would,
    /// so the tests exercise the real unseal path rather than plaintext input.
    async fn sealed(mut node: MemoryNode) -> MemoryNode {
        let values: Vec<String> = content::content_fields(&mut node)
            .iter()
            .map(|f| f.to_string())
            .collect();
        let mut packed = Vec::new();
        for value in values {
            let blob = seal::encrypt("owner-1", value.into_bytes()).await.unwrap();
            packed.push(content::pack(&blob.key_id, &blob.ciphertext));
        }
        for (field, value) in content::content_fields(&mut node).iter_mut().zip(packed) {
            **field = value;
        }
        node
    }

    #[tokio::test]
    async fn a_permitted_claim_comes_back_as_plaintext() {
        let node = sealed(MemoryNode::Claim(claim("c1", "we decided on Neo4j"))).await;
        let out = assemble("owner-1", &scope(), "what did we decide?", vec![candidate(node)])
            .await
            .unwrap();

        assert!(out.answer.answered);
        assert_eq!(out.answer.text, "- we decided on Neo4j (c1)");
        assert_eq!(out.disclosed_ids, vec!["c1"]);
        assert!(out.denials.is_empty());
        assert_eq!(out.considered, 1);
    }

    #[tokio::test]
    async fn a_denied_candidate_discloses_its_id_and_reason_and_not_its_content() {
        // The split ADR 0024 draws: ids and reasons are structure the host
        // already had and the read log needs; the statement is not.
        let mut denied = claim("c2", "the sensitive one");
        denied.acl.sensitivity = Sensitivity::Restricted;
        let node = sealed(MemoryNode::Claim(denied)).await;

        let out = assemble("owner-1", &scope(), "what did we decide?", vec![candidate(node)])
            .await
            .unwrap();

        assert!(!out.answer.answered);
        assert!(out.disclosed_ids.is_empty());
        assert_eq!(out.denials.len(), 1);
        assert_eq!(out.denials[0].id, "c2");
        assert_eq!(out.denials[0].reason, DenyReason::TooSensitive);
        assert!(!out.answer.text.contains("the sensitive one"));
        assert!(out.answer.text.contains("too sensitive"));
    }

    #[tokio::test]
    async fn nothing_denied_is_ever_unsealed() {
        // The decrypt budget is the disclosure budget. A denied object seals a
        // statement under a key id belonging to *another* owner, which the mock
        // unsealer refuses -- so if the filter ran after the unseal, this would
        // error instead of declining.
        let mut foreign = claim("c3", "someone else's memory");
        foreign.owner_id = "owner-2".into();
        foreign.acl.owner_id = "owner-2".into();
        let mut node = MemoryNode::Claim(foreign);
        let blob = seal::encrypt("owner-2", b"someone else's memory".to_vec())
            .await
            .unwrap();
        for field in content::content_fields(&mut node) {
            *field = content::pack(&blob.key_id, &blob.ciphertext);
        }

        let out = assemble("owner-1", &scope(), "anything?", vec![candidate(node)])
            .await
            .unwrap();
        assert_eq!(out.denials[0].reason, DenyReason::WrongOwner);
    }

    #[tokio::test]
    async fn no_candidates_at_all_declines_differently_from_all_denied() {
        let out = assemble("owner-1", &scope(), "anything?", vec![])
            .await
            .unwrap();
        assert_eq!(out.answer.text, "No memory matches this question.");
        assert_eq!(out.considered, 0);
    }

    #[tokio::test]
    async fn unsealed_content_never_reaches_the_structural_half() {
        // The one assertion that would catch a future refactor relaying the
        // answer in the clear: everything outside `answer` is ids and reasons.
        let node = sealed(MemoryNode::Claim(claim("c1", "we decided on Neo4j"))).await;
        let out = assemble("owner-1", &scope(), "what did we decide?", vec![candidate(node)])
            .await
            .unwrap();
        let structural = serde_json::json!({
            "disclosed_ids": out.disclosed_ids,
            "denials": out.denials,
            "considered": out.considered,
        });
        assert!(!structural.to_string().contains("Neo4j"));
    }

    #[tokio::test]
    async fn plaintext_fields_pass_through_untouched() {
        // ENCRYPT_CONTENT_AT_REST is off by default, so an unsealed store is an
        // ordinary state rather than a corrupt one.
        let node = MemoryNode::Claim(claim("c1", "stored in the clear"));
        let out = assemble("owner-1", &scope(), "?", vec![candidate(node)])
            .await
            .unwrap();
        assert_eq!(out.answer.text, "- stored in the clear (c1)");
    }

    #[tokio::test]
    async fn a_superseded_claim_keeps_its_marker() {
        let mut superseded = claim("c4", "we decided on Postgres");
        superseded.status = ClaimStatus::Superseded;
        let node = sealed(MemoryNode::Claim(superseded)).await;
        let out = assemble("owner-1", &scope(), "?", vec![candidate(node)])
            .await
            .unwrap();
        assert_eq!(out.answer.text, "- we decided on Postgres [superseded] (c4)");
    }

    #[tokio::test]
    async fn an_entity_line_names_its_kind_and_an_event_line_does_not() {
        let entity = MemoryNode::Entity(Entity {
            id: "n1".into(),
            owner_id: "owner-1".into(),
            kind: EntityKind::Project,
            name: "Kleos".into(),
            aliases: vec![],
            first_seen_at_ms: 1_000,
            last_seen_at_ms: 1_000,
            provenance: provenance(),
            acl: acl(),
        });
        let event = MemoryNode::Event(Event {
            id: "e1".into(),
            owner_id: "owner-1".into(),
            summary: "the kickoff call".into(),
            body: Some("a longer body".into()),
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
        });
        let out = assemble(
            "owner-1",
            &scope(),
            "?",
            vec![candidate(sealed(entity).await), candidate(sealed(event).await)],
        )
        .await
        .unwrap();
        assert_eq!(
            out.answer.text,
            "- project: Kleos (n1)\n- the kickoff call (e1)"
        );
    }

    #[tokio::test]
    async fn the_citation_carries_structure_and_the_url() {
        let node = sealed(MemoryNode::Claim(claim("c1", "we decided on Neo4j"))).await;
        let out = assemble("owner-1", &scope(), "?", vec![candidate(node)])
            .await
            .unwrap();
        let citation = &out.answer.citations[0];
        assert_eq!(citation.object_id, "c1");
        assert_eq!(citation.label, "Claim");
        assert_eq!(citation.source, "text");
        assert_eq!(citation.url.as_deref(), Some("https://example.invalid/1"));
        assert_eq!(citation.occurred_at_ms, 1_000);
        assert_eq!(citation.ingested_at_ms, Some(2_000));
    }

    #[tokio::test]
    async fn the_order_the_host_sent_is_the_order_assembled() {
        // The enclave has no opinion about relevance; re-sorting on a score the
        // host computed would look like it did.
        let a = sealed(MemoryNode::Claim(claim("c1", "first"))).await;
        let b = sealed(MemoryNode::Claim(claim("c2", "second"))).await;
        let out = assemble(
            "owner-1",
            &scope(),
            "?",
            vec![
                AssembleCandidate { node: a, score: 0.1 },
                AssembleCandidate { node: b, score: 0.9 },
            ],
        )
        .await
        .unwrap();
        assert_eq!(out.answer.text, "- first (c1)\n- second (c2)");
    }

    #[tokio::test]
    async fn a_scope_for_another_owner_is_refused_rather_than_answered_empty() {
        let mut other = scope();
        other.owner_id = "owner-2".into();
        assert!(assemble("owner-1", &other, "?", vec![]).await.is_err());
    }
}
