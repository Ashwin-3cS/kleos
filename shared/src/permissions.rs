use crate::memory::{EntityKind, MemoryKind, SourceId};
use serde::{Deserialize, Serialize};

/// How sensitive a piece of stored memory is. Ordered: a scope granting
/// `Confidential` also admits everything below it.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public = 0,
    /// The default, deliberately not `Public`: an object whose sensitivity is
    /// missing must not be the most widely readable thing in the store.
    #[default]
    Personal = 1,
    Confidential = 2,
    Restricted = 3,
}

/// The access-control facts a stored object carries so that a permission
/// check can be evaluated against a requesting agent's scope *at query
/// time*, rather than baking a static visibility label in at ingest.
///
/// Everything here is denormalised onto the object on purpose: the check
/// must be decidable from (scope, acl) alone, with no further lookups, so
/// that the same evaluation can later be performed on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ObjectAcl {
    pub owner_id: String,
    /// Every source this object draws on. Plural because a resolved object
    /// can be derived from several: a decision evidenced by both a Slack
    /// thread and a Notion page belongs to both, and a scope covering only
    /// one of them must not see it.
    pub sources: Vec<SourceId>,
    pub sensitivity: Sensitivity,
    /// Kinds of every entity this object is about (for an `Entity`, its own
    /// kind). A scope restricted to `Project` must not see an object that
    /// is also about a `Person` unless persons are in scope too.
    pub entity_kinds: Vec<EntityKind>,
    /// When the underlying thing happened, for time-window checks. Distinct
    /// from when it was ingested; scopes are expressed over real-world time.
    pub occurred_at_ms: u64,
    /// Agent ids explicitly revoked for this object, overriding any grant.
    #[serde(default)]
    pub denied_agents: Vec<String>,
}

/// A grant presented by a querying agent. The owner's device signs these and
/// the gateway verifies them (see `gateway/src/routes/memory.rs`); the
/// orchestrator's query graph enforces them per candidate object.
///
/// `Default` is safe to reach for and is how a read-only scope is spelled:
/// every list defaults empty and every capability flag defaults false, and
/// empty denies everywhere here. So `Scope { agent_id, owner_id, sources,
/// entity_kinds, ..Default::default() }` grants reads over those sources and
/// nothing else -- and a field appended later cannot silently become granted in
/// a caller that did not mention it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Scope {
    pub agent_id: String,
    pub owner_id: String,
    pub sources: Vec<SourceId>,
    pub entity_kinds: Vec<EntityKind>,
    pub not_before_ms: Option<u64>,
    pub not_after_ms: Option<u64>,
    pub max_sensitivity: Sensitivity,
    pub expires_at_ms: Option<u64>,
    // Everything below is appended, defaulted, and false or empty when absent.
    //
    // `serde(default)` is load-bearing rather than tidy: a grant is signed by a
    // key the owner holds, and the signature covers the payload bytes as they
    // were signed. Without a default, every grant issued before this change
    // would fail to deserialize -- and there is no way to reissue one without
    // the owner's device in hand. Defaulting means an old grant stays valid and
    // stays read-only, which is the safe direction.
    /// May this agent write into the owner's memory at all.
    #[serde(default)]
    pub may_write: bool,
    /// May it turn a sealed body back into plaintext.
    ///
    /// A separate axis from `may_write` because the risks are different: one
    /// changes the person's record, the other produces plaintext the operator
    /// cannot otherwise read. The same split `ToolSpec` makes between
    /// `writes_memory` and `reaches_network`, one layer up.
    #[serde(default)]
    pub may_unseal: bool,
    /// May a claim this agent writes supersede one the owner wrote.
    ///
    /// Off by default, so an agent's claim *contradicts* the owner's rather
    /// than replacing it -- the disagreement stays visible with neither side
    /// overwritten. ADR 0014 established that a web page may never supersede
    /// the person; an agent the owner explicitly granted this is a delegate
    /// rather than a stranger, which is why precedence is a property of the
    /// grant and not of the source.
    #[serde(default)]
    pub may_supersede_owner: bool,
    /// Which sources this agent may write *as*.
    ///
    /// Deliberately not `sources`. Read scope and write scope are not one set:
    /// an agent permitted to read `text` must not thereby be able to write a
    /// claim that claims to be a typed note from the person.
    #[serde(default)]
    pub write_sources: Vec<SourceId>,
    /// Which kinds of long-term memory this agent may read. Empty grants none
    /// of them, like every other list here.
    #[serde(default)]
    pub memory_kinds: Vec<MemoryKind>,
    /// May this agent ask the enclave to perform a sensitive action on the
    /// owner's behalf. The agent never receives the credential -- it submits an
    /// intent and receives an acknowledgement.
    #[serde(default)]
    pub may_act: bool,
    /// Which actions, by id. Empty grants none.
    #[serde(default)]
    pub act_actions: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    WrongOwner,
    GrantExpired,
    AgentRevoked,
    SourceNotInScope,
    EntityKindNotInScope,
    OutsideTimeWindow,
    TooSensitive,
    WriteNotPermitted,
    WriteSourceNotInScope,
    MemoryKindNotInScope,
    UnsealNotPermitted,
    ActionNotPermitted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "decision", content = "reason")]
pub enum PermissionDecision {
    Allow,
    Deny(DenyReason),
}

impl PermissionDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, PermissionDecision::Allow)
    }
}

/// Pure, total permission check. Deny-by-default: an empty `sources` or
/// `entity_kinds` list in a scope grants nothing rather than everything.
pub fn evaluate(scope: &Scope, acl: &ObjectAcl, now_ms: u64) -> PermissionDecision {
    use PermissionDecision::{Allow, Deny};

    if scope.owner_id != acl.owner_id {
        return Deny(DenyReason::WrongOwner);
    }
    if let Some(expiry) = scope.expires_at_ms {
        if now_ms >= expiry {
            return Deny(DenyReason::GrantExpired);
        }
    }
    if acl.denied_agents.iter().any(|a| a == &scope.agent_id) {
        return Deny(DenyReason::AgentRevoked);
    }
    // `all`, not `any`: an object derived from two sources is only visible
    // to a scope covering both. The permissive reading would leak the
    // un-granted source's contribution through a resolved statement. Empty
    // is a deny, same as everywhere else here.
    if acl.sources.is_empty() || !acl.sources.iter().all(|s| scope.sources.contains(s)) {
        return Deny(DenyReason::SourceNotInScope);
    }
    if acl.entity_kinds.is_empty()
        || !acl
            .entity_kinds
            .iter()
            .all(|k| scope.entity_kinds.contains(k))
    {
        return Deny(DenyReason::EntityKindNotInScope);
    }
    if let Some(nb) = scope.not_before_ms {
        if acl.occurred_at_ms < nb {
            return Deny(DenyReason::OutsideTimeWindow);
        }
    }
    if let Some(na) = scope.not_after_ms {
        if acl.occurred_at_ms > na {
            return Deny(DenyReason::OutsideTimeWindow);
        }
    }
    if acl.sensitivity > scope.max_sensitivity {
        return Deny(DenyReason::TooSensitive);
    }
    Allow
}

pub fn permits(scope: &Scope, acl: &ObjectAcl, now_ms: u64) -> bool {
    evaluate(scope, acl, now_ms).is_allowed()
}

/// What an agent proposes to write: the ACL the object *would* carry.
///
/// A write cannot honestly share [`evaluate`]'s signature, because there is no
/// [`ObjectAcl`] yet -- there is no object. So the asymmetry is in the type:
/// reads evaluate `(scope, acl)`, writes evaluate `(scope, intent)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct WriteIntent {
    pub owner_id: String,
    pub source: SourceId,
    pub entity_kinds: Vec<EntityKind>,
    pub sensitivity: Sensitivity,
    pub memory_kind: Option<MemoryKind>,
}

/// Pure, total write check. Deny-by-default, like [`evaluate`].
///
/// A sibling function rather than a mode on [`evaluate`]. A mode parameter
/// would mean every existing call site has to say "read", and the one that
/// forgets gets whatever the default is -- a deny-by-default violation waiting
/// for someone to add a fifth read path.
pub fn evaluate_write(scope: &Scope, intent: &WriteIntent, now_ms: u64) -> PermissionDecision {
    use PermissionDecision::{Allow, Deny};

    if scope.owner_id != intent.owner_id {
        return Deny(DenyReason::WrongOwner);
    }
    if let Some(expiry) = scope.expires_at_ms {
        if now_ms >= expiry {
            return Deny(DenyReason::GrantExpired);
        }
    }
    if !scope.may_write {
        return Deny(DenyReason::WriteNotPermitted);
    }
    if !scope.write_sources.contains(&intent.source) {
        return Deny(DenyReason::WriteSourceNotInScope);
    }
    // `all` and empty-denies, exactly as the read check does: an agent writing
    // a claim about a person and a project needs both kinds in scope.
    if intent.entity_kinds.is_empty()
        || !intent
            .entity_kinds
            .iter()
            .all(|k| scope.entity_kinds.contains(k))
    {
        return Deny(DenyReason::EntityKindNotInScope);
    }
    // An agent must not write something it could not then read: a claim above
    // its own ceiling would be invisible to the agent that asserted it, and
    // would be a way to put material into the record that no grant accounts
    // for.
    if intent.sensitivity > scope.max_sensitivity {
        return Deny(DenyReason::TooSensitive);
    }
    if let Some(kind) = intent.memory_kind {
        if !scope.memory_kinds.contains(&kind) {
            return Deny(DenyReason::MemoryKindNotInScope);
        }
        if intent.sensitivity < kind.sensitivity_floor() {
            return Deny(DenyReason::TooSensitive);
        }
    }
    Allow
}

pub fn permits_write(scope: &Scope, intent: &WriteIntent, now_ms: u64) -> bool {
    evaluate_write(scope, intent, now_ms).is_allowed()
}

/// Whether this grant may turn a sealed body back into plaintext.
///
/// Separate from [`evaluate`] rather than folded into it: seeing a resolved
/// claim and pulling the raw transcript it was derived from are different
/// disclosures, and the body is the one the enclave exists for. The caller is
/// expected to have passed [`permits`] on the object first -- this is the
/// second gate, not a replacement for the first.
pub fn evaluate_unseal(scope: &Scope, acl: &ObjectAcl, now_ms: u64) -> PermissionDecision {
    match evaluate(scope, acl, now_ms) {
        PermissionDecision::Allow if !scope.may_unseal => {
            PermissionDecision::Deny(DenyReason::UnsealNotPermitted)
        }
        other => other,
    }
}

/// Whether this grant may ask for one named action.
pub fn evaluate_action(scope: &Scope, action_id: &str, now_ms: u64) -> PermissionDecision {
    use PermissionDecision::{Allow, Deny};

    if let Some(expiry) = scope.expires_at_ms {
        if now_ms >= expiry {
            return Deny(DenyReason::GrantExpired);
        }
    }
    if !scope.may_act || !scope.act_actions.iter().any(|a| a == action_id) {
        return Deny(DenyReason::ActionNotPermitted);
    }
    Allow
}

#[cfg(test)]
mod tests {
    use super::*;

    fn github() -> SourceId {
        SourceId::parse("github").expect("valid source id")
    }

    fn acl() -> ObjectAcl {
        ObjectAcl {
            owner_id: "owner-1".into(),
            sources: vec![github()],
            sensitivity: Sensitivity::Personal,
            entity_kinds: vec![EntityKind::Project],
            occurred_at_ms: 1_000,
            denied_agents: vec![],
        }
    }

    fn scope() -> Scope {
        Scope {
            agent_id: "agent-1".into(),
            owner_id: "owner-1".into(),
            sources: vec![github()],
            entity_kinds: vec![EntityKind::Project],
            not_before_ms: None,
            not_after_ms: None,
            max_sensitivity: Sensitivity::Personal,
            expires_at_ms: None,
            may_write: false,
            may_unseal: false,
            may_supersede_owner: false,
            write_sources: vec![],
            memory_kinds: vec![],
            may_act: false,
            act_actions: vec![],
        }
    }

    fn intent() -> WriteIntent {
        WriteIntent {
            owner_id: "owner-1".into(),
            source: SourceId::parse("agent").expect("valid source id"),
            entity_kinds: vec![EntityKind::Project],
            sensitivity: Sensitivity::Personal,
            memory_kind: Some(MemoryKind::Episodic),
        }
    }

    /// Every capability is off in a default scope, and a default scope grants
    /// nothing. This is the one test that fails if a field is appended with a
    /// permissive default.
    #[test]
    fn a_default_scope_grants_nothing() {
        let s = Scope::default();
        assert!(!s.may_write);
        assert!(!s.may_unseal);
        assert!(!s.may_supersede_owner);
        assert!(!s.may_act);
        assert!(s.write_sources.is_empty());
        assert!(s.memory_kinds.is_empty());
        assert!(s.act_actions.is_empty());
        assert!(!permits_write(&s, &intent(), 2_000));
        assert!(!evaluate_unseal(&s, &acl(), 2_000).is_allowed());
        assert!(!evaluate_action(&s, "anything", 2_000).is_allowed());
    }

    /// The property that matters most operationally: a grant signed before
    /// these fields existed must still verify, and must be read-only. The
    /// signature covers the bytes as signed, and there is no way to reissue a
    /// grant without the owner's device.
    #[test]
    fn a_grant_signed_before_these_fields_existed_is_read_only() {
        let json = r#"{
            "agent_id": "agent-1",
            "owner_id": "owner-1",
            "sources": ["github"],
            "entity_kinds": ["project"],
            "not_before_ms": null,
            "not_after_ms": null,
            "max_sensitivity": "personal",
            "expires_at_ms": null
        }"#;
        let old: Scope = serde_json::from_str(json).expect("an old grant must still parse");

        assert!(permits(&old, &acl(), 2_000), "reads must keep working");
        assert_eq!(
            evaluate_write(&old, &intent(), 2_000),
            PermissionDecision::Deny(DenyReason::WriteNotPermitted)
        );
        assert_eq!(
            evaluate_unseal(&old, &acl(), 2_000),
            PermissionDecision::Deny(DenyReason::UnsealNotPermitted)
        );
    }

    #[test]
    fn writing_needs_the_write_flag_and_the_write_source() {
        let mut s = scope();
        s.entity_kinds = vec![EntityKind::Project];
        s.memory_kinds = vec![MemoryKind::Episodic];

        assert_eq!(
            evaluate_write(&s, &intent(), 2_000),
            PermissionDecision::Deny(DenyReason::WriteNotPermitted)
        );

        s.may_write = true;
        assert_eq!(
            evaluate_write(&s, &intent(), 2_000),
            PermissionDecision::Deny(DenyReason::WriteSourceNotInScope),
            "may_write alone says nothing about what it may write as"
        );

        s.write_sources = vec![SourceId::parse("agent").unwrap()];
        assert!(permits_write(&s, &intent(), 2_000));
    }

    /// Read scope and write scope are not one set. An agent that may *read* the
    /// person's typed notes must not thereby be able to write a claim that
    /// claims to be one.
    #[test]
    fn read_scope_does_not_confer_write_scope() {
        let mut s = scope();
        s.may_write = true;
        s.memory_kinds = vec![MemoryKind::Episodic];
        s.sources = vec![SourceId::parse("text").unwrap()];
        s.write_sources = vec![SourceId::parse("agent").unwrap()];

        let mut as_the_person = intent();
        as_the_person.source = SourceId::parse("text").unwrap();

        assert_eq!(
            evaluate_write(&s, &as_the_person, 2_000),
            PermissionDecision::Deny(DenyReason::WriteSourceNotInScope)
        );
    }

    #[test]
    fn a_kind_outside_the_scope_cannot_be_written() {
        let mut s = scope();
        s.may_write = true;
        s.write_sources = vec![SourceId::parse("agent").unwrap()];
        s.memory_kinds = vec![MemoryKind::Episodic];

        let mut procedural = intent();
        procedural.memory_kind = Some(MemoryKind::Procedural);
        assert_eq!(
            evaluate_write(&s, &procedural, 2_000),
            PermissionDecision::Deny(DenyReason::MemoryKindNotInScope)
        );
    }

    /// A tacit claim is an inference about a person rather than something they
    /// said. Labelling one may only narrow who can read it, so writing one
    /// below its floor is refused rather than silently stored at the lower
    /// sensitivity.
    #[test]
    fn a_tacit_claim_cannot_be_written_below_its_floor() {
        let mut s = scope();
        s.may_write = true;
        s.write_sources = vec![SourceId::parse("agent").unwrap()];
        s.memory_kinds = vec![MemoryKind::Tacit];
        s.max_sensitivity = Sensitivity::Confidential;

        let mut tacit = intent();
        tacit.memory_kind = Some(MemoryKind::Tacit);
        tacit.sensitivity = Sensitivity::Personal;
        assert_eq!(
            evaluate_write(&s, &tacit, 2_000),
            PermissionDecision::Deny(DenyReason::TooSensitive)
        );

        tacit.sensitivity = Sensitivity::Confidential;
        assert!(permits_write(&s, &tacit, 2_000));
    }

    #[test]
    fn no_kind_lowers_the_floor_below_personal() {
        for kind in [
            MemoryKind::Episodic,
            MemoryKind::Procedural,
            MemoryKind::Tacit,
        ] {
            assert!(kind.sensitivity_floor() >= Sensitivity::Personal);
        }
    }

    /// An agent must not write something it could not then read: a claim above
    /// its own ceiling would be invisible to the agent that asserted it.
    #[test]
    fn an_agent_cannot_write_above_its_own_ceiling() {
        let mut s = scope();
        s.may_write = true;
        s.write_sources = vec![SourceId::parse("agent").unwrap()];
        s.memory_kinds = vec![MemoryKind::Episodic];

        let mut restricted = intent();
        restricted.sensitivity = Sensitivity::Restricted;
        assert_eq!(
            evaluate_write(&s, &restricted, 2_000),
            PermissionDecision::Deny(DenyReason::TooSensitive)
        );
    }

    /// Seeing a resolved claim and pulling the raw transcript it came from are
    /// different disclosures.
    #[test]
    fn reading_an_object_does_not_confer_unsealing_it() {
        let mut s = scope();
        assert!(permits(&s, &acl(), 2_000));
        assert_eq!(
            evaluate_unseal(&s, &acl(), 2_000),
            PermissionDecision::Deny(DenyReason::UnsealNotPermitted)
        );

        s.may_unseal = true;
        assert!(evaluate_unseal(&s, &acl(), 2_000).is_allowed());
    }

    /// And the other direction: `may_unseal` is not a way around the read
    /// check. An object the grant cannot see stays unseen, with the read
    /// check's own reason rather than an unseal reason.
    #[test]
    fn may_unseal_does_not_bypass_the_read_check() {
        let mut s = scope();
        s.may_unseal = true;
        s.sources = vec![];

        assert_eq!(
            evaluate_unseal(&s, &acl(), 2_000),
            PermissionDecision::Deny(DenyReason::SourceNotInScope)
        );
    }

    #[test]
    fn an_action_must_be_named_in_the_grant() {
        let mut s = scope();
        assert_eq!(
            evaluate_action(&s, "gmail.send", 2_000),
            PermissionDecision::Deny(DenyReason::ActionNotPermitted)
        );

        s.may_act = true;
        assert_eq!(
            evaluate_action(&s, "gmail.send", 2_000),
            PermissionDecision::Deny(DenyReason::ActionNotPermitted),
            "may_act alone names no action"
        );

        s.act_actions = vec!["gmail.send".into()];
        assert!(evaluate_action(&s, "gmail.send", 2_000).is_allowed());
        assert!(
            !evaluate_action(&s, "gmail.delete", 2_000).is_allowed(),
            "one action granted is not every action granted"
        );
    }

    #[test]
    fn an_expired_grant_writes_and_acts_no_more_than_it_reads() {
        let mut s = scope();
        s.may_write = true;
        s.may_act = true;
        s.write_sources = vec![SourceId::parse("agent").unwrap()];
        s.memory_kinds = vec![MemoryKind::Episodic];
        s.act_actions = vec!["gmail.send".into()];
        s.expires_at_ms = Some(1_500);

        assert_eq!(
            evaluate_write(&s, &intent(), 2_000),
            PermissionDecision::Deny(DenyReason::GrantExpired)
        );
        assert_eq!(
            evaluate_action(&s, "gmail.send", 2_000),
            PermissionDecision::Deny(DenyReason::GrantExpired)
        );
    }

    #[test]
    fn a_write_for_another_owner_is_refused() {
        let mut s = scope();
        s.may_write = true;
        s.write_sources = vec![SourceId::parse("agent").unwrap()];
        s.memory_kinds = vec![MemoryKind::Episodic];

        let mut theirs = intent();
        theirs.owner_id = "owner-2".into();
        assert_eq!(
            evaluate_write(&s, &theirs, 2_000),
            PermissionDecision::Deny(DenyReason::WrongOwner)
        );
    }

    #[test]
    fn allows_matching_scope() {
        assert!(permits(&scope(), &acl(), 2_000));
    }

    /// The regression the closed enum caused: a source this binary has never
    /// heard of must deserialize and then be *denied*, not fail to parse. A
    /// hard deserialization error on an unknown source meant every new
    /// connector required a coordinated enclave redeploy.
    #[test]
    fn an_unknown_source_deserializes_and_is_denied() {
        let json = r#"{
            "owner_id": "owner-1",
            "sources": ["slack"],
            "sensitivity": "personal",
            "entity_kinds": ["project"],
            "occurred_at_ms": 1000,
            "denied_agents": []
        }"#;
        let acl: ObjectAcl = serde_json::from_str(json).expect("unknown source must parse");

        assert_eq!(
            evaluate(&scope(), &acl, 2_000),
            PermissionDecision::Deny(DenyReason::SourceNotInScope),
            "a grant minted before the source existed must grant nothing for it"
        );
    }

    /// A derived object belongs to every source it draws on, and a scope
    /// covering only one of them must not see it -- otherwise the resolved
    /// statement leaks the un-granted source's contribution.
    #[test]
    fn a_multi_source_object_needs_every_source_in_scope() {
        let mut a = acl();
        a.sources = vec![github(), SourceId::parse("slack").unwrap()];
        assert_eq!(
            evaluate(&scope(), &a, 2_000),
            PermissionDecision::Deny(DenyReason::SourceNotInScope)
        );

        let mut s = scope();
        s.sources = vec![github(), SourceId::parse("slack").unwrap()];
        assert!(permits(&s, &a, 2_000));
    }

    #[test]
    fn an_object_with_no_source_is_denied() {
        let mut a = acl();
        a.sources.clear();
        assert!(!permits(&scope(), &a, 2_000));
    }

    #[test]
    fn source_ids_that_could_confuse_a_comparison_are_rejected() {
        assert!(SourceId::parse("github").is_some());
        assert!(SourceId::parse("google_calendar").is_some());
        // Case and whitespace variants would compare unequal to the
        // canonical id while looking identical in a grant UI.
        assert!(SourceId::parse("GitHub").is_none());
        assert!(SourceId::parse(" github").is_none());
        assert!(SourceId::parse("github ").is_none());
        assert!(SourceId::parse("").is_none());
        assert!(SourceId::parse(&"x".repeat(65)).is_none());
    }

    #[test]
    fn denies_other_owner() {
        let mut s = scope();
        s.owner_id = "owner-2".into();
        assert_eq!(
            evaluate(&s, &acl(), 0),
            PermissionDecision::Deny(DenyReason::WrongOwner)
        );
    }

    #[test]
    fn denies_more_sensitive_object() {
        let mut a = acl();
        a.sensitivity = Sensitivity::Restricted;
        assert_eq!(
            evaluate(&scope(), &a, 0),
            PermissionDecision::Deny(DenyReason::TooSensitive)
        );
    }

    #[test]
    fn denies_empty_scope() {
        let mut s = scope();
        s.sources.clear();
        assert!(!permits(&s, &acl(), 0));
    }

    #[test]
    fn denies_revoked_agent() {
        let mut a = acl();
        a.denied_agents.push("agent-1".into());
        assert_eq!(
            evaluate(&scope(), &a, 0),
            PermissionDecision::Deny(DenyReason::AgentRevoked)
        );
    }

    #[test]
    fn denies_outside_time_window() {
        let mut s = scope();
        s.not_before_ms = Some(5_000);
        assert_eq!(
            evaluate(&s, &acl(), 0),
            PermissionDecision::Deny(DenyReason::OutsideTimeWindow)
        );
    }

    #[test]
    fn denies_expired_grant() {
        let mut s = scope();
        s.expires_at_ms = Some(1_000);
        assert_eq!(
            evaluate(&s, &acl(), 1_000),
            PermissionDecision::Deny(DenyReason::GrantExpired)
        );
    }
}
