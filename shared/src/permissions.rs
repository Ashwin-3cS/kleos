use crate::memory::{EntityKind, SourceId};
use serde::{Deserialize, Serialize};

/// How sensitive a piece of stored memory is. Ordered: a scope granting
/// `Confidential` also admits everything below it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Public = 0,
    Personal = 1,
    Confidential = 2,
    Restricted = 3,
}

impl Default for Sensitivity {
    fn default() -> Self {
        Sensitivity::Personal
    }
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

/// A grant presented by a querying agent. The gateway mints and validates
/// these (see `gateway/src/routes/memory.rs`); the orchestrator's query
/// graph enforces them per candidate object.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        }
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
