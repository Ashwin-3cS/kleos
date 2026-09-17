use crate::memory::{EntityKind, SourceKind};
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
    pub source: SourceKind,
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
    pub sources: Vec<SourceKind>,
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
    if !scope.sources.contains(&acl.source) {
        return Deny(DenyReason::SourceNotInScope);
    }
    if acl.entity_kinds.is_empty() || !acl.entity_kinds.iter().all(|k| scope.entity_kinds.contains(k))
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

    fn acl() -> ObjectAcl {
        ObjectAcl {
            owner_id: "owner-1".into(),
            source: SourceKind::Github,
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
            sources: vec![SourceKind::Github],
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

    #[test]
    fn denies_other_owner() {
        let mut s = scope();
        s.owner_id = "owner-2".into();
        assert_eq!(evaluate(&s, &acl(), 0), PermissionDecision::Deny(DenyReason::WrongOwner));
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
