use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use shared::Scope;

/// A grant is a signed capability: the whole scope travels inside the token
/// so that introspection needs no server-side state, and so the same
/// structure can later be published as an on-chain grant object verbatim.
/// See the note in `session.rs`: both token types are signed with the same
/// secret, so each states what it is rather than relying on its claim shape
/// being incompatible with the other's.
const TOKEN_TYPE: &str = "grant";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantClaims {
    #[serde(default)]
    pub typ: String,
    pub scope: Scope,
    pub exp: usize,
}

pub fn issue_grant_token(
    scope: &Scope,
    ttl_secs: u64,
    secret: &str,
) -> anyhow::Result<(String, u64)> {
    let expires_at_secs = now_secs() + ttl_secs;
    // The scope's own expiry is what the permission check enforces per
    // object; the JWT `exp` only stops the token being decodable at all.
    let mut scope = scope.clone();
    scope.expires_at_ms = Some(match scope.expires_at_ms {
        Some(existing) => existing.min(expires_at_secs * 1_000),
        None => expires_at_secs * 1_000,
    });

    let claims = GrantClaims {
        typ: TOKEN_TYPE.to_string(),
        scope: scope.clone(),
        exp: expires_at_secs as usize,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok((token, scope.expires_at_ms.expect("set above")))
}

pub fn validate_grant_token(token: &str, secret: &str) -> anyhow::Result<Scope> {
    let data = decode::<GrantClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    if data.claims.typ != TOKEN_TYPE {
        anyhow::bail!("token is not an agent grant token");
    }
    Ok(data.claims.scope)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::session::{issue_session_token, validate_session_token};
    use shared::{Scope, Sensitivity};

    fn scope() -> Scope {
        Scope {
            agent_id: "agent-1".into(),
            owner_id: "owner-1".into(),
            sources: vec![],
            entity_kinds: vec![],
            not_before_ms: None,
            not_after_ms: None,
            max_sensitivity: Sensitivity::Personal,
            expires_at_ms: None,
        }
    }

    /// Session and grant tokens are signed with the same secret. They were
    /// previously distinguishable only because their claim shapes are
    /// disjoint and serde rejects a missing field -- so adding one optional
    /// field to either struct would have silently made an owner session
    /// usable as an agent grant, and vice versa.
    #[test]
    fn a_session_token_is_not_accepted_as_a_grant() {
        let secret = "same-secret";
        let session = issue_session_token("owner-1", secret, 300).unwrap();
        assert!(validate_grant_token(&session, secret).is_err());
    }

    #[test]
    fn a_grant_token_is_not_accepted_as_a_session() {
        let secret = "same-secret";
        let (grant, _) = issue_grant_token(&scope(), 300, secret).unwrap();
        assert!(validate_session_token(&grant, secret).is_err());
    }

    #[test]
    fn each_token_still_validates_as_itself() {
        let secret = "same-secret";
        let (grant, _) = issue_grant_token(&scope(), 300, secret).unwrap();
        assert_eq!(
            validate_grant_token(&grant, secret).unwrap().agent_id,
            "agent-1"
        );
        let session = issue_session_token("owner-1", secret, 300).unwrap();
        assert_eq!(
            validate_session_token(&session, secret).unwrap().owner_id,
            "owner-1"
        );
    }
}
