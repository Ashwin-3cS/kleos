use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use shared::Scope;

/// A grant is a signed capability: the whole scope travels inside the token
/// so that introspection needs no server-side state, and so the same
/// structure can later be published as an on-chain grant object verbatim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantClaims {
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
    Ok(data.claims.scope)
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}
