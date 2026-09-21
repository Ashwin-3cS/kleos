use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// Marks this as an owner session and not some other token signed with the
/// same secret. Without it, session and grant tokens are distinguishable only
/// because their claim shapes happen to be disjoint and serde rejects a
/// missing field -- an accident of the structs, not a defence. Adding an
/// optional field to either one would silently make them interchangeable.
const TOKEN_TYPE: &str = "session";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    #[serde(default)]
    pub typ: String,
    pub owner_id: String,
    pub exp: usize,
}

pub fn issue_session_token(
    owner_id: &str,
    secret: &str,
    ttl_secs: usize,
) -> anyhow::Result<String> {
    let exp = (chrono_now_secs() + ttl_secs) as usize;
    let claims = SessionClaims {
        typ: TOKEN_TYPE.to_string(),
        owner_id: owner_id.to_string(),
        exp,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )?;
    Ok(token)
}

pub fn validate_session_token(token: &str, secret: &str) -> anyhow::Result<SessionClaims> {
    let data = decode::<SessionClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &Validation::default(),
    )?;
    if data.claims.typ != TOKEN_TYPE {
        anyhow::bail!("token is not an owner session token");
    }
    Ok(data.claims)
}

fn chrono_now_secs() -> usize {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as usize
}

/// Extracts and validates the owner session from an `Authorization: Bearer`
/// header. Every memory route is owner-authenticated: the enclave will seal
/// under whatever owner id it is told, so the gateway is what binds a
/// request to an actual verified identity.
pub fn require_session(
    headers: &axum::http::HeaderMap,
    secret: &str,
) -> Result<SessionClaims, crate::error::GatewayError> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| {
            crate::error::GatewayError::Unauthorized(
                "missing Authorization: Bearer <session token> header".into(),
            )
        })?;

    validate_session_token(raw, secret)
        .map_err(|e| crate::error::GatewayError::Unauthorized(format!("invalid session: {e}")))
}
