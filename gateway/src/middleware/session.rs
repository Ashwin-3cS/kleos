use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionClaims {
    pub owner_id: String,
    pub exp: usize,
}

pub fn issue_session_token(owner_id: &str, secret: &str, ttl_secs: usize) -> anyhow::Result<String> {
    let exp = (chrono_now_secs() + ttl_secs) as usize;
    let claims = SessionClaims {
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
    Ok(data.claims)
}

fn chrono_now_secs() -> usize {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs() as usize
}
