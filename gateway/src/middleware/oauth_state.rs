//! CSRF/replay protection for the OAuth redirect flow, plus PKCE.
//!
//! Two separate things guard the callback:
//!
//! * The `state` parameter is a **signed, expiring** JWT. An attacker who
//!   did not start a flow here cannot mint one, which is what stops a
//!   forged callback binding the attacker's provider account to a victim's
//!   session.
//! * The PKCE verifier is kept **server-side**, keyed by an id carried in
//!   that state, and removed on first use. Consuming it is what makes a
//!   replayed callback fail even with a still-valid, correctly signed
//!   state, and keeping it out of the state token is what stops anyone who
//!   observes the redirect from reconstructing the verifier.

use crate::error::GatewayError;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;

/// The `typ` discriminator the README asks for on session/grant tokens. An
/// oauth-state token is signed with the same machinery, so without this a
/// state could be presented as a session.
const TOKEN_TYPE: &str = "oauth_state";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthStateClaims {
    pub typ: String,
    pub state_id: String,
    pub provider: String,
    pub exp: usize,
}

/// The half of a pending authorization that never goes near the browser.
pub struct PendingAuth {
    pub provider: String,
    pub code_verifier: String,
    pub redirect_uri: String,
    pub expires_at_secs: u64,
}

#[derive(Default)]
pub struct PendingAuthStore {
    entries: Mutex<HashMap<String, PendingAuth>>,
}

impl PendingAuthStore {
    pub fn insert(&self, state_id: String, pending: PendingAuth) {
        let mut entries = self.entries.lock().expect("pending auth mutex poisoned");
        let now = now_secs();
        entries.retain(|_, p| p.expires_at_secs > now);
        entries.insert(state_id, pending);
    }

    /// Removes and returns the pending authorization. Removal is the point:
    /// a second callback with the same state finds nothing and is rejected.
    pub fn take(&self, state_id: &str) -> Option<PendingAuth> {
        let mut entries = self.entries.lock().expect("pending auth mutex poisoned");
        let pending = entries.remove(state_id)?;
        if pending.expires_at_secs <= now_secs() {
            return None;
        }
        Some(pending)
    }
}

pub struct IssuedState {
    pub state_token: String,
    pub state_id: String,
    pub code_verifier: String,
    pub code_challenge: String,
}

pub fn issue_state(
    provider: &str,
    secret: &str,
    ttl_secs: u64,
) -> Result<IssuedState, GatewayError> {
    let state_id = random_b64url(16);
    let code_verifier = random_b64url(32);
    let code_challenge = B64URL.encode(Sha256::digest(code_verifier.as_bytes()));

    let claims = OAuthStateClaims {
        typ: TOKEN_TYPE.to_string(),
        state_id: state_id.clone(),
        provider: provider.to_string(),
        exp: (now_secs() + ttl_secs) as usize,
    };
    let state_token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|e| GatewayError::Internal(format!("failed to sign oauth state: {e}")))?;

    Ok(IssuedState {
        state_token,
        state_id,
        code_verifier,
        code_challenge,
    })
}

pub fn validate_state(token: &str, secret: &str) -> Result<OAuthStateClaims, GatewayError> {
    // Default leeway is 60s. A consent flow has no clock-skew problem worth
    // that, and every second of leeway is a second of extra replay window.
    let mut validation = Validation::default();
    validation.leeway = 0;

    let data = decode::<OAuthStateClaims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|e| GatewayError::Unauthorized(format!("invalid oauth state: {e}")))?;

    if data.claims.typ != TOKEN_TYPE {
        return Err(GatewayError::Unauthorized(
            "token is not an oauth state token".into(),
        ));
    }
    Ok(data.claims)
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_secs()
}

fn random_b64url(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::thread_rng().fill_bytes(&mut buf);
    B64URL.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_challenge_is_s256_of_the_verifier() {
        let issued = issue_state("google", "s", 300).unwrap();
        let expected = B64URL.encode(Sha256::digest(issued.code_verifier.as_bytes()));
        assert_eq!(issued.code_challenge, expected);
        assert_ne!(issued.code_challenge, issued.code_verifier);
    }

    #[test]
    fn state_signed_with_another_secret_is_rejected() {
        let issued = issue_state("google", "real-secret", 300).unwrap();
        assert!(validate_state(&issued.state_token, "attacker-secret").is_err());
        assert!(validate_state(&issued.state_token, "real-secret").is_ok());
    }

    #[test]
    fn expired_state_is_rejected() {
        let claims = OAuthStateClaims {
            typ: TOKEN_TYPE.into(),
            state_id: "x".into(),
            provider: "google".into(),
            exp: (now_secs() - 1) as usize,
        };
        let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(b"s")).unwrap();
        assert!(validate_state(&token, "s").is_err());
    }

    #[test]
    fn a_session_token_is_not_accepted_as_state() {
        let session = crate::middleware::session::issue_session_token("owner-1", "s", 300).unwrap();
        assert!(validate_state(&session, "s").is_err());
    }

    #[test]
    fn pending_auth_is_single_use() {
        let store = PendingAuthStore::default();
        store.insert(
            "sid".into(),
            PendingAuth {
                provider: "google".into(),
                code_verifier: "v".into(),
                redirect_uri: "http://localhost/cb".into(),
                expires_at_secs: now_secs() + 300,
            },
        );
        assert!(store.take("sid").is_some());
        assert!(store.take("sid").is_none());
    }
}
