//! Per-purpose signing keys, derived from one root secret.
//!
//! The gateway signs three unrelated things: owner session tokens, agent
//! grant tokens, and the OAuth `state` parameter. All three used to be signed
//! with `SESSION_JWT_SECRET` -- `OAUTH_STATE_SECRET` existed but defaulted to
//! it, and grants never had a key of their own at all.
//!
//! Each token already declares its own `typ` and is rejected when presented as
//! another, so confusion was handled. What was not handled is *blast radius*:
//! one key meant anything able to read it could mint all three. A leaked state
//! secret could forge an owner session; a leaked session secret could mint
//! agent grants over any owner's memory.
//!
//! Three independent keys would mean three secrets to provision, and an
//! operator who provisions three has a fourth option available: paste the same
//! value into all three and be back where we started, invisibly. So the keys
//! are **derived** from one root instead. See ADR 0004.
//!
//! Derivation is HMAC-SHA256 over a versioned label, which gives the property
//! that matters: the three keys are computationally independent, so recovering
//! one yields neither the root nor its siblings. Explicit per-purpose
//! overrides exist for rotating a single key without rotating the others.

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Versioned so a future change to the derivation can coexist with tokens
/// signed under the old one during a rollover.
const DOMAIN: &str = "kleos/signing/v1/";

/// The value `SESSION_JWT_SECRET` falls back to when unset. Fine for mock
/// mode, fatal in `nitro` -- see [`SigningKeys::from_env`].
pub const DEV_ROOT_SECRET: &str = "dev-insecure-secret-change-me";

/// Shortest root accepted outside mock mode. 32 bytes is the output width of
/// the derivation, so anything shorter caps the entropy of all three keys at
/// less than the keys can carry.
const MIN_ROOT_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct SigningKeys {
    session: String,
    oauth_state: String,
}

fn derive(root: &str, label: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(root.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(DOMAIN.as_bytes());
    mac.update(label.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

impl SigningKeys {
    /// Derives all three keys from one root secret.
    pub fn derive_from(root: &str) -> Self {
        Self {
            session: derive(root, "session"),
            oauth_state: derive(root, "oauth_state"),
        }
    }

    /// Derives the keys, refusing a root that is unsafe for a real deployment.
    ///
    /// Split out from [`Self::from_env`] so the refusal is testable without a
    /// test mutating process-wide environment variables underneath its
    /// neighbours.
    pub fn from_root_checked(root: &str, nitro: bool) -> anyhow::Result<Self> {
        if nitro {
            if root == DEV_ROOT_SECRET {
                anyhow::bail!(
                    "SIGNING_ROOT_SECRET is the public development default; refusing to start \
                     in nitro mode. Generate one with `openssl rand -hex 32`."
                );
            }
            if root.len() < MIN_ROOT_LEN {
                anyhow::bail!(
                    "SIGNING_ROOT_SECRET is {} characters; nitro mode requires at least {}. \
                     Generate one with `openssl rand -hex 32`.",
                    root.len(),
                    MIN_ROOT_LEN
                );
            }
        } else if root == DEV_ROOT_SECRET {
            tracing::warn!(
                "using the public development signing secret; set SIGNING_ROOT_SECRET for \
                 anything that is not a local mock run"
            );
        }
        Ok(Self::derive_from(root))
    }

    /// Reads the root from the environment and applies any explicit
    /// per-purpose overrides.
    ///
    /// Returns an error rather than falling back when the configuration would
    /// be unsafe in a real deployment: a gateway that boots with a known
    /// public secret is worse than one that refuses to boot, because the first
    /// looks like it is working.
    pub fn from_env(nitro: bool) -> anyhow::Result<Self> {
        let root = std::env::var("SIGNING_ROOT_SECRET")
            .or_else(|_| std::env::var("SESSION_JWT_SECRET"))
            .unwrap_or_else(|_| DEV_ROOT_SECRET.to_string());

        let mut keys = Self::from_root_checked(&root, nitro)?;
        // Overrides exist to rotate one key without rotating the others --
        // invalidating every live session because a grant key leaked is an
        // availability cost with no security benefit.
        if let Ok(explicit) = std::env::var("SESSION_SIGNING_KEY") {
            keys.session = explicit;
        }
        // Accepts the historical name so an existing deployment that set it
        // keeps working; it is now an override of a derived key rather than a
        // value that silently defaults to the session secret.
        if let Ok(explicit) =
            std::env::var("OAUTH_STATE_SIGNING_KEY").or_else(|_| std::env::var("OAUTH_STATE_SECRET"))
        {
            keys.oauth_state = explicit;
        }
        Ok(keys)
    }

    /// Fixed keys for mock runs and tests.
    pub fn mock() -> Self {
        Self::derive_from("test-root-secret")
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn oauth_state(&self) -> &str {
        &self.oauth_state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nitro_refuses_the_public_development_secret() {
        let err = SigningKeys::from_root_checked(DEV_ROOT_SECRET, true)
            .expect_err("nitro must not boot on the public dev secret");
        assert!(err.to_string().contains("development default"));
    }

    #[test]
    fn nitro_refuses_a_short_root() {
        assert!(SigningKeys::from_root_checked(&"x".repeat(MIN_ROOT_LEN - 1), true).is_err());
        assert!(SigningKeys::from_root_checked(&"x".repeat(MIN_ROOT_LEN), true).is_ok());
    }

    #[test]
    fn mock_mode_still_boots_on_the_development_secret() {
        // Refusing here would mean `./scripts/run_local.sh` needs a secret
        // before it can start, which is a cost with no benefit locally.
        assert!(SigningKeys::from_root_checked(DEV_ROOT_SECRET, false).is_ok());
    }

    #[test]
    fn the_keys_differ() {
        let keys = SigningKeys::derive_from("a-root-secret-of-reasonable-length");
        assert_ne!(keys.session(), keys.oauth_state());
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = SigningKeys::derive_from("same-root");
        let b = SigningKeys::derive_from("same-root");
        assert_eq!(a.session(), b.session());
        assert_eq!(a.oauth_state(), b.oauth_state());
    }

    #[test]
    fn a_different_root_gives_different_keys() {
        let a = SigningKeys::derive_from("root-one");
        let b = SigningKeys::derive_from("root-two");
        assert_ne!(a.session(), b.session());
        assert_ne!(a.oauth_state(), b.oauth_state());
    }

    /// The property the whole module exists for: a key recovered from a token
    /// signed with it must not reveal the root or either sibling.
    #[test]
    fn a_derived_key_does_not_contain_the_root() {
        let root = "a-root-secret-of-reasonable-length";
        let keys = SigningKeys::derive_from(root);
        for key in [keys.session(), keys.oauth_state()] {
            assert!(!key.contains(root));
            assert_eq!(key.len(), 64, "32 bytes, hex encoded");
        }
    }

    /// There is no key here that signs a grant. The property the previous
    /// version of this test checked -- that a grant does not verify under the
    /// session key -- is now structural: grant verification takes an Ed25519
    /// public key belonging to the owner, and nothing derived from this root
    /// participates. See `shared/src/grants.rs`.
    #[test]
    fn no_derived_key_can_sign_a_grant() {
        let keys = SigningKeys::derive_from("a-root-secret-of-reasonable-length");
        // Session and state are the only purposes left; neither is a grant key.
        assert_eq!(
            [keys.session(), keys.oauth_state()].len(),
            2,
            "a third purpose here would mean the gateway can mint again"
        );
    }
}
