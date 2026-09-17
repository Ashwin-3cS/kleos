use serde::{Deserialize, Serialize};

/// One verified OAuth (or wallet/domain) signal contributing to an owner's
/// identity. Verification of each signal happens inside the enclave.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum OAuthSignal {
    Google {
        subject: String,
        email: String,
    },
    #[serde(rename = "github")]
    GitHub {
        subject: String,
        login: String,
    },
    Wallet {
        address: String,
    },
    Domain {
        domain: String,
    },
}

/// Trust tier derived from the number/kind of stacked signals.
/// Google alone = 1, + GitHub = 2, + wallet = 3, + domain = 4.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TrustTier {
    None = 0,
    Google = 1,
    GoogleGithub = 2,
    GoogleGithubWallet = 3,
    GoogleGithubWalletDomain = 4,
}

impl TrustTier {
    pub fn from_signals(signals: &[OAuthSignal]) -> Self {
        let has_google = signals
            .iter()
            .any(|s| matches!(s, OAuthSignal::Google { .. }));
        let has_github = signals
            .iter()
            .any(|s| matches!(s, OAuthSignal::GitHub { .. }));
        let has_wallet = signals
            .iter()
            .any(|s| matches!(s, OAuthSignal::Wallet { .. }));
        let has_domain = signals
            .iter()
            .any(|s| matches!(s, OAuthSignal::Domain { .. }));

        match (has_google, has_github, has_wallet, has_domain) {
            (true, true, true, true) => TrustTier::GoogleGithubWalletDomain,
            (true, true, true, false) => TrustTier::GoogleGithubWallet,
            (true, true, false, _) => TrustTier::GoogleGithub,
            (true, false, _, _) => TrustTier::Google,
            _ => TrustTier::None,
        }
    }
}

/// The attested identity of a memory-layer owner, as established by the
/// enclave from one or more stacked signals. No government ID is ever used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnerIdentity {
    pub owner_id: String,
    pub signals: Vec<OAuthSignal>,
    pub trust_tier: TrustTier,
}
