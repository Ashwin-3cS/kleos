//! The OAuth scopes memorai asks for, in one place, so the authorize URL the
//! gateway builds and the consent the user actually sees can be audited
//! against a single list.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    Google,
    #[serde(rename = "github")]
    GitHub,
}

impl Provider {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "google" => Some(Provider::Google),
            "github" => Some(Provider::GitHub),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::Google => "google",
            Provider::GitHub => "github",
        }
    }

    /// Data scopes requested at consent time. Read-only throughout: memorai
    /// ingests, it never writes back to a source.
    pub fn scopes(&self) -> &'static [&'static str] {
        match self {
            Provider::Google => &[
                "openid",
                "email",
                "https://www.googleapis.com/auth/gmail.readonly",
                "https://www.googleapis.com/auth/calendar.readonly",
            ],
            Provider::GitHub => &["read:user", "repo"],
        }
    }

    /// The provider's user-facing authorize endpoint. Unlike the token
    /// endpoint (which the enclave calls through a VSOCK tunnel) this URL is
    /// only ever handed to the user's browser, so it is a plain absolute URL.
    pub fn authorize_endpoint(&self) -> &'static str {
        match self {
            Provider::Google => "https://accounts.google.com/o/oauth2/v2/auth",
            Provider::GitHub => "https://github.com/login/oauth/authorize",
        }
    }

    pub fn scope_param(&self) -> String {
        self.scopes().join(" ")
    }
}
