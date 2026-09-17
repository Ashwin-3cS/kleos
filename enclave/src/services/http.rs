use crate::error::EnclaveError;
use std::time::Duration;

/// An external service the enclave talks to through a VSOCK tunnel.
///
/// The enclave has no direct network access, but it still speaks **TLS
/// itself, end to end**: it dials the real hostname over HTTPS, and inside
/// the enclave `/etc/hosts` maps that hostname to a loopback alias where
/// socat is listening on :443 (see `enclave/run.sh`). socat forwards the raw
/// bytes over VSOCK to `scripts/parent_forwarder.sh`, which connects to the
/// real host:443 and pipes them on.
///
/// The host therefore moves an opaque TLS stream it cannot read, and the
/// certificate is validated inside the TEE against the real hostname. Were
/// the enclave to speak plaintext HTTP and let the host terminate TLS, the
/// operator would see every request and response -- client secrets and
/// refresh tokens included -- which would defeat the whole trust model.
pub struct Upstream {
    /// Real DNS name; the TLS certificate is validated against it. This is
    /// deliberately a compile-time constant rather than configuration: the
    /// enclave's environment is supplied by the host, so a host-settable
    /// endpoint would let the operator redirect the client secret to a
    /// server it controls.
    pub host: &'static str,
    /// VSOCK port the host-side forwarder bridges this upstream on. Not used
    /// to build the URL -- routing is by hostname -- but kept so the Rust
    /// side, `run.sh` and `parent_forwarder.sh` share one table.
    pub tunnel_port: u16,
    /// Loopback alias `run.sh` maps `host` to inside the enclave. Each
    /// upstream needs its own, since they all listen on :443.
    pub loopback: &'static str,
}

pub const GOOGLE_TOKENINFO: Upstream = Upstream {
    host: "www.googleapis.com",
    tunnel_port: 8002,
    loopback: "127.0.0.2",
};

pub const GITHUB_API: Upstream = Upstream {
    host: "api.github.com",
    tunnel_port: 8003,
    loopback: "127.0.0.3",
};

pub const GOOGLE_TOKEN: Upstream = Upstream {
    host: "oauth2.googleapis.com",
    tunnel_port: 8006,
    loopback: "127.0.0.4",
};

pub const GITHUB_TOKEN: Upstream = Upstream {
    host: "github.com",
    tunnel_port: 8007,
    loopback: "127.0.0.5",
};

pub const ALL_UPSTREAMS: [&Upstream; 4] =
    [&GOOGLE_TOKENINFO, &GITHUB_API, &GOOGLE_TOKEN, &GITHUB_TOKEN];

pub fn tunnel_client() -> Result<reqwest::Client, EnclaveError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| EnclaveError::Internal(format!("failed to build HTTP client: {e}")))
}

pub fn tunnel_url(upstream: &Upstream, path: &str) -> String {
    format!("https://{}{}", upstream.host, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard. This was plaintext HTTP into a tunnel that landed
    /// on :443, so no outbound enclave call could ever have succeeded.
    #[test]
    fn upstream_urls_are_https() {
        for upstream in ALL_UPSTREAMS {
            assert!(tunnel_url(upstream, "/x").starts_with("https://"));
        }
    }

    #[test]
    fn upstreams_do_not_collide() {
        let mut seen = std::collections::HashSet::new();
        for upstream in ALL_UPSTREAMS {
            assert!(seen.insert((upstream.tunnel_port, upstream.loopback)));
        }
    }
}
