//! The code that lets one keypair become this install's owner (ADR 0029).
//!
//! Possession of a file on the machine is the authentication, which is the
//! right strength for what it protects: anything that can read this file can
//! already read the Neo4j volume and the blob store. What it stops is a
//! stranger who can reach the port enrolling themselves as a brand-new owner
//! — the same thing the loopback bind stops, from the other side.
//!
//! It is consumed on use, so an install has one local owner. A second device
//! for that owner goes through `/auth/device/register` under a session, which
//! the dashboard already does.

use std::path::{Path, PathBuf};

use crate::error::GatewayError;

/// A code on disk, and the two things anyone does with it.
#[derive(Debug, Clone)]
pub struct Enrolment {
    path: PathBuf,
}

impl Enrolment {
    /// Reads the code, creating one if this is a first run.
    ///
    /// Fallible rather than best-effort: a gateway that could not write the
    /// code has a path problem the operator needs told about now, not when
    /// somebody tries to enrol.
    pub fn open(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let code = generate();
            std::fs::write(&path, &code)?;
            restrict(&path)?;
            tracing::info!(
                path = %path.display(),
                "local enrolment is open: the code is in this file, and is consumed by the \
                 first device that enrols"
            );
        }
        Ok(Self { path })
    }

    /// Refuses unless `candidate` is the code.
    ///
    /// A consumed code leaves no file, so "already enrolled" and "wrong code"
    /// are the same answer. Deliberately: the alternative tells an unenrolled
    /// caller whether this install has an owner yet, which is a fact about
    /// somebody's machine.
    pub fn check(&self, candidate: &str) -> Result<(), GatewayError> {
        let expected = std::fs::read_to_string(&self.path).map_err(|_| {
            GatewayError::Unauthorized(
                "enrolment is closed on this install. If you need to enrol another owner, \
                 remove the enrolment code file and restart the gateway."
                    .into(),
            )
        })?;
        if !constant_time_eq(expected.trim().as_bytes(), candidate.trim().as_bytes()) {
            return Err(GatewayError::Unauthorized("wrong enrolment code".into()));
        }
        Ok(())
    }

    /// Spends it.
    pub fn consume(&self) -> Result<(), GatewayError> {
        std::fs::remove_file(&self.path).map_err(|e| {
            GatewayError::Internal(format!("could not consume the enrolment code: {e}"))
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// 160 bits, base32-ish over an unambiguous alphabet.
///
/// No `0`, `1`, `i`, `l` or `o`: this is a string a person copies out of a log
/// line by hand, and a code that fails because of a glyph tells them nothing
/// useful about why.
fn generate() -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"abcdefghjkmnpqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    let raw: String = (0..32)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect();
    // Grouped for the same reason: a person reads it in chunks.
    raw.as_bytes()
        .chunks(8)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

/// Compares without an early return on the first differing byte.
///
/// The code is on the same machine as the data it protects, so a timing oracle
/// is not the threat that matters here. It is written this way because a
/// comparison of a secret that short-circuits is the kind of thing that gets
/// copied into somewhere it does matter.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(unix)]
fn restrict(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
