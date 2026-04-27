//! DKIM verification (inbound) and signing (outbound).
//! Uses `mail-auth` 0.5.
//!
//! Both verify() and sign() are stubs for now. Full implementation requires
//! wiring in a DNS resolver and determining the exact mail-auth 0.5 signing API.
//! TODO: implement once resolver integration is complete (Phase 10).

use mail_auth::AuthenticatedMessage;
use tracing::debug;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DkimVerdict {
    Pass,
    Fail,
    PermError,
    TempError,
    None,
}

impl std::fmt::Display for DkimVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Pass      => "pass",
            Self::Fail      => "fail",
            Self::PermError => "permerror",
            Self::TempError => "temperror",
            Self::None      => "none",
        };
        f.write_str(s)
    }
}

/// Verify all DKIM-Signature headers in a raw message.
///
/// Stub: parses the message (validates basic structure) but does not
/// perform DNS lookups or cryptographic verification yet.
pub async fn verify(raw_message: &[u8]) -> DkimVerdict {
    let _msg = match AuthenticatedMessage::parse(raw_message) {
        Some(m) => m,
        Option::None => return DkimVerdict::None,
    };
    // TODO: wire up DNS resolver and call resolver.verify_dkim(&_msg).await
    debug!("DKIM verify (stub — returning None)");
    DkimVerdict::None
}

/// Sign a message with an RSA private key.
///
/// Stub: returns the message unchanged until the signing API is wired up.
pub fn sign(
    raw_message: &[u8],
    _domain: &str,
    _selector: &str,
    _private_key_pem: &[u8],
) -> Result<Vec<u8>, DkimError> {
    // TODO: implement DKIM signing with mail-auth 0.5 API
    debug!("DKIM sign (stub — returning unsigned message)");
    Ok(raw_message.to_vec())
}

#[derive(Debug, Error)]
pub enum DkimError {
    #[error("DKIM signing error: {0}")]
    Sign(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
