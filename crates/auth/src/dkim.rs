//! DKIM verification (inbound) and signing (outbound).
//! Uses `mail-auth` 0.5.

use mail_auth::{
    AuthenticatedMessage,
    DkimOutput, DkimResult,
    dkim::{DkimSigner, Canonicalization, RsaKey, Sha256},
};
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
/// NOTE: Full verification requires a DNS-backed resolver. This stub
/// parses the message and returns None if unparseable; real DNS
/// verification will be wired in once resolver integration is complete.
pub async fn verify(raw_message: &[u8]) -> DkimVerdict {
    let msg = match AuthenticatedMessage::parse(raw_message) {
        Some(m) => m,
        Option::None => return DkimVerdict::None,
    };
    // TODO: wire up DNS resolver and call resolver.verify_dkim(&msg).await
    debug!("DKIM check (stub — returning None)");
    DkimVerdict::None
}

/// Sign a message with an RSA private key (PEM format).
/// Returns the raw message with a DKIM-Signature header prepended.
pub fn sign(
    raw_message: &[u8],
    domain: &str,
    selector: &str,
    private_key_pem: &[u8],
) -> Result<Vec<u8>, DkimError> {
    // Build RSA key from PEM
    let rsa_key = RsaKey::<Sha256>::from_rsa_pem(private_key_pem)
        .map_err(|e| DkimError::Sign(e.to_string()))?;

    let signer = DkimSigner::from_key(rsa_key)
        .domain(domain)
        .selector(selector)
        .headers(["From", "To", "Subject", "Date", "Message-ID"])
        .canonicalization((Canonicalization::Relaxed, Canonicalization::Relaxed));

    let msg = AuthenticatedMessage::parse(raw_message)
        .ok_or_else(|| DkimError::Sign("could not parse message".into()))?;

    let signature = signer
        .sign(&msg)
        .map_err(|e| DkimError::Sign(e.to_string()))?;

    // Prepend signature header to message
    let sig_header = signature.to_header();
    let mut out = Vec::with_capacity(sig_header.len() + raw_message.len());
    out.extend_from_slice(sig_header.as_bytes());
    out.extend_from_slice(raw_message);
    Ok(out)
}

#[derive(Debug, Error)]
pub enum DkimError {
    #[error("DKIM signing error: {0}")]
    Sign(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
