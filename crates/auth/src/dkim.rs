//! DKIM verification (inbound) and signing (outbound).
//! Delegates to `mail-auth` (stalwartlabs).

use std::path::Path;
use mail_auth::{
    AuthenticatedMessage, MessageAuthenticator,
    DkimOutput, DkimResult,
    dkim::{DkimSigner, SignatureAlgorithm, Canonicalization},
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
/// Returns the best (highest-quality) result found.
pub async fn verify(raw_message: &[u8]) -> DkimVerdict {
    let authenticator = match MessageAuthenticator::new() {
        Ok(a) => a,
        Err(_) => return DkimVerdict::TempError,
    };
    let msg = match AuthenticatedMessage::parse(raw_message) {
        Ok(m) => m,
        Err(_) => return DkimVerdict::None,
    };
    let results: Vec<DkimOutput> = authenticator.verify_dkim(&msg).await;
    if results.is_empty() {
        return DkimVerdict::None;
    }
    // Return Pass if any signature passes
    for r in &results {
        if r.result() == &DkimResult::Pass {
            debug!("DKIM pass");
            return DkimVerdict::Pass;
        }
    }
    // Otherwise return the first failure
    match results[0].result() {
        DkimResult::Fail(_)      => DkimVerdict::Fail,
        DkimResult::PermError(_) => DkimVerdict::PermError,
        DkimResult::TempError(_) => DkimVerdict::TempError,
        _                        => DkimVerdict::None,
    }
}

/// Sign a message with the given RSA private key.
/// Returns the raw message with a DKIM-Signature header prepended.
pub fn sign(
    raw_message: &[u8],
    domain: &str,
    selector: &str,
    private_key_pem: &[u8],
) -> Result<Vec<u8>, DkimError> {
    let signer = DkimSigner::from_rsa_pem(private_key_pem)
        .map_err(|e| DkimError::Sign(e.to_string()))?
        .domain(domain)
        .selector(selector)
        .headers(["From", "To", "Subject", "Date", "Message-ID"])
        .algorithm(SignatureAlgorithm::RsaSha256)
        .canonicalization((Canonicalization::Relaxed, Canonicalization::Relaxed));

    let msg = AuthenticatedMessage::parse(raw_message)
        .map_err(|e| DkimError::Sign(e.to_string()))?;
    let signature = signer.sign(&msg)
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
