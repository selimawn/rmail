//! DKIM verification (inbound) and signing (outbound).
//! Uses `mail-auth` 0.5.

use mail_auth::common::headers::HeaderWriter;
use mail_auth::{
    common::crypto::{RsaKey, Sha256},
    dkim::DkimSigner,
    AuthenticatedMessage,
};
use thiserror::Error;
use tracing::debug;

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
        f.write_str(match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::PermError => "permerror",
            Self::TempError => "temperror",
            Self::None => "none",
        })
    }
}

/// Stub: verify is handled by checker.rs using mail-auth's full resolver pipeline.
/// This function is kept for direct/unit-test use.
pub async fn verify(raw_message: &[u8]) -> DkimVerdict {
    match AuthenticatedMessage::parse(raw_message) {
        Some(_) => {
            debug!("DKIM verify (use checker::verify for full DNS-based verification)");
            DkimVerdict::None
        }
        Option::None => DkimVerdict::PermError,
    }
}

/// Sign a raw RFC 5322 message with an RSA-SHA256 DKIM signature.
/// Prepends the `DKIM-Signature:` header to the message.
pub fn sign(
    raw_message: &[u8],
    domain: &str,
    selector: &str,
    private_key_pem: &[u8],
) -> Result<Vec<u8>, DkimError> {
    let pk = RsaKey::<Sha256>::from_pkcs8_pem(
        std::str::from_utf8(private_key_pem).map_err(|e| DkimError::Sign(e.to_string()))?,
    )
    .map_err(|e| DkimError::Sign(e.to_string()))?;

    let signature = DkimSigner::from_key(pk)
        .domain(domain)
        .selector(selector)
        .headers([
            "From",
            "To",
            "Subject",
            "Date",
            "Message-ID",
            "MIME-Version",
            "Content-Type",
        ])
        .sign(raw_message)
        .map_err(|e| DkimError::Sign(e.to_string()))?;

    let header_line = signature.to_header();
    let mut out = Vec::with_capacity(header_line.len() + 2 + raw_message.len());
    out.extend_from_slice(header_line.as_bytes());
    out.extend_from_slice(b"\r\n");
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
