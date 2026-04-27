//! DMARC policy evaluation.
//! Uses `mail-auth` 0.5.

use mail_auth::{
    AuthenticatedMessage,
    DmarcOutput,
    dmarc::Policy,
};
use tracing::debug;
use crate::dkim::DkimVerdict;
use crate::spf::SpfVerdict;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmarcVerdict {
    Pass,
    /// Policy says quarantine (deliver to Junk)
    Quarantine,
    /// Policy says reject
    Reject,
    /// No DMARC record or p=none
    None,
}

impl std::fmt::Display for DmarcVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Pass       => "pass",
            Self::Quarantine => "quarantine",
            Self::Reject     => "reject",
            Self::None       => "none",
        };
        f.write_str(s)
    }
}

/// Evaluate DMARC policy.
///
/// NOTE: Full evaluation requires a DNS-backed resolver. This stub
/// returns None and will be replaced once resolver integration is complete.
pub async fn evaluate(
    raw_message: &[u8],
    spf: &SpfVerdict,
    dkim: &DkimVerdict,
) -> DmarcVerdict {
    let _msg = match AuthenticatedMessage::parse(raw_message) {
        Some(m) => m,
        Option::None => return DmarcVerdict::None,
    };
    // TODO: wire up DNS resolver and call resolver.verify_dmarc(&msg).await
    debug!(spf = %spf, dkim = %dkim, "DMARC check (stub — returning None)");
    DmarcVerdict::None
}
