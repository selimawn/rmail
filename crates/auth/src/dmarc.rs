//! DMARC policy evaluation.
//! Combines SPF + DKIM results and looks up the sender domain's DMARC record.

use mail_auth::{
    AuthenticatedMessage, MessageAuthenticator,
    DmarcOutput, DmarcResult,
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

pub async fn evaluate(
    raw_message: &[u8],
    spf: &SpfVerdict,
    dkim: &DkimVerdict,
) -> DmarcVerdict {
    let authenticator = match MessageAuthenticator::new() {
        Ok(a) => a,
        Err(_) => return DmarcVerdict::None,
    };
    let msg = match AuthenticatedMessage::parse(raw_message) {
        Ok(m) => m,
        Err(_) => return DmarcVerdict::None,
    };

    let output: DmarcOutput = authenticator.verify_dmarc(&msg).await;
    let verdict = match output.dmarc_pass() {
        true => DmarcVerdict::Pass,
        false => match output.policy() {
            Policy::Reject      => DmarcVerdict::Reject,
            Policy::Quarantine  => DmarcVerdict::Quarantine,
            _                   => DmarcVerdict::None,
        },
    };
    debug!(spf = %spf, dkim = %dkim, dmarc = %verdict, "DMARC");
    verdict
}
