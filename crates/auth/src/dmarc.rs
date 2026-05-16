//! DMARC policy evaluation.
//! Uses `mail-auth` 0.5.

use mail_auth::{dmarc::Policy, AuthenticatedMessage, DmarcResult, Resolver as MailAuthResolver};
use std::net::IpAddr;
use tracing::{debug, warn};

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
            Self::Pass => "pass",
            Self::Quarantine => "quarantine",
            Self::Reject => "reject",
            Self::None => "none",
        };
        f.write_str(s)
    }
}

/// Evaluate DMARC policy for an inbound message.
///
/// Runs SPF and DKIM checks internally then applies the sender domain's DMARC policy.
/// For the full inbound auth pipeline with a shared `AuthResults`, prefer `checker::verify`.
pub async fn evaluate(
    raw_message: &[u8],
    mail_from: &str,
    mail_from_domain: &str,
    client_ip: IpAddr,
    helo: &str,
    server_hostname: &str,
) -> DmarcVerdict {
    let resolver = match MailAuthResolver::new_cloudflare_tls() {
        Ok(r) => r,
        Err(e) => {
            warn!("Cannot build mail-auth resolver: {e}");
            return DmarcVerdict::None;
        }
    };

    let auth_msg = match AuthenticatedMessage::parse(raw_message) {
        Some(m) => m,
        Option::None => return DmarcVerdict::None,
    };

    let spf = resolver
        .verify_spf(client_ip, helo, server_hostname, mail_from)
        .await;
    let dkim_results = resolver.verify_dkim(&auth_msg).await;

    let dmarc_output = resolver
        .verify_dmarc(&auth_msg, &dkim_results, mail_from_domain, &spf, |d| d)
        .await;

    let pass = matches!(dmarc_output.spf_result(), DmarcResult::Pass)
        || matches!(dmarc_output.dkim_result(), DmarcResult::Pass);

    let verdict = if pass {
        DmarcVerdict::Pass
    } else {
        match dmarc_output.policy() {
            Policy::Reject => DmarcVerdict::Reject,
            Policy::Quarantine => DmarcVerdict::Quarantine,
            Policy::None | Policy::Unspecified => DmarcVerdict::None,
        }
    };
    debug!(%mail_from_domain, result = %verdict, "DMARC");
    verdict
}
