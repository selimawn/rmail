//! Inbound mail authentication: SPF, DKIM, DMARC.
//!
//! Wraps `mail-auth` (stalwartlabs) which does the heavy lifting.
//! We are responsible for feeding it the right data and interpreting the result.

use std::net::IpAddr;
use std::time::SystemTime;
use mail_auth::{
    AuthenticatedMessage, Resolver as MailAuthResolver,
    DkimResult, SpfResult, DmarcResult, DmarcPolicy,
    spf::verify::SpfOutput,
    dmarc::verify::DmarcOutput,
};
use tracing::{debug, info, warn};
use thiserror::Error;

#[derive(Debug)]
pub struct AuthResults {
    pub spf:   SpfOutcome,
    pub dkim:  DkimOutcome,
    pub dmarc: DmarcOutcome,
}

impl AuthResults {
    /// Produce the `Authentication-Results:` header value.
    pub fn header(&self, server_hostname: &str) -> String {
        format!(
            "{host};\r\n spf={spf} smtp.mailfrom={spf_domain};\r\n dkim={dkim};\r\n dmarc={dmarc}",
            host = server_hostname,
            spf = self.spf.label(),
            spf_domain = self.spf.domain(),
            dkim = self.dkim.label(),
            dmarc = self.dmarc.label(),
        )
    }

    /// True when DMARC policy says we MUST reject this message.
    pub fn should_reject(&self) -> Option<&'static str> {
        if self.dmarc == DmarcOutcome::Reject {
            Some("Message rejected due to DMARC policy")
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SpfOutcome { Pass, Fail, SoftFail, Neutral, None, TempError, PermError }
impl SpfOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pass      => "pass",
            Self::Fail      => "fail",
            Self::SoftFail  => "softfail",
            Self::Neutral   => "neutral",
            Self::None      => "none",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
        }
    }
    pub fn domain(&self) -> &str { "" }  // filled by caller
}

#[derive(Debug, Clone, PartialEq)]
pub enum DkimOutcome { Pass, Fail, None, PermError, TempError }
impl DkimOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pass      => "pass",
            Self::Fail      => "fail",
            Self::None      => "none",
            Self::PermError => "permerror",
            Self::TempError => "temperror",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DmarcOutcome { Pass, Fail, Quarantine, Reject, None }
impl DmarcOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pass       => "pass",
            Self::Fail       => "fail",
            Self::Quarantine => "quarantine",
            Self::Reject     => "reject",
            Self::None       => "none",
        }
    }
}

/// Verify SPF, DKIM and DMARC for an inbound message.
///
/// `raw_message` is the full RFC 5322 bytes.
/// `mail_from_domain` is the domain from the SMTP MAIL FROM address.
/// `client_ip` is the connecting client's IP.
pub async fn verify(
    raw_message: &[u8],
    mail_from: &str,
    mail_from_domain: &str,
    helo_domain: &str,
    client_ip: IpAddr,
    server_hostname: &str,
) -> AuthResults {
    // mail-auth's async resolver uses its own DNS — but we want to use our
    // Cloudflare-only resolver. For now we use mail-auth's built-in resolver
    // and will wire our custom hickory resolver in the next phase.
    // TODO: replace with rmail-dns::Resolver once mail-auth supports custom resolvers.
    let resolver = match MailAuthResolver::new_cloudflare_tls().await {
        Ok(r)  => r,
        Err(e) => {
            warn!("Cannot build mail-auth resolver: {}", e);
            return AuthResults {
                spf:   SpfOutcome::TempError,
                dkim:  DkimOutcome::TempError,
                dmarc: DmarcOutcome::None,
            };
        }
    };

    // ─── SPF
    let spf = resolver
        .verify_spf_helo(client_ip, helo_domain, server_hostname)
        .await;

    let spf_outcome = match spf.result() {
        SpfResult::Pass      => SpfOutcome::Pass,
        SpfResult::Fail      => SpfOutcome::Fail,
        SpfResult::SoftFail  => SpfOutcome::SoftFail,
        SpfResult::Neutral   => SpfOutcome::Neutral,
        SpfResult::None      => SpfOutcome::None,
        SpfResult::TempError => SpfOutcome::TempError,
        SpfResult::PermError => SpfOutcome::PermError,
    };
    debug!(spf = spf_outcome.label(), "SPF result");

    // ─── DKIM
    let auth_msg = match AuthenticatedMessage::parse(raw_message) {
        Some(m) => m,
        None => {
            return AuthResults {
                spf: spf_outcome,
                dkim: DkimOutcome::PermError,
                dmarc: DmarcOutcome::None,
            };
        }
    };

    let dkim_results = resolver.verify_dkim(&auth_msg).await;
    let dkim_outcome = if dkim_results.iter().any(|r| *r.result() == DkimResult::Pass) {
        DkimOutcome::Pass
    } else if dkim_results.is_empty() {
        DkimOutcome::None
    } else {
        DkimOutcome::Fail
    };
    debug!(dkim = dkim_outcome.label(), "DKIM result");

    // ─── DMARC
    let dmarc_output = resolver
        .verify_dmarc(&auth_msg, &dkim_results, mail_from_domain, &spf, &spf)
        .await;

    let dmarc_outcome = match dmarc_output.policy() {
        DmarcPolicy::None       => match dmarc_output.dmarc_result() {
            DmarcResult::Pass => DmarcOutcome::Pass,
            _                 => DmarcOutcome::Fail,
        },
        DmarcPolicy::Quarantine => DmarcOutcome::Quarantine,
        DmarcPolicy::Reject     => DmarcOutcome::Reject,
    };
    debug!(dmarc = dmarc_outcome.label(), "DMARC result");

    AuthResults { spf: spf_outcome, dkim: dkim_outcome, dmarc: dmarc_outcome }
}
