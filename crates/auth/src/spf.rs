//! SPF verification using `mail-auth` 0.5.

use mail_auth::{Resolver as MailAuthResolver, SpfResult};
use std::net::IpAddr;
use tracing::{debug, warn};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpfVerdict {
    Pass,
    Fail,
    SoftFail,
    Neutral,
    None,
    TempError,
    PermError,
}

impl SpfVerdict {
    pub fn is_reject(&self) -> bool {
        matches!(self, Self::Fail)
    }
}

impl std::fmt::Display for SpfVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::SoftFail => "softfail",
            Self::Neutral => "neutral",
            Self::None => "none",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
        };
        f.write_str(s)
    }
}

/// Verify SPF for a given MAIL FROM address and connecting client.
///
/// Uses Cloudflare DNS via `mail_auth`'s built-in resolver.
/// For the full inbound auth pipeline (SPF + DKIM + DMARC), prefer `checker::verify`.
pub async fn verify(
    mail_from: &str,
    client_ip: IpAddr,
    helo: &str,
    server_hostname: &str,
) -> SpfVerdict {
    let resolver = match MailAuthResolver::new_cloudflare_tls() {
        Ok(r) => r,
        Err(e) => {
            warn!("Cannot build mail-auth resolver: {e}");
            return SpfVerdict::TempError;
        }
    };
    let spf = resolver
        .verify_spf(client_ip, helo, server_hostname, mail_from)
        .await;
    let verdict = match spf.result() {
        SpfResult::Pass => SpfVerdict::Pass,
        SpfResult::Fail => SpfVerdict::Fail,
        SpfResult::SoftFail => SpfVerdict::SoftFail,
        SpfResult::Neutral => SpfVerdict::Neutral,
        SpfResult::None => SpfVerdict::None,
        SpfResult::TempError => SpfVerdict::TempError,
        SpfResult::PermError => SpfVerdict::PermError,
    };
    debug!(%mail_from, %client_ip, result = %verdict, "SPF");
    verdict
}
