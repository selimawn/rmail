//! SPF verification using `mail-auth` 0.5.

use std::net::IpAddr;
use tracing::debug;

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
            Self::Pass      => "pass",
            Self::Fail      => "fail",
            Self::SoftFail  => "softfail",
            Self::Neutral   => "neutral",
            Self::None      => "none",
            Self::TempError => "temperror",
            Self::PermError => "permerror",
        };
        f.write_str(s)
    }
}

/// Verify SPF for a given MAIL FROM domain and client IP.
///
/// NOTE: Full async DNS-backed SPF verification requires wiring in a
/// `mail_auth::Resolver` implementation. This stub returns `None` and
/// will be replaced once the DNS resolver integration is complete.
pub async fn verify(
    sender_domain: &str,
    client_ip: IpAddr,
    helo: &str,
) -> SpfVerdict {
    // TODO: wire up mail_auth resolver for real SPF evaluation
    debug!(%sender_domain, %client_ip, %helo, "SPF check (stub — returning None)");
    SpfVerdict::None
}
