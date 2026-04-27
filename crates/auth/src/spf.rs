//! SPF verification using `mail-auth` (stalwartlabs).
//!
//! Called after MAIL FROM to check whether the client IP is
//! authorised to send on behalf of the sender domain.

use std::net::IpAddr;
use mail_auth::{
    AuthenticatedMessage, MessageAuthenticator,
    SpfOutput, SpfResult,
};
use tracing::debug;
use thiserror::Error;

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
    /// True if the result should be treated as a hard rejection.
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

/// Verify SPF for a given MAIL FROM and client IP.
///
/// `sender_domain` is the domain part of the MAIL FROM address.
/// `client_ip` is the IP of the connecting SMTP client.
pub async fn verify(
    sender_domain: &str,
    client_ip: IpAddr,
    helo: &str,
) -> SpfVerdict {
    let authenticator = MessageAuthenticator::new().unwrap();
    let output: SpfOutput = authenticator
        .verify_spf_sender(client_ip, helo, sender_domain)
        .await;

    let verdict = match output.result() {
        SpfResult::Pass      => SpfVerdict::Pass,
        SpfResult::Fail      => SpfVerdict::Fail,
        SpfResult::SoftFail  => SpfVerdict::SoftFail,
        SpfResult::Neutral   => SpfVerdict::Neutral,
        SpfResult::None      => SpfVerdict::None,
        SpfResult::TempError => SpfVerdict::TempError,
        SpfResult::PermError => SpfVerdict::PermError,
    };
    debug!(%sender_domain, %client_ip, result = %verdict, "SPF");
    verdict
}
