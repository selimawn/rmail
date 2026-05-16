//! Forward-Confirmed Reverse DNS check.
//!
//! For a connecting IP:
//! 1. PTR lookup  → hostname(s)
//! 2. A/AAAA lookup of each hostname
//! 3. Confirmed if the original IP appears in step 2

use rmail_dns::Resolver;
use std::net::IpAddr;
use tracing::debug;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FcrdnsResult {
    /// IP resolves to a hostname that resolves back to the IP.
    Pass(String),
    /// PTR exists but none of the A/AAAA records match.
    Fail,
    /// No PTR record published.
    NoPTR,
}

pub async fn check(ip: IpAddr, resolver: &Resolver) -> FcrdnsResult {
    let ptrs = match resolver.ptr(ip).await {
        Ok(p) if !p.is_empty() => p,
        _ => return FcrdnsResult::NoPTR,
    };

    for hostname in &ptrs {
        match resolver.host(hostname).await {
            Ok(ips) if ips.contains(&ip) => {
                debug!(%ip, %hostname, "FCrDNS pass");
                return FcrdnsResult::Pass(hostname.clone());
            }
            _ => {}
        }
    }
    debug!(%ip, "FCrDNS fail");
    FcrdnsResult::Fail
}
