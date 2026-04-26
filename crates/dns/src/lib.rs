//! DNS resolver for rmail.
//!
//! Cloudflare DNS (1.1.1.1 / 1.0.0.1) is used **exclusively**.
//! The system resolver (/etc/resolv.conf) is never consulted.
//! This is a deliberate design decision, not a config option.
//!
//! Transports:
//!   - UDP  (fast path, default)
//!   - TCP  (fallback — large records such as long DKIM keys truncate on UDP)
//!
//! All public functions are async and reuse a single shared resolver instance.

use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;

// ─── Cloudflare DNS addresses ────────────────────────────────────────────────
// Hardcoded. If you need to change these, change them here — not in config.
const CLOUDFLARE: &[&str] = &[
    "1.1.1.1:53",                      // IPv4 primary
    "1.0.0.1:53",                      // IPv4 secondary
    "[2606:4700:4700::1111]:53",       // IPv6 primary
    "[2606:4700:4700::1001]:53",       // IPv6 secondary
];

// ─── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("DNS lookup failed: {0}")]
    Resolve(#[from] hickory_resolver::error::ResolveError),
    #[error("No records found for {0}")]
    NoRecords(String),
}

// ─── Resolver ────────────────────────────────────────────────────────────────

pub struct Resolver(TokioAsyncResolver);

impl Resolver {
    /// Build a resolver that talks exclusively to Cloudflare DNS.
    /// Call once at startup and store in shared state (Arc<Resolver>).
    pub fn new(dnssec: bool) -> Self {
        let mut config = ResolverConfig::new();

        for addr_str in CLOUDFLARE {
            let Ok(addr) = addr_str.parse::<SocketAddr>() else {
                continue;
            };
            // UDP — fast path
            config.add_name_server(NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Udp,
                tls_dns_name: None,
                trust_negative_responses: true,
                bind_addr: None,
            });
            // TCP — fallback for responses that exceed 512-byte UDP limit
            // (common with long DKIM public keys)
            config.add_name_server(NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Tcp,
                tls_dns_name: None,
                trust_negative_responses: true,
                bind_addr: None,
            });
        }

        let mut opts = ResolverOpts::default();
        opts.cache_size    = 2048;
        opts.use_hosts_file = false; // /etc/hosts is irrelevant for mail routing
        opts.validate      = dnssec;

        tracing::info!(
            nameservers = ?CLOUDFLARE,
            dnssec,
            "DNS resolver initialised (Cloudflare)"
        );

        Self(TokioAsyncResolver::tokio(config, opts))
    }

    // ─── MX ──────────────────────────────────────────────────────────────────

    /// MX records for a domain, sorted by priority (ascending).
    /// Used by the delivery worker to find the target server.
    pub async fn mx(&self, domain: &str) -> Result<Vec<MxRecord>, DnsError> {
        tracing::debug!(%domain, "MX lookup");
        let resp = self.0.mx_lookup(domain).await?;
        let mut records: Vec<MxRecord> = resp
            .iter()
            .map(|r| MxRecord {
                priority: r.preference(),
                exchange: r.exchange().to_utf8(),
            })
            .collect();
        records.sort_by_key(|r| r.priority);
        if records.is_empty() {
            return Err(DnsError::NoRecords(format!("MX {domain}")));
        }
        Ok(records)
    }

    // ─── A / AAAA ────────────────────────────────────────────────────────────

    /// All A + AAAA records for a hostname.
    /// Used after MX lookup to resolve the exchange hostname to IPs.
    pub async fn host(&self, hostname: &str) -> Result<Vec<IpAddr>, DnsError> {
        tracing::debug!(%hostname, "A/AAAA lookup");
        let resp = self.0.lookup_ip(hostname).await?;
        let ips: Vec<IpAddr> = resp.iter().collect();
        if ips.is_empty() {
            return Err(DnsError::NoRecords(format!("A/AAAA {hostname}")));
        }
        Ok(ips)
    }

    // ─── PTR ─────────────────────────────────────────────────────────────────

    /// Reverse DNS (PTR) for an IP.
    /// Used for FCrDNS check on inbound SMTP connections.
    pub async fn ptr(&self, ip: IpAddr) -> Result<Vec<String>, DnsError> {
        tracing::debug!(%ip, "PTR lookup");
        let resp = self.0.reverse_lookup(ip).await?;
        Ok(resp.iter().map(|n| n.to_utf8()).collect())
    }

    // ─── TXT ─────────────────────────────────────────────────────────────────

    /// Raw TXT records for a name.
    /// Underlying primitive for SPF, DKIM, DMARC, MTA-STS.
    pub async fn txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        tracing::debug!(%name, "TXT lookup");
        let resp = self.0.txt_lookup(name).await?;
        Ok(resp
            .iter()
            .map(|txt| {
                txt.iter()
                    .map(|b| String::from_utf8_lossy(b).into_owned())
                    .collect::<String>()
            })
            .collect())
    }

    // ─── SPF ─────────────────────────────────────────────────────────────────

    /// The SPF TXT record for a domain (the one starting with `v=spf1`).
    /// Returns None if no SPF record is published.
    pub async fn spf(&self, domain: &str) -> Result<Option<String>, DnsError> {
        let txts = self.txt(domain).await?;
        Ok(txts.into_iter().find(|t| t.starts_with("v=spf1")))
    }

    // ─── DKIM ────────────────────────────────────────────────────────────────

    /// DKIM public key record: `<selector>._domainkey.<domain>`.
    /// The key value is used by mail-auth to verify inbound signatures.
    pub async fn dkim_key(&self, selector: &str, domain: &str) -> Result<String, DnsError> {
        let name = format!("{}._domainkey.{}", selector, domain);
        let txts = self.txt(&name).await?;
        txts.into_iter()
            .find(|t| t.contains("v=DKIM1"))
            .ok_or_else(|| DnsError::NoRecords(name))
    }

    // ─── DMARC ───────────────────────────────────────────────────────────────

    /// DMARC policy record for a domain (`_dmarc.<domain>`).
    /// Returns None if no DMARC policy is published (treat as p=none).
    pub async fn dmarc(&self, domain: &str) -> Result<Option<String>, DnsError> {
        let name = format!("_dmarc.{}", domain);
        // DMARC absence is not an error — many domains don't publish it.
        match self.txt(&name).await {
            Ok(txts) => Ok(txts.into_iter().find(|t| t.starts_with("v=DMARC1"))),
            Err(DnsError::Resolve(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

// ─── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MxRecord {
    /// Lower = higher priority (RFC 5321).
    pub priority: u16,
    /// FQDN of the target mail server.
    pub exchange: String,
}
