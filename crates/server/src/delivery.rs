//! Outbound SMTP delivery worker.

use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::{info, warn};
use rmail_core::Envelope;
use rmail_config::Config;
use rmail_dns::Resolver;
use rmail_smtp::client;

pub async fn deliver_message(
    envelope: &mut Envelope,
    body_path: &PathBuf,
    config: &Config,
    resolver: &Resolver,
) {
    let body = match tokio::fs::read(body_path).await {
        Ok(b) => b,
        Err(e) => {
            warn!(id = %envelope.id, "cannot read body: {}", e);
            return;
        }
    };

    // Group recipients by domain for efficiency
    let mut domains: std::collections::HashMap<String, Vec<rmail_core::Address>> =
        std::collections::HashMap::new();
    for rcpt in envelope.pending_recipients() {
        domains.entry(rcpt.address.domain.clone()).or_default().push(rcpt.address.clone());
    }

    for (domain, addrs) in &domains {
        let target = match resolve_mx(domain, resolver).await {
            Some(t) => t,
            None => {
                warn!(id = %envelope.id, %domain, "MX lookup failed");
                for addr in addrs {
                    envelope.mark_failed(addr, 451, format!("MX lookup failed for {}", domain));
                }
                continue;
            }
        };

        match client::deliver(target, envelope, &body, &config.server.hostname).await {
            Ok(result) if result.is_success() => {
                for addr in addrs {
                    info!(id = %envelope.id, %addr, "remote delivery ok");
                    envelope.mark_delivered(addr);
                }
            }
            Ok(result) if result.is_permanent() => {
                for addr in addrs {
                    envelope.mark_failed(addr, result.code, result.message.clone());
                }
            }
            Ok(result) => {
                // Transient — will retry (leave as Pending)
                warn!(id = %envelope.id, code = result.code, "transient delivery failure");
            }
            Err(e) => {
                warn!(id = %envelope.id, %domain, "delivery error: {}", e);
            }
        }
    }
}

async fn resolve_mx(domain: &str, resolver: &Resolver) -> Option<SocketAddr> {
    let records = resolver.mx(domain).await.ok()?;
    for mx in records {
        if let Ok(ips) = resolver.host(&mx.exchange).await {
            for ip in ips {
                return Some(SocketAddr::new(ip, 25));
            }
        }
    }
    None
}
