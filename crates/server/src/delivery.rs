//! Outbound SMTP delivery worker.

use rmail_config::Config;
use rmail_core::Envelope;
use rmail_dns::Resolver;
use rmail_smtp::client;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{info, warn};

const PER_MX_TIMEOUT: Duration = Duration::from_secs(120);

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
    let body = sign_if_local_sender(envelope, body, config).await;

    let mut domains: std::collections::HashMap<String, Vec<rmail_core::Address>> =
        std::collections::HashMap::new();
    for rcpt in envelope.pending_recipients() {
        domains
            .entry(rcpt.address.domain.clone())
            .or_default()
            .push(rcpt.address.clone());
    }

    for (domain, addrs) in &domains {
        let targets = match resolve_mx_targets(domain, resolver).await {
            MxTargets::Targets(v) => v,
            MxTargets::NullMx => {
                for addr in addrs {
                    envelope.mark_failed(addr, 550, "5.1.10 Null MX domain".into());
                }
                continue;
            }
            MxTargets::LookupFailed => {
                warn!(id = %envelope.id, %domain, "MX lookup failed");
                continue;
            }
        };

        let mut delivered_or_permanent = false;
        for (target, mx_hostname) in targets {
            match timeout(
                PER_MX_TIMEOUT,
                client::deliver(
                    target,
                    envelope,
                    addrs,
                    &body,
                    &config.server.hostname,
                    &mx_hostname,
                ),
            )
            .await
            {
                Ok(Ok(outcome)) => {
                    for (addr, result) in &outcome.rejected {
                        if result.is_permanent() {
                            envelope.mark_failed(addr, result.code, result.message.clone());
                            delivered_or_permanent = true;
                        }
                    }

                    if outcome.final_result.is_success() {
                        for addr in &outcome.accepted {
                            info!(id = %envelope.id, %addr, %mx_hostname, "remote delivery ok");
                            envelope.mark_delivered(addr);
                        }
                        break;
                    }

                    if outcome.final_result.is_permanent() {
                        for addr in &outcome.accepted {
                            envelope.mark_failed(
                                addr,
                                outcome.final_result.code,
                                outcome.final_result.message.clone(),
                            );
                        }
                        break;
                    }

                    warn!(
                        id = %envelope.id,
                        %domain,
                        code = outcome.final_result.code,
                        %mx_hostname,
                        "transient delivery failure"
                    );
                }
                Ok(Err(e)) => {
                    warn!(id = %envelope.id, %domain, %mx_hostname, "delivery error: {}", e);
                }
                Err(_) => {
                    warn!(id = %envelope.id, %domain, %mx_hostname, "delivery timed out");
                }
            }

            if delivered_or_permanent {
                break;
            }
        }
    }
}

async fn sign_if_local_sender(envelope: &Envelope, body: Vec<u8>, config: &Config) -> Vec<u8> {
    if envelope.from.is_null() {
        return body;
    }
    let Some(domain) = config.find_domain(&envelope.from.domain) else {
        return body;
    };
    let key = match tokio::fs::read(&domain.dkim_key).await {
        Ok(k) => k,
        Err(e) => {
            warn!(
                id = %envelope.id,
                domain = %domain.name,
                key = %domain.dkim_key.display(),
                "DKIM key read failed: {}",
                e
            );
            return body;
        }
    };
    match rmail_auth::dkim::sign(&body, &domain.name, &domain.dkim_selector, &key) {
        Ok(signed) => signed,
        Err(e) => {
            warn!(id = %envelope.id, domain = %domain.name, "DKIM signing failed: {}", e);
            body
        }
    }
}

/// Returns all MX targets in priority order. Delivery tries each until one
/// gives a conclusive result.
enum MxTargets {
    Targets(Vec<(SocketAddr, String)>),
    NullMx,
    LookupFailed,
}

async fn resolve_mx_targets(domain: &str, resolver: &Resolver) -> MxTargets {
    let Ok(records) = resolver.mx(domain).await else {
        return MxTargets::LookupFailed;
    };
    if records.len() == 1 && records[0].exchange == "." {
        return MxTargets::NullMx;
    }
    let mut targets = Vec::new();
    for mx in records {
        if let Ok(ips) = resolver.host(&mx.exchange).await {
            for ip in ips {
                targets.push((SocketAddr::new(ip, 25), mx.exchange.clone()));
            }
        }
    }
    if targets.is_empty() {
        MxTargets::LookupFailed
    } else {
        MxTargets::Targets(targets)
    }
}
