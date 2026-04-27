//! Cleanup task: validates an inbound message and runs SPF/DKIM/DMARC.
//! Moves `incoming/<id>` → `active/<id>` when clean.

use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{info, warn, error};
use rmail_config::Config;
use rmail_queue::Queue;
use rmail_core::QueueState;
use rmail_auth::checker;
use rmail_dns::Resolver;

pub async fn run_one(
    id: &str,
    config: &Config,
    queue: &Queue,
    dns: &Resolver,
    notify: &mpsc::Sender<String>,
) {
    let msg = match queue.load(QueueState::Incoming, id).await {
        Ok(m)  => m,
        Err(e) => { error!(%id, "cleanup load failed: {}", e); return; }
    };

    let body = match tokio::fs::read(&msg.body_path).await {
        Ok(b)  => b,
        Err(e) => { error!(%id, "cleanup read body failed: {}", e); return; }
    };

    // SPF / DKIM / DMARC
    let from_domain = msg.envelope.from.domain.as_str();
    let from_addr   = msg.envelope.from.as_str();
    let helo        = &msg.envelope.client_helo;
    let client_ip   = msg.envelope.client_ip;

    let auth = checker::verify(
        &body,
        &from_addr,
        from_domain,
        helo,
        client_ip,
        &config.server.hostname,
    ).await;

    info!(%id, spf = auth.spf.label(), dkim = auth.dkim.label(), dmarc = auth.dmarc.label(), "auth check");

    if let Some(reason) = auth.should_reject() {
        warn!(%id, %reason, "cleanup: DMARC reject");
        // Move to corrupt for logging — do not bounce (prevents backscatter)
        let _ = queue.transition(id, QueueState::Incoming, QueueState::Corrupt).await;
        return;
    }

    // Prepend Authentication-Results header to body
    let auth_header = format!("Authentication-Results: {}\r\n", auth.header(&config.server.hostname));
    let mut new_body = auth_header.into_bytes();
    new_body.extend_from_slice(&body);

    // Rewrite body with prepended header
    if let Err(e) = tokio::fs::write(&msg.body_path, &new_body).await {
        error!(%id, "cleanup: rewrite body failed: {}", e);
        return;
    }

    // Transition incoming → active, then notify queue manager
    match queue.transition(id, QueueState::Incoming, QueueState::Active).await {
        Ok(()) => {
            info!(%id, "cleanup done, queued for delivery");
            let _ = notify.send(id.to_owned()).await;
        }
        Err(e) => error!(%id, "cleanup transition failed: {}", e),
    }
}
