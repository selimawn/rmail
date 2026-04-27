//! Queue manager: picks messages from `active/` and dispatches them.
//!
//! Runs as a background Tokio task.
//! Woken by a channel whenever a new message lands in `incoming/` after cleanup.

use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tracing::{info, warn, error, debug};
use rmail_config::Config;
use rmail_queue::Queue;
use rmail_mailbox::Maildir;
use rmail_dns::Resolver;
use rmail_core::{QueueState, Address};

/// Channel message: a new queue ID is ready for delivery.
pub type QueueNotify = mpsc::Sender<String>;

pub async fn run(
    config:  Arc<Config>,
    queue:   Arc<Queue>,
    mailbox: Arc<Maildir>,
    dns:     Arc<Resolver>,
    mut rx:  mpsc::Receiver<String>,
) {
    info!("Queue manager started");

    // On startup, process anything left in active/ (crash recovery)
    sweep(&config, &queue, &mailbox, &dns).await;

    loop {
        tokio::select! {
            Some(id) = rx.recv() => {
                // New message: move incoming -> active, then deliver
                match queue.transition(&id, QueueState::Incoming, QueueState::Active).await {
                    Ok(()) => deliver_one(&id, &config, &queue, &mailbox, &dns).await,
                    Err(e) => warn!(%id, "transition incoming->active failed: {}", e),
                }
            }
            // Periodic scan for deferred messages ready for retry
            _ = sleep(Duration::from_secs(60)) => {
                sweep_deferred(&config, &queue, &mailbox, &dns).await;
            }
        }
    }
}

async fn sweep(config: &Config, queue: &Queue, mailbox: &Maildir, dns: &Resolver) {
    match queue.list(QueueState::Active).await {
        Ok(ids) => {
            for id in ids {
                deliver_one(&id, config, queue, mailbox, dns).await;
            }
        }
        Err(e) => error!("sweep error: {}", e),
    }
}

async fn sweep_deferred(config: &Config, queue: &Queue, mailbox: &Maildir, dns: &Resolver) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    match queue.list(QueueState::Deferred).await {
        Ok(ids) => {
            for id in ids {
                if let Ok(msg) = queue.load(QueueState::Deferred, &id).await {
                    let ready = msg.envelope.next_retry_at
                        .map(|t| now >= t)
                        .unwrap_or(true);
                    if ready {
                        match queue.transition(&id, QueueState::Deferred, QueueState::Active).await {
                            Ok(()) => deliver_one(&id, config, queue, mailbox, dns).await,
                            Err(e) => warn!(%id, "deferred->active failed: {}", e),
                        }
                    }
                }
            }
        }
        Err(e) => error!("deferred sweep error: {}", e),
    }
}

async fn deliver_one(id: &str, config: &Config, queue: &Queue, mailbox: &Maildir, dns: &Resolver) {
    let msg = match queue.load(QueueState::Active, id).await {
        Ok(m) => m,
        Err(e) => { error!(%id, "load failed: {}", e); return; }
    };

    let body = match tokio::fs::read(&msg.body_path).await {
        Ok(b) => b,
        Err(e) => { error!(%id, "read body failed: {}", e); return; }
    };

    let mut envelope = msg.envelope;
    let mut any_pending = false;

    for rcpt in envelope.recipients.clone() {
        if rcpt.status != rmail_core::DeliveryStatus::Pending { continue; }

        let addr = &rcpt.address;
        if config.is_local_domain(&addr.domain) {
            // Local delivery via Maildir
            match mailbox.deliver(addr, &body).await {
                Ok(f) => {
                    info!(%id, address = %addr, file = %f, "delivered local");
                    envelope.mark_delivered(addr);
                }
                Err(e) => {
                    warn!(%id, address = %addr, "local delivery failed: {}", e);
                    envelope.mark_failed(addr, 450, e.to_string());
                    any_pending = true;
                }
            }
        } else {
            // Remote delivery — handed to delivery worker
            match crate::delivery::deliver_remote(id, addr, &body, dns, config).await {
                Ok(()) => { envelope.mark_delivered(addr); }
                Err((code, msg)) => {
                    if code >= 500 {
                        envelope.mark_failed(addr, code, msg);
                    } else {
                        any_pending = true;
                    }
                }
            }
        }
    }

    // Update envelope on disk
    let _ = queue.update_envelope(QueueState::Active, &envelope).await;

    if envelope.all_done() {
        let _ = queue.remove(QueueState::Active, id).await;
        info!(%id, "all recipients delivered, removed from queue");
    } else if any_pending {
        // Schedule retry with exponential backoff
        let delay = rmail_config::next_retry_delay(&config.delivery, envelope.retry_count);
        let mut env = envelope;
        env.retry_count += 1;
        let next = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64 + delay as i64;
        env.next_retry_at = Some(next);
        let _ = queue.update_envelope(QueueState::Active, &env).await;
        let _ = queue.transition(id, QueueState::Active, QueueState::Deferred).await;
        info!(%id, retry_in = delay, "deferred");
    }
}
