//! Queue manager: moves messages from `incoming` to `active`,
//! dispatches to local delivery or outbound SMTP delivery.

use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};
use rmail_config::Config;
use rmail_queue::Queue;
use rmail_mailbox::Maildir;
use rmail_core::QueueState;
use rmail_dns::Resolver;

pub async fn run(
    config: Arc<Config>,
    queue: Arc<Queue>,
    maildir: Arc<Maildir>,
    resolver: Arc<Resolver>,
) {
    loop {
        if let Err(e) = tick(&config, &queue, &maildir, &resolver).await {
            error!("qmgr tick error: {}", e);
        }
        sleep(Duration::from_secs(10)).await;
    }
}

async fn tick(
    config: &Config,
    queue: &Queue,
    maildir: &Maildir,
    resolver: &Resolver,
) -> anyhow::Result<()> {
    // 1. Promote incoming → active
    let incoming = queue.list(QueueState::Incoming).await?;
    for id in &incoming {
        queue.transition(id, QueueState::Incoming, QueueState::Active).await?;
    }

    // 2. Process active queue
    let active = queue.list(QueueState::Active).await?;
    for id in active {
        let msg = match queue.load(QueueState::Active, &id).await {
            Ok(m) => m,
            Err(e) => { warn!(%id, "load error: {}", e); continue; }
        };

        let mut envelope = msg.envelope;
        let mut all_local = true;

        for rcpt in envelope.pending_recipients() {
            if !config.is_local_domain(&rcpt.address.domain) {
                all_local = false;
            }
        }

        if all_local {
            // Read body once, deliver to all local recipients
            let body = match tokio::fs::read(&msg.body_path).await {
                Ok(b) => b,
                Err(e) => { warn!(%id, "body read error: {}", e); continue; }
            };
            let recipients: Vec<_> = envelope
                .pending_recipients()
                .map(|r| r.address.clone())
                .collect();
            for addr in &recipients {
                match maildir.deliver(addr, &body).await {
                    Ok(filename) => {
                        info!(%id, %addr, %filename, "local delivery ok");
                        envelope.mark_delivered(addr);
                    }
                    Err(e) => {
                        warn!(%id, %addr, "local delivery error: {}", e);
                        envelope.mark_failed(addr, 451, e.to_string());
                    }
                }
            }
        } else {
            // Remote delivery — handled by delivery worker
            crate::delivery::deliver_message(&mut envelope, &msg.body_path, config, resolver).await;
        }

        if envelope.all_done() {
            queue.remove(QueueState::Active, &id).await?;
        } else {
            // Some recipients still pending — defer
            envelope.retry_count += 1;
            let delay = rmail_config::next_retry_delay(&config.delivery, envelope.retry_count);
            let next = chrono_now() + delay as i64;
            envelope.next_retry_at = Some(next);
            queue.update_envelope(QueueState::Active, &envelope).await?;
            queue.transition(&id, QueueState::Active, QueueState::Deferred).await?;
        }
    }

    // 3. Re-queue deferred messages that are ready
    let deferred = queue.list(QueueState::Deferred).await?;
    let now = chrono_now();
    for id in deferred {
        if let Ok(msg) = queue.load(QueueState::Deferred, &id).await {
            if msg.envelope.next_retry_at.map(|t| t <= now).unwrap_or(true) {
                queue.transition(&id, QueueState::Deferred, QueueState::Active).await?;
            }
        }
    }
    Ok(())
}

fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
