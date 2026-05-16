//! Queue manager: moves messages from `incoming` to `active`,
//! dispatches to local delivery or outbound SMTP delivery.

use rmail_config::Config;
use rmail_core::{DeliveryStatus, Envelope, QueueState};
use rmail_dns::Resolver;
use rmail_mailbox::{MailboxError, Maildir};
use rmail_queue::Queue;
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

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
        queue
            .transition(id, QueueState::Incoming, QueueState::Active)
            .await?;
    }

    // 2. Process active queue
    let active = queue.list(QueueState::Active).await?;
    for id in active {
        let msg = match queue.load(QueueState::Active, &id).await {
            Ok(m) => m,
            Err(e) => {
                warn!(%id, "load error: {}", e);
                continue;
            }
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
                Err(e) => {
                    warn!(%id, "body read error: {}", e);
                    continue;
                }
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
                    Err(MailboxError::UserNotFound(_)) => {
                        warn!(%id, %addr, "local recipient has no Maildir");
                        envelope.mark_failed(addr, 550, "Local user mailbox does not exist".into());
                    }
                    Err(e) => {
                        warn!(%id, %addr, "local delivery error: {}", e);
                    }
                }
            }
        } else {
            // Remote delivery — handled by delivery worker
            crate::delivery::deliver_message(&mut envelope, &msg.body_path, config, resolver).await;
        }

        if envelope.all_done() {
            if has_failures(&envelope) {
                crate::bounce::generate(
                    &envelope,
                    &failure_summary(&envelope),
                    queue,
                    &config.server.hostname,
                )
                .await;
            }
            queue.remove(QueueState::Active, &id).await?;
        } else {
            // Some recipients still pending — defer
            envelope.retry_count += 1;
            if retry_budget_exhausted(&envelope, config) {
                mark_pending_failed(
                    &mut envelope,
                    451,
                    "Delivery retry limit reached or bounce window expired",
                );
                crate::bounce::generate(
                    &envelope,
                    &failure_summary(&envelope),
                    queue,
                    &config.server.hostname,
                )
                .await;
                queue.remove(QueueState::Active, &id).await?;
                continue;
            }
            let delay = rmail_config::next_retry_delay(&config.delivery, envelope.retry_count);
            let next = chrono_now() + delay as i64;
            envelope.next_retry_at = Some(next);
            queue.update_envelope(QueueState::Active, &envelope).await?;
            queue
                .transition(&id, QueueState::Active, QueueState::Deferred)
                .await?;
        }
    }

    // 3. Re-queue deferred messages that are ready
    let deferred = queue.list(QueueState::Deferred).await?;
    let now = chrono_now();
    for id in deferred {
        if let Ok(msg) = queue.load(QueueState::Deferred, &id).await {
            if msg.envelope.next_retry_at.map(|t| t <= now).unwrap_or(true) {
                queue
                    .transition(&id, QueueState::Deferred, QueueState::Active)
                    .await?;
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

fn has_failures(envelope: &Envelope) -> bool {
    envelope
        .recipients
        .iter()
        .any(|r| matches!(r.status, DeliveryStatus::Failed { .. }))
}

fn failure_summary(envelope: &Envelope) -> String {
    let failures: Vec<String> = envelope
        .recipients
        .iter()
        .filter_map(|r| match &r.status {
            DeliveryStatus::Failed { code, message } => {
                Some(format!("{}: {} {}", r.address, code, message))
            }
            _ => None,
        })
        .collect();
    if failures.is_empty() {
        "Delivery failed".into()
    } else {
        failures.join("; ")
    }
}

fn retry_budget_exhausted(envelope: &Envelope, config: &Config) -> bool {
    if envelope.retry_count >= config.delivery.max_retries {
        return true;
    }
    let bounce_after = (config.delivery.bounce_after_hours as i64).saturating_mul(3600);
    chrono_now().saturating_sub(envelope.received_at.unix_timestamp()) >= bounce_after
}

fn mark_pending_failed(envelope: &mut Envelope, code: u16, message: &str) {
    for rcpt in &mut envelope.recipients {
        if rcpt.status == DeliveryStatus::Pending {
            rcpt.status = DeliveryStatus::Failed {
                code,
                message: message.to_owned(),
            };
        }
    }
}
