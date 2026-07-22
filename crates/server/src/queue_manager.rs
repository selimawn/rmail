//! Queue manager: moves messages from `incoming` to `active`,
//! dispatches to local delivery or outbound SMTP delivery.
//!
//! Local and remote recipients of the same message are handled independently:
//! local recipients go straight to their Maildir (Junk when the message was
//! quarantined by DMARC), remote recipients go through MX resolution and the
//! outbound SMTP client. Messages are processed concurrently; the loop wakes
//! immediately when a new message is enqueued, and otherwise sleeps until the
//! next scheduled retry.

use rmail_config::Config;
use rmail_core::{DeliveryStatus, Envelope, QueueState};
use rmail_dns::Resolver;
use rmail_mailbox::{MailboxError, Maildir};
use rmail_queue::Queue;
use std::sync::Arc;
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinSet;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

/// Maximum messages being delivered at the same time.
const MAX_CONCURRENT_DELIVERIES: usize = 16;
/// Fallback sleep when the queue is empty or the next retry is unknown.
const IDLE_SLEEP: Duration = Duration::from_secs(60);

pub async fn run(
    config: Arc<Config>,
    queue: Arc<Queue>,
    maildir: Arc<Maildir>,
    resolver: Arc<Resolver>,
    notify: Arc<Notify>,
) {
    loop {
        if let Err(e) = tick(&config, &queue, &maildir, &resolver).await {
            error!("qmgr tick error: {}", e);
        }
        let wait = next_wake_delay(&queue).await.unwrap_or(IDLE_SLEEP);
        tokio::select! {
            _ = notify.notified() => {}
            _ = sleep(wait) => {}
        }
    }
}

/// Sleep until the next deferred message is due (clamped to [1s, IDLE_SLEEP]).
async fn next_wake_delay(queue: &Queue) -> Option<Duration> {
    let deferred = queue.list(QueueState::Deferred).await.ok()?;
    if deferred.is_empty() {
        return Some(IDLE_SLEEP);
    }
    let now = chrono_now();
    let mut soonest = i64::MAX;
    for id in deferred {
        if let Ok(msg) = queue.load(QueueState::Deferred, &id).await {
            if let Some(t) = msg.envelope.next_retry_at {
                soonest = soonest.min(t);
            }
        }
    }
    if soonest == i64::MAX {
        return Some(IDLE_SLEEP);
    }
    let secs = (soonest - now).clamp(1, IDLE_SLEEP.as_secs() as i64) as u64;
    Some(Duration::from_secs(secs))
}

async fn tick(
    config: &Arc<Config>,
    queue: &Arc<Queue>,
    maildir: &Arc<Maildir>,
    resolver: &Arc<Resolver>,
) -> anyhow::Result<()> {
    // 1. Promote incoming → active
    let incoming = queue.list(QueueState::Incoming).await?;
    for id in &incoming {
        queue
            .transition(id, QueueState::Incoming, QueueState::Active)
            .await?;
    }

    // 2. Re-queue deferred messages that are ready
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

    // 3. Process the active queue concurrently
    let active = queue.list(QueueState::Active).await?;
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES));
    let mut set: JoinSet<()> = JoinSet::new();
    for id in active {
        let permit = Arc::clone(&sem).acquire_owned().await?;
        let (config, queue, maildir, resolver) = (
            Arc::clone(config),
            Arc::clone(queue),
            Arc::clone(maildir),
            Arc::clone(resolver),
        );
        set.spawn(async move {
            let _permit = permit;
            if let Err(e) = process_message(&id, &config, &queue, &maildir, &resolver).await {
                warn!(%id, "delivery task error: {}", e);
            }
        });
    }
    while let Some(res) = set.join_next().await {
        if let Err(e) = res {
            warn!("delivery task panicked: {}", e);
        }
    }
    Ok(())
}

async fn process_message(
    id: &str,
    config: &Arc<Config>,
    queue: &Arc<Queue>,
    maildir: &Arc<Maildir>,
    resolver: &Arc<Resolver>,
) -> anyhow::Result<()> {
    let msg = match queue.load(QueueState::Active, id).await {
        Ok(m) => m,
        Err(e) => {
            warn!(%id, "load error: {}", e);
            return Ok(());
        }
    };
    let mut envelope = msg.envelope;

    // Split pending recipients: local → Maildir, remote → outbound SMTP.
    let local: Vec<_> = envelope
        .pending_recipients()
        .filter(|r| config.is_local_domain(&r.address.domain))
        .map(|r| r.address.clone())
        .collect();
    let has_remote = envelope
        .pending_recipients()
        .any(|r| !config.is_local_domain(&r.address.domain));

    if !local.is_empty() || has_remote {
        let body = match queue.read_body(QueueState::Active, id).await {
            Ok(b) => b,
            Err(e) => {
                warn!(%id, "body read error: {}", e);
                return Ok(());
            }
        };

        for addr in &local {
            // DMARC quarantine: deliver to Junk instead of INBOX.
            let result = if envelope.quarantine {
                maildir.append_to_folder(addr, "Junk", &body, "").await
            } else {
                maildir.deliver(addr, &body).await
            };
            match result {
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

        if has_remote {
            crate::delivery::deliver_message(&mut envelope, body, config, resolver).await;
        }
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
        queue.remove(QueueState::Active, id).await?;
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
            queue.remove(QueueState::Active, id).await?;
            return Ok(());
        }
        let delay = rmail_config::next_retry_delay(&config.delivery, envelope.retry_count);
        let next = chrono_now() + delay as i64;
        envelope.next_retry_at = Some(next);
        queue.update_envelope(QueueState::Active, &envelope).await?;
        queue
            .transition(id, QueueState::Active, QueueState::Deferred)
            .await?;
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
