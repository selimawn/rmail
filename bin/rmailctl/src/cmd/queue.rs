//! `rmailctl queue` subcommands.

use clap::{Args, Subcommand};
use rmail_config::Config;
use rmail_queue::Queue;
use rmail_core::QueueState;

#[derive(Args)]
pub struct QueueArgs {
    #[command(subcommand)]
    pub command: QueueCmd,
}

#[derive(Subcommand)]
pub enum QueueCmd {
    /// List messages in a queue state
    List {
        #[arg(long, default_value = "active")]
        state: String,
    },
    /// Show envelope of a queued message
    Show { id: String },
    /// Flush all deferred messages (move back to active)
    Flush,
    /// Delete a message from the queue
    Delete { id: String },
    /// Hold a message
    Hold { id: String },
    /// Release a held message
    Release { id: String },
}

pub async fn run(args: QueueArgs, config: &Config) -> anyhow::Result<()> {
    let queue = Queue::new(config.storage.queue_dir.clone()).await?;

    match args.command {
        QueueCmd::List { state } => {
            let st = parse_state(&state);
            let ids = queue.list(st).await?;
            if ids.is_empty() {
                println!("Queue {} is empty.", state);
            }
            for id in &ids {
                println!("{}", id);
            }
            println!("{} message(s)", ids.len());
        }

        QueueCmd::Show { id } => {
            // Try all states
            for st in [QueueState::Active, QueueState::Deferred, QueueState::Hold, QueueState::Incoming] {
                if let Ok(msg) = queue.load(st, &id).await {
                    let env = &msg.envelope;
                    println!("ID:         {}", env.id);
                    println!("From:       {}", env.from);
                    println!("Received:   {}", env.received_at);
                    println!("Client IP:  {}", env.client_ip);
                    println!("HELO:       {}", env.client_helo);
                    println!("Retries:    {}", env.retry_count);
                    println!("Recipients:");
                    for r in &env.recipients {
                        println!("  {} - {:?}", r.address, r.status);
                    }
                    return Ok(());
                }
            }
            println!("Message not found: {}", id);
        }

        QueueCmd::Flush => {
            let ids = queue.list(QueueState::Deferred).await?;
            let n = ids.len();
            for id in &ids {
                queue.transition(id, QueueState::Deferred, QueueState::Active).await?;
            }
            println!("Flushed {} message(s).", n);
        }

        QueueCmd::Delete { id } => {
            for st in [QueueState::Active, QueueState::Deferred, QueueState::Hold] {
                if queue.remove(st, &id).await.is_ok() {
                    println!("Deleted {}.", id);
                    return Ok(());
                }
            }
            println!("Message not found: {}", id);
        }

        QueueCmd::Hold { id } => {
            queue.transition(&id, QueueState::Active, QueueState::Hold).await?;
            println!("Held {}.", id);
        }

        QueueCmd::Release { id } => {
            queue.transition(&id, QueueState::Hold, QueueState::Active).await?;
            println!("Released {}.", id);
        }
    }
    Ok(())
}

fn parse_state(s: &str) -> QueueState {
    match s {
        "incoming" => QueueState::Incoming,
        "deferred" => QueueState::Deferred,
        "hold"     => QueueState::Hold,
        "bounce"   => QueueState::Bounce,
        "corrupt"  => QueueState::Corrupt,
        _          => QueueState::Active,
    }
}
