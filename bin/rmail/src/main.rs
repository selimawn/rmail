//! rmail daemon entry point.
//!
//! 1. Parse CLI args / load config.
//! 2. Build shared services (DNS, TLS, Queue, Maildir).
//! 3. Spawn SMTP listener tasks.
//! 4. Spawn IMAP listener tasks.
//! 5. Spawn queue manager.
//! 6. Block until SIGTERM / SIGINT.

use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;
use clap::Parser;

#[derive(Parser)]
#[command(name = "rmail", about = "rmail mail engine daemon")]
struct Args {
    #[arg(short, long, default_value = "/etc/rmail/rmail.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rmail=info,rmail_server=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();

    // ─── Config
    let config = Arc::new(rmail_config::Config::load(&args.config)?);
    info!(hostname = %config.server.hostname, "rmail starting");

    // ─── DNS (Cloudflare-only)
    let dns = Arc::new(rmail_dns::Resolver::new(config.dns.dnssec));

    // ─── TLS
    let tls = Arc::new(rmail_tls::build_acceptor(&config.tls.cert, &config.tls.key)?);

    // ─── Queue
    let queue = Arc::new(
        rmail_queue::Queue::new(config.storage.queue_dir.clone()).await?
    );

    // ─── Maildir
    let mailbox = Arc::new(rmail_mailbox::Maildir::new(config.storage.mailbox_dir.clone()));

    // ─── Queue manager channel
    let (qm_tx, qm_rx) = mpsc::channel::<String>(4096);

    // ─── Queue manager task
    {
        let config  = config.clone();
        let queue   = queue.clone();
        let mailbox = mailbox.clone();
        let dns     = dns.clone();
        tokio::spawn(async move {
            rmail_server::queue_manager::run(config, queue, mailbox, dns, qm_rx).await;
        });
    }

    // ─── SMTP listeners
    for addr in &config.server.listen_smtp {
        let addr    = *addr;
        let config  = config.clone();
        let queue   = queue.clone();
        let mailbox = mailbox.clone();
        let dns     = dns.clone();
        let tls     = tls.clone();
        tokio::spawn(async move {
            if let Err(e) = rmail_server::smtpd::listen(addr, config, queue, mailbox, dns, tls).await {
                tracing::error!("SMTP listener {addr} failed: {e}");
            }
        });
    }

    info!("All listeners started. Press Ctrl+C to stop.");

    // Wait for Ctrl+C / SIGTERM
    tokio::signal::ctrl_c().await?;
    info!("Shutting down.");
    Ok(())
}
