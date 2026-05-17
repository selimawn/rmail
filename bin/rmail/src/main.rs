//! rmail daemon — entry point.
//!
//! Starts all listeners (SMTP + IMAP) and the queue manager.
//! All components share Arc references to config, queue, maildir, and resolver.

use anyhow::{Context, Result};
use clap::Parser;
use rmail_config::Config;
use rmail_dns::Resolver;
use rmail_mailbox::Maildir;
use rmail_queue::Queue;
use rmail_tls::TlsAcceptor;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

#[derive(Debug, Parser)]
#[command(name = "rmail", about = "rmail SMTP/IMAP server")]
struct Cli {
    #[arg(short, long, default_value = "/etc/rmail/rmail.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "rmail=info,rmail_server=info,rmail_smtp=info,rmail_imap=info".into()
            }),
        )
        .init();

    let cli = Cli::parse();

    // Load config
    let config = Config::load(&cli.config)
        .with_context(|| format!("failed to load config from {}", cli.config.display()))?;
    let config = Arc::new(config);
    info!(hostname = %config.server.hostname, "rmail starting");

    // Shared state
    let queue = Arc::new(
        Queue::from_storage_config(&config.storage)
            .await
            .context("failed to initialise queue")?,
    );
    queue.recover().await.context("failed to recover queue")?;
    let maildir = Arc::new(
        Maildir::from_storage_config(&config.storage).context("failed to initialise mailbox")?,
    );
    let resolver = Arc::new(Resolver::new(config.dns.dnssec));
    let tls = Arc::new(
        TlsAcceptor::from_pem(&config.tls.cert, &config.tls.key)
            .context("failed to load TLS certificate")?,
    );

    info!("shared state initialised");

    // Spawn all tasks
    let smtp_task = {
        let (config, queue, tls) = (Arc::clone(&config), Arc::clone(&queue), Arc::clone(&tls));
        tokio::spawn(async move {
            rmail_server::smtp_listener::run(config.server.listen_smtp.clone(), config, queue, tls)
                .await
        })
    };

    let imap_task = {
        let (config, maildir, tls) = (Arc::clone(&config), Arc::clone(&maildir), Arc::clone(&tls));
        tokio::spawn(async move {
            rmail_server::imap_listener::run(
                config.server.listen_imap.clone(),
                config,
                maildir,
                tls,
            )
            .await
        })
    };

    let qmgr_task = {
        let (config, queue, maildir, resolver) = (
            Arc::clone(&config),
            Arc::clone(&queue),
            Arc::clone(&maildir),
            Arc::clone(&resolver),
        );
        tokio::spawn(async move {
            rmail_server::queue_manager::run(config, queue, maildir, resolver).await
        })
    };

    info!("all listeners started");

    // Wait for first task to finish or for an operator shutdown signal.
    tokio::select! {
        r = smtp_task => { r?.context("SMTP listener exited")?; }
        r = imap_task => { r?.context("IMAP listener exited")?; }
        r = qmgr_task => { r.context("queue manager panicked")?; }
        r = tokio::signal::ctrl_c() => {
            r.context("failed to listen for shutdown signal")?;
            info!("shutdown signal received");
        }
    }

    Ok(())
}
