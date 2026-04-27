//! rmailctl — admin CLI for rmail.
//!
//! All subcommands read the same config file as the daemon.
//! They operate directly on the filesystem (queue dirs, mailbox dirs)
//! — no Unix socket needed for the initial release.

use std::path::PathBuf;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rmail_config::Config;

#[derive(Debug, Parser)]
#[command(name = "rmailctl", about = "rmail admin CLI")]
struct Cli {
    #[arg(short, long, default_value = "/etc/rmail/rmail.toml")]
    config: PathBuf,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Manage hosted domains
    #[command(subcommand)]
    Domain(DomainCmd),
    /// Manage users
    #[command(subcommand)]
    User(UserCmd),
    /// Inspect the mail queue
    #[command(subcommand)]
    Queue(QueueCmd),
    /// Print server status
    Status,
}

#[derive(Debug, Subcommand)]
enum DomainCmd {
    /// List all hosted domains
    List,
    /// Add a domain and show required DNS records
    Add { name: String },
    /// Print DNS records for a domain
    Dns {
        name: String,
        /// Export format: cloudflare | bind
        #[arg(long)]
        export: Option<String>,
    },
    /// Remove a domain from config
    Remove { name: String },
}

#[derive(Debug, Subcommand)]
enum UserCmd {
    /// List all users
    List,
    /// Add a user (prompts for password)
    Add { address: String },
    /// Change a user's password
    Passwd { address: String },
    /// Remove a user
    Remove { address: String },
}

#[derive(Debug, Subcommand)]
enum QueueCmd {
    /// List queued messages
    List {
        #[arg(long, default_value = "active")]
        state: String,
    },
    /// Show details of a queued message
    Show { id: String },
    /// Flush the deferred queue (move all deferred → active)
    Flush,
    /// Delete a queued message
    Delete { id: String },
    /// Hold a message (pause delivery)
    Hold { id: String },
    /// Release a held message
    Release { id: String },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("warn").init();
    let cli = Cli::parse();
    let config = Config::load(&cli.config)
        .with_context(|| format!("failed to load config: {}", cli.config.display()))?;

    match cli.command {
        Cmd::Domain(sub) => handle_domain(sub, &config).await?,
        Cmd::User(sub)   => handle_user(sub, &config).await?,
        Cmd::Queue(sub)  => handle_queue(sub, &config).await?,
        Cmd::Status      => handle_status(&config),
    }
    Ok(())
}

// ─── domain ────────────────────────────────────────────────────────────────

async fn handle_domain(cmd: DomainCmd, config: &Config) -> Result<()> {
    match cmd {
        DomainCmd::List => {
            if config.domains.is_empty() {
                println!("No domains configured.");
            } else {
                for d in &config.domains {
                    println!("{}", d.name);
                }
            }
        }
        DomainCmd::Add { name } => {
            if config.find_domain(&name).is_some() {
                println!("Domain {} is already configured.", name);
            } else {
                println!("Add the following to your rmail.toml:\n");
                println!("[[domain]]");
                println!("name          = \"{}\"", name);
                println!("dkim_selector = \"rmail\"");
                println!("dkim_key      = \"/etc/rmail/dkim/{}.key\"", name);
                println!();
                print_dns_records(&name, "<YOUR_SERVER_IP>", "rmail");
            }
        }
        DomainCmd::Dns { name, export } => {
            let domain = config.find_domain(&name)
                .context(format!("domain {} not found in config", name))?;
            let server_ip = "<YOUR_SERVER_IP>";
            match export.as_deref() {
                Some("cloudflare") => print_cloudflare_json(&name, server_ip, &domain.dkim_selector),
                Some("bind")       => print_bind_zone(&name, server_ip, &domain.dkim_selector),
                _                  => print_dns_records(&name, server_ip, &domain.dkim_selector),
            }
        }
        DomainCmd::Remove { name } => {
            println!("Remove the [[domain]] block for {} from rmail.toml manually.", name);
            println!("(Config file editing is not yet automated.)");
        }
    }
    Ok(())
}

fn print_dns_records(domain: &str, ip: &str, selector: &str) {
    println!("DNS records required for {}:", domain);
    println!();
    println!("  A       mail.{domain}              {ip}");
    println!("  MX      {domain}                   10 mail.{domain}.");
    println!("  TXT     {domain}                   v=spf1 mx -all");
    println!("  TXT     {selector}._domainkey.{domain}  v=DKIM1; k=rsa; p=<YOUR_DKIM_PUBLIC_KEY>");
    println!("  TXT     _dmarc.{domain}            v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}");
    println!("  TXT     _mta-sts.{domain}          v=STSv1; id=20260426");
    println!("  TXT     _smtp._tls.{domain}        v=TLSRPTv1; rua=mailto:tlsrpt@{domain}");
    println!();
    println!("  PTR     {ip}  mail.{domain}  (set at your hosting provider)");
}

fn print_cloudflare_json(domain: &str, ip: &str, selector: &str) {
    // Cloudflare bulk import format (POST /zones/:id/dns_records)
    let records = serde_json::json!([
        { "type": "A",   "name": format!("mail.{}", domain), "content": ip, "ttl": 3600, "proxied": false },
        { "type": "MX",  "name": domain, "content": format!("mail.{}", domain), "priority": 10, "ttl": 3600 },
        { "type": "TXT", "name": domain, "content": "v=spf1 mx -all", "ttl": 3600 },
        { "type": "TXT", "name": format!("{}._domainkey.{}", selector, domain), "content": "v=DKIM1; k=rsa; p=<YOUR_DKIM_PUBLIC_KEY>", "ttl": 3600 },
        { "type": "TXT", "name": format!("_dmarc.{}", domain), "content": format!("v=DMARC1; p=quarantine; rua=mailto:dmarc@{}", domain), "ttl": 3600 },
        { "type": "TXT", "name": format!("_mta-sts.{}", domain), "content": "v=STSv1; id=20260426", "ttl": 3600 },
        { "type": "TXT", "name": format!("_smtp._tls.{}", domain), "content": format!("v=TLSRPTv1; rua=mailto:tlsrpt@{}", domain), "ttl": 3600 },
    ]);
    println!("{}", serde_json::to_string_pretty(&records).unwrap());
}

fn print_bind_zone(domain: &str, ip: &str, selector: &str) {
    println!("$ORIGIN {}.", domain);
    println!("mail      3600  IN  A     {}", ip);
    println!("@         3600  IN  MX    10 mail.{}.", domain);
    println!("@         3600  IN  TXT   \"v=spf1 mx -all\"");
    println!("{selector}._domainkey  3600  IN  TXT  \"v=DKIM1; k=rsa; p=<YOUR_DKIM_PUBLIC_KEY>\"");
    println!("_dmarc    3600  IN  TXT   \"v=DMARC1; p=quarantine; rua=mailto:dmarc@{}\"", domain);
    println!("_mta-sts  3600  IN  TXT   \"v=STSv1; id=20260426\"");
    println!("_smtp._tls 3600 IN  TXT   \"v=TLSRPTv1; rua=mailto:tlsrpt@{}\"", domain);
}

// ─── user ─────────────────────────────────────────────────────────────────

async fn handle_user(cmd: UserCmd, config: &Config) -> Result<()> {
    match cmd {
        UserCmd::List => {
            if config.users.is_empty() {
                println!("No users configured.");
            } else {
                for u in &config.users { println!("{}", u.address); }
            }
        }
        UserCmd::Add { address } => {
            let password = prompt_password("New password: ")?;
            let hash = rmail_auth::password::hash(&password)?;
            println!("Add to rmail.toml:");
            println!();
            println!("[[user]]");
            println!("address       = \"{}\"", address);
            println!("password_hash = \"{}\"", hash);
        }
        UserCmd::Passwd { address } => {
            config.find_user(&address)
                .context(format!("user {} not found", address))?;
            let password = prompt_password("New password: ")?;
            let hash = rmail_auth::password::hash(&password)?;
            println!("Update password_hash for {} in rmail.toml:", address);
            println!("  password_hash = \"{}\"", hash);
        }
        UserCmd::Remove { address } => {
            println!("Remove the [[user]] block for {} from rmail.toml manually.", address);
        }
    }
    Ok(())
}

// ─── queue ────────────────────────────────────────────────────────────────

async fn handle_queue(cmd: QueueCmd, config: &Config) -> Result<()> {
    let queue = rmail_queue::Queue::new(config.storage.queue_dir.clone()).await?;
    match cmd {
        QueueCmd::List { state } => {
            let qstate = parse_queue_state(&state)?;
            let ids = queue.list(qstate).await?;
            if ids.is_empty() {
                println!("Queue {} is empty.", state);
            } else {
                println!("{} message(s) in {}:", ids.len(), state);
                for id in ids { println!("  {}", id); }
            }
        }
        QueueCmd::Show { id } => {
            // Try active first, then deferred
            for state in [rmail_core::QueueState::Active, rmail_core::QueueState::Deferred,
                          rmail_core::QueueState::Hold, rmail_core::QueueState::Incoming] {
                if let Ok(msg) = queue.load(state, &id).await {
                    let env = &msg.envelope;
                    println!("ID:       {}", env.id);
                    println!("From:     {}", env.from);
                    println!("To:       {}", env.recipients.iter().map(|r| r.address.to_string()).collect::<Vec<_>>().join(", "));
                    println!("Received: {}", env.received_at);
                    println!("Client:   {} ({})", env.client_helo, env.client_ip);
                    println!("Retries:  {}", env.retry_count);
                    println!("Size:     {} bytes", msg.size);
                    return Ok(());
                }
            }
            println!("Message {} not found in any queue.", id);
        }
        QueueCmd::Flush => {
            let ids = queue.list(rmail_core::QueueState::Deferred).await?;
            let n = ids.len();
            for id in ids {
                queue.transition(&id, rmail_core::QueueState::Deferred, rmail_core::QueueState::Active).await?;
            }
            println!("Flushed {} message(s) from deferred to active.", n);
        }
        QueueCmd::Delete { id } => {
            for state in [rmail_core::QueueState::Active, rmail_core::QueueState::Deferred,
                          rmail_core::QueueState::Hold, rmail_core::QueueState::Incoming] {
                if queue.load(state, &id).await.is_ok() {
                    queue.remove(state, &id).await?;
                    println!("Deleted {}", id);
                    return Ok(());
                }
            }
            println!("Message {} not found.", id);
        }
        QueueCmd::Hold { id } => {
            queue.transition(&id, rmail_core::QueueState::Active, rmail_core::QueueState::Hold).await?;
            println!("Message {} put on hold.", id);
        }
        QueueCmd::Release { id } => {
            queue.transition(&id, rmail_core::QueueState::Hold, rmail_core::QueueState::Active).await?;
            println!("Message {} released.", id);
        }
    }
    Ok(())
}

// ─── status ────────────────────────────────────────────────────────────────

fn handle_status(config: &Config) {
    println!("hostname:   {}", config.server.hostname);
    println!("smtp:       {}", config.server.listen_smtp.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "));
    println!("imap:       {}", config.server.listen_imap.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "));
    println!("domains:    {}", config.domains.iter().map(|d| d.name.as_str()).collect::<Vec<_>>().join(", "));
    println!("users:      {}", config.users.len());
    println!("queue dir:  {}", config.storage.queue_dir.display());
    println!("mailbox dir:{}", config.storage.mailbox_dir.display());
}

// ─── helpers ────────────────────────────────────────────────────────────────

fn parse_queue_state(s: &str) -> Result<rmail_core::QueueState> {
    match s {
        "incoming" => Ok(rmail_core::QueueState::Incoming),
        "active"   => Ok(rmail_core::QueueState::Active),
        "deferred" => Ok(rmail_core::QueueState::Deferred),
        "hold"     => Ok(rmail_core::QueueState::Hold),
        "bounce"   => Ok(rmail_core::QueueState::Bounce),
        "corrupt"  => Ok(rmail_core::QueueState::Corrupt),
        _ => anyhow::bail!("unknown queue state: {}", s),
    }
}

fn prompt_password(prompt: &str) -> Result<String> {
    use std::io::Write;
    print!("{}", prompt);
    std::io::stdout().flush()?;
    let mut pw = String::new();
    std::io::stdin().read_line(&mut pw)?;
    Ok(pw.trim().to_owned())
}
