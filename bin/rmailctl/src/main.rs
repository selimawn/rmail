//! rmailctl — admin CLI for rmail.
//!
//! Domain and user management edits rmail.toml directly and generates DKIM
//! keys. Queue inspection operates on the queue directories — no Unix socket
//! needed.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::{Parser, Subcommand};
use rmail_config::Config;
use std::path::{Path, PathBuf};

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
    /// Manage DKIM keys
    #[command(subcommand)]
    Dkim(DkimCmd),
    /// Manage users
    #[command(subcommand)]
    User(UserCmd),
    /// Inspect the mail queue
    #[command(subcommand)]
    Queue(QueueCmd),
    /// Print storage configuration snippets
    #[command(subcommand)]
    Storage(StorageCmd),
    /// Print server status
    Status,
}

#[derive(Debug, Subcommand)]
enum DomainCmd {
    /// List all hosted domains
    List,
    /// Add a domain: writes config, generates the DKIM key, prints DNS records
    Add {
        name: String,
        /// DKIM selector
        #[arg(long, default_value = "rmail")]
        selector: String,
    },
    /// Print DNS records for a domain
    Dns {
        name: String,
        /// Export format: cloudflare | bind
        #[arg(long)]
        export: Option<String>,
    },
    /// Remove a domain from the config file
    Remove { name: String },
}

#[derive(Debug, Subcommand)]
enum DkimCmd {
    /// Generate (or rotate) the DKIM key for a configured domain
    Generate { name: String },
}

#[derive(Debug, Subcommand)]
enum UserCmd {
    /// List all users
    List,
    /// Add a user: prompts for password, writes config, creates the Maildir
    Add { address: String },
    /// Change a user's password (updates the config file)
    Passwd { address: String },
    /// Remove a user from the config file (Maildir is kept)
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

#[derive(Debug, Subcommand)]
enum StorageCmd {
    /// Print a TOML snippet for S3-compatible object storage
    S3(S3Args),
    /// Test the configured S3-compatible object store
    S3Test,
}

#[derive(Debug, Parser)]
struct S3Args {
    #[arg(long)]
    endpoint: String,
    #[arg(long)]
    region: String,
    #[arg(long)]
    bucket: String,
    #[arg(long)]
    access_key_id: String,
    #[arg(long)]
    secret_access_key: String,
    #[arg(long, default_value_t = false)]
    path_style: bool,
    #[arg(long, default_value = "")]
    prefix: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter("warn").init();
    let cli = Cli::parse();
    if let Cmd::Storage(StorageCmd::S3(args)) = cli.command {
        print_s3_snippet(args);
        return Ok(());
    }
    let config = Config::load(&cli.config)
        .with_context(|| format!("failed to load config: {}", cli.config.display()))?;

    match cli.command {
        Cmd::Domain(sub) => handle_domain(sub, &config, &cli.config).await?,
        Cmd::Dkim(sub) => handle_dkim(sub, &config).await?,
        Cmd::User(sub) => handle_user(sub, &config, &cli.config).await?,
        Cmd::Queue(sub) => handle_queue(sub, &config).await?,
        Cmd::Storage(sub) => handle_storage(sub, &config).await?,
        Cmd::Status => handle_status(&config),
    }
    Ok(())
}

// ─── domain ────────────────────────────────────────────────────────────────

async fn handle_domain(cmd: DomainCmd, config: &Config, config_path: &Path) -> Result<()> {
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
        DomainCmd::Add { name, selector } => {
            if config.find_domain(&name).is_some() {
                println!("Domain {} is already configured.", name);
                return Ok(());
            }
            rmail_core::Address::parse(&format!("postmaster@{}", name))
                .with_context(|| format!("invalid domain name: {}", name))?;

            let dkim_key = format!("/etc/rmail/dkim/{}.key", name);
            let pubkey = generate_dkim_key(Path::new(&dkim_key))?;

            let block = format!(
                "[[domain]]\nname          = \"{}\"\ndkim_selector = \"{}\"\ndkim_key      = \"{}\"\n",
                name, selector, dkim_key
            );
            append_block(config_path, &block)?;
            println!("Domain {} added to {}.", name, config_path.display());
            println!();
            print_dns_records(&name, "<YOUR_SERVER_IP>", &selector, &pubkey);
        }
        DomainCmd::Dns { name, export } => {
            let domain = config
                .find_domain(&name)
                .context(format!("domain {} not found in config", name))?;
            let server_ip = "<YOUR_SERVER_IP>";
            let pubkey = read_dkim_public_key(&domain.dkim_key)
                .unwrap_or_else(|_| "<YOUR_DKIM_PUBLIC_KEY>".to_owned());
            match export.as_deref() {
                Some("cloudflare") => {
                    print_cloudflare_json(&name, server_ip, &domain.dkim_selector, &pubkey)
                }
                Some("bind") => print_bind_zone(&name, server_ip, &domain.dkim_selector, &pubkey),
                _ => print_dns_records(&name, server_ip, &domain.dkim_selector, &pubkey),
            }
        }
        DomainCmd::Remove { name } => {
            if config.find_domain(&name).is_none() {
                println!("Domain {} is not configured.", name);
                return Ok(());
            }
            remove_block(config_path, "[[domain]]", &format!("\"{}\"", name))?;
            println!("Domain {} removed from {}.", name, config_path.display());
            println!("(Mailboxes and DKIM key were kept on disk.)");
        }
    }
    Ok(())
}

// ─── dkim ──────────────────────────────────────────────────────────────────

async fn handle_dkim(cmd: DkimCmd, config: &Config) -> Result<()> {
    match cmd {
        DkimCmd::Generate { name } => {
            let domain = config
                .find_domain(&name)
                .context(format!("domain {} not found in config", name))?;
            let pubkey = generate_dkim_key(&domain.dkim_key)?;
            println!("DKIM key written to {}", domain.dkim_key.display());
            println!();
            println!(
                "  TXT  {}._domainkey.{}  \"v=DKIM1; k=rsa; p={}\"",
                domain.dkim_selector, name, pubkey
            );
        }
    }
    Ok(())
}

/// Generate a 2048-bit RSA key in PKCS#8 PEM, write it with 0600 permissions,
/// return the base64 public key for the DNS record.
fn generate_dkim_key(path: &Path) -> Result<String> {
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};

    let mut rng = rand::thread_rng();
    let private = rsa::RsaPrivateKey::new(&mut rng, 2048).context("RSA key generation")?;
    let pem = private
        .to_pkcs8_pem(LineEnding::LF)
        .context("PEM encoding")?;
    let public_der = rsa::RsaPublicKey::from(&private)
        .to_public_key_der()
        .context("public key DER encoding")?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, pem.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(B64.encode(public_der.as_bytes()))
}

fn read_dkim_public_key(path: &Path) -> Result<String> {
    use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};

    let pem = std::fs::read_to_string(path)?;
    let private = rsa::RsaPrivateKey::from_pkcs8_pem(&pem).context("not a PKCS#8 RSA key")?;
    let public_der = rsa::RsaPublicKey::from(&private)
        .to_public_key_der()
        .context("public key DER encoding")?;
    Ok(B64.encode(public_der.as_bytes()))
}

fn print_dns_records(domain: &str, ip: &str, selector: &str, dkim_pubkey: &str) {
    println!("DNS records required for {}:", domain);
    println!();
    println!("  A       mail.{domain}              {ip}");
    println!("  MX      {domain}                   10 mail.{domain}.");
    println!("  TXT     {domain}                   v=spf1 mx -all");
    println!("  TXT     {selector}._domainkey.{domain}  v=DKIM1; k=rsa; p={dkim_pubkey}");
    println!(
        "  TXT     _dmarc.{domain}            v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}"
    );
    println!("  TXT     _mta-sts.{domain}          v=STSv1; id=20260426");
    println!("  TXT     _smtp._tls.{domain}        v=TLSRPTv1; rua=mailto:tlsrpt@{domain}");
    println!();
    println!("  PTR     {ip}  mail.{domain}  (set at your hosting provider)");
}

fn print_cloudflare_json(domain: &str, ip: &str, selector: &str, dkim_pubkey: &str) {
    // Cloudflare bulk import format (POST /zones/:id/dns_records)
    let records = serde_json::json!([
        { "type": "A",   "name": format!("mail.{}", domain), "content": ip, "ttl": 3600, "proxied": false },
        { "type": "MX",  "name": domain, "content": format!("mail.{}", domain), "priority": 10, "ttl": 3600 },
        { "type": "TXT", "name": domain, "content": "v=spf1 mx -all", "ttl": 3600 },
        { "type": "TXT", "name": format!("{}._domainkey.{}", selector, domain), "content": format!("v=DKIM1; k=rsa; p={}", dkim_pubkey), "ttl": 3600 },
        { "type": "TXT", "name": format!("_dmarc.{}", domain), "content": format!("v=DMARC1; p=quarantine; rua=mailto:dmarc@{}", domain), "ttl": 3600 },
        { "type": "TXT", "name": format!("_mta-sts.{}", domain), "content": "v=STSv1; id=20260426", "ttl": 3600 },
        { "type": "TXT", "name": format!("_smtp._tls.{}", domain), "content": format!("v=TLSRPTv1; rua=mailto:tlsrpt@{}", domain), "ttl": 3600 },
    ]);
    println!("{}", serde_json::to_string_pretty(&records).unwrap());
}

fn print_bind_zone(domain: &str, ip: &str, selector: &str, dkim_pubkey: &str) {
    println!("$ORIGIN {}.", domain);
    println!("mail      3600  IN  A     {}", ip);
    println!("@         3600  IN  MX    10 mail.{}.", domain);
    println!("@         3600  IN  TXT   \"v=spf1 mx -all\"");
    println!("{selector}._domainkey  3600  IN  TXT  \"v=DKIM1; k=rsa; p={dkim_pubkey}\"");
    println!(
        "_dmarc    3600  IN  TXT   \"v=DMARC1; p=quarantine; rua=mailto:dmarc@{}\"",
        domain
    );
    println!("_mta-sts  3600  IN  TXT   \"v=STSv1; id=20260426\"");
    println!(
        "_smtp._tls 3600 IN  TXT   \"v=TLSRPTv1; rua=mailto:tlsrpt@{}\"",
        domain
    );
}

// ─── user ─────────────────────────────────────────────────────────────────

async fn handle_user(cmd: UserCmd, config: &Config, config_path: &Path) -> Result<()> {
    match cmd {
        UserCmd::List => {
            if config.users.is_empty() {
                println!("No users configured.");
            } else {
                for u in &config.users {
                    println!("{}", u.address);
                }
            }
        }
        UserCmd::Add { address } => {
            let addr = rmail_core::Address::parse(&address)
                .with_context(|| format!("invalid user address: {}", address))?;
            if !config.is_local_domain(&addr.domain) {
                anyhow::bail!(
                    "domain {} is not configured — run `rmailctl domain add {}` first",
                    addr.domain,
                    addr.domain
                );
            }
            if config.find_user(&address).is_some() {
                println!("User {} is already configured.", address);
                return Ok(());
            }
            let password = prompt_password("New password: ")?;
            let hash = rmail_auth::password::hash(&password)?;
            rmail_mailbox::Maildir::from_storage_config(&config.storage)?
                .create_user(&addr)
                .await?;
            let block = format!(
                "[[user]]\naddress       = \"{}\"\npassword_hash = \"{}\"\n",
                address, hash
            );
            append_block(config_path, &block)?;
            println!("User {} added to {}.", address, config_path.display());
        }
        UserCmd::Passwd { address } => {
            config
                .find_user(&address)
                .context(format!("user {} not found", address))?;
            let password = prompt_password("New password: ")?;
            let hash = rmail_auth::password::hash(&password)?;
            update_block_value(
                config_path,
                "[[user]]",
                &format!("\"{}\"", address),
                "password_hash",
                &hash,
            )?;
            println!("Password updated for {}.", address);
        }
        UserCmd::Remove { address } => {
            if config.find_user(&address).is_none() {
                println!("User {} is not configured.", address);
                return Ok(());
            }
            remove_block(config_path, "[[user]]", &format!("\"{}\"", address))?;
            println!("User {} removed from {}.", address, config_path.display());
            println!("(Maildir was kept on disk.)");
        }
    }
    Ok(())
}

// ─── config file editing ────────────────────────────────────────────────────

/// Append a TOML block at the end of the config file.
fn append_block(path: &Path, block: &str) -> Result<()> {
    let mut content = std::fs::read_to_string(path)?;
    if !content.ends_with('\n') {
        content.push('\n');
    }
    content.push('\n');
    content.push_str(block);
    std::fs::write(path, content)?;
    Ok(())
}

/// Remove a `[[section]]` block whose body contains `marker`.
fn remove_block(path: &Path, header: &str, marker: &str) -> Result<()> {
    let content = std::fs::read_to_string(path)?;
    let lines: Vec<&str> = content.lines().collect();
    let mut out: Vec<&str> = Vec::with_capacity(lines.len());
    let mut i = 0;
    let mut removed = false;
    while i < lines.len() {
        if lines[i].trim() == header {
            // Collect the whole section (up to the next header or EOF).
            let start = i;
            let mut end = i + 1;
            while end < lines.len() && !lines[end].trim_start().starts_with('[') {
                end += 1;
            }
            if lines[start..end].iter().any(|l| l.contains(marker)) {
                removed = true;
                i = end;
                continue;
            }
        }
        out.push(lines[i]);
        i += 1;
    }
    if !removed {
        anyhow::bail!("no {} block containing {} found", header, marker);
    }
    std::fs::write(path, out.join("\n") + "\n")?;
    Ok(())
}

/// Replace the value of `key` inside the `[[section]]` block containing `marker`.
fn update_block_value(
    path: &Path,
    header: &str,
    marker: &str,
    key: &str,
    new_value: &str,
) -> Result<()> {
    let content = std::fs::read_to_string(path)?;
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == header {
            let mut end = i + 1;
            while end < lines.len() && !lines[end].trim_start().starts_with('[') {
                end += 1;
            }
            if lines[i..end].iter().any(|l| l.contains(marker)) {
                for j in (i + 1)..end {
                    let trimmed = lines[j].trim_start();
                    if trimmed.starts_with(key) && trimmed.contains('=') {
                        let mut new_lines: Vec<String> =
                            lines.iter().map(|s| (*s).to_owned()).collect();
                        new_lines[j] = format!("{} = \"{}\"", key, new_value);
                        std::fs::write(path, new_lines.join("\n") + "\n")?;
                        return Ok(());
                    }
                }
                anyhow::bail!("key {} not found in the {} block", key, header);
            }
            i = end;
        } else {
            i += 1;
        }
    }
    anyhow::bail!("no {} block containing {} found", header, marker)
}

// ─── queue ────────────────────────────────────────────────────────────────

const ALL_STATES: [rmail_core::QueueState; 5] = [
    rmail_core::QueueState::Active,
    rmail_core::QueueState::Deferred,
    rmail_core::QueueState::Hold,
    rmail_core::QueueState::Incoming,
    rmail_core::QueueState::Corrupt,
];

async fn find_message(queue: &rmail_queue::Queue, id: &str) -> Option<rmail_core::QueueState> {
    for state in ALL_STATES {
        if queue.load(state, id).await.is_ok() {
            return Some(state);
        }
    }
    None
}

async fn handle_queue(cmd: QueueCmd, config: &Config) -> Result<()> {
    let queue = rmail_queue::Queue::from_storage_config(&config.storage).await?;
    match cmd {
        QueueCmd::List { state } => {
            let qstate = parse_queue_state(&state)?;
            let ids = queue.list(qstate).await?;
            if ids.is_empty() {
                println!("Queue {} is empty.", state);
            } else {
                println!("{} message(s) in {}:", ids.len(), state);
                for id in ids {
                    println!("  {}", id);
                }
            }
        }
        QueueCmd::Show { id } => match find_message(&queue, &id).await {
            Some(state) => {
                let msg = queue.load(state, &id).await?;
                let env = &msg.envelope;
                println!("ID:        {}", env.id);
                println!("State:     {}", state.dir_name());
                println!("From:      {}", env.from);
                println!(
                    "To:        {}",
                    env.recipients
                        .iter()
                        .map(|r| r.address.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                println!("Received:  {}", env.received_at);
                println!("Client:    {} ({})", env.client_helo, env.client_ip);
                println!("Retries:   {}", env.retry_count);
                println!("Quarantine: {}", env.quarantine);
                println!("Recipients:");
                for recipient in &env.recipients {
                    println!("  {}  {:?}", recipient.address, recipient.status);
                }
                println!("Size:      {} bytes", msg.size);
            }
            None => println!("Message {} not found in any queue.", id),
        },
        QueueCmd::Flush => {
            let ids = queue.list(rmail_core::QueueState::Deferred).await?;
            let n = ids.len();
            for id in ids {
                queue
                    .transition(
                        &id,
                        rmail_core::QueueState::Deferred,
                        rmail_core::QueueState::Active,
                    )
                    .await?;
            }
            println!("Flushed {} message(s) from deferred to active.", n);
        }
        QueueCmd::Delete { id } => match find_message(&queue, &id).await {
            Some(state) => {
                queue.remove(state, &id).await?;
                println!("Deleted {}", id);
            }
            None => println!("Message {} not found.", id),
        },
        QueueCmd::Hold { id } => match find_message(&queue, &id).await {
            Some(rmail_core::QueueState::Hold) => println!("Message {} is already on hold.", id),
            Some(state) => {
                queue
                    .transition(&id, state, rmail_core::QueueState::Hold)
                    .await?;
                println!("Message {} put on hold.", id);
            }
            None => println!("Message {} not found.", id),
        },
        QueueCmd::Release { id } => {
            queue
                .transition(
                    &id,
                    rmail_core::QueueState::Hold,
                    rmail_core::QueueState::Active,
                )
                .await?;
            println!("Message {} released.", id);
        }
    }
    Ok(())
}

async fn handle_storage(cmd: StorageCmd, config: &Config) -> Result<()> {
    match cmd {
        StorageCmd::S3(args) => print_s3_snippet(args),
        StorageCmd::S3Test => {
            let s3 = config
                .storage
                .s3
                .as_ref()
                .context("storage.s3 is not configured")?;
            let store = rmail_storage::S3Store::new(s3);
            store.healthcheck().await?;
            println!("S3 storage healthcheck ok.");
        }
    }
    Ok(())
}

fn print_s3_snippet(args: S3Args) {
    println!("Add or update the following in rmail.toml:\n");
    println!("[storage]");
    println!("backend = \"s3\"");
    println!();
    println!("[storage.s3]");
    println!("endpoint = \"{}\"", args.endpoint);
    println!("region = \"{}\"", args.region);
    println!("bucket = \"{}\"", args.bucket);
    println!("access_key_id = \"{}\"", args.access_key_id);
    println!("secret_access_key = \"{}\"", args.secret_access_key);
    println!("path_style = {}", args.path_style);
    println!("prefix = \"{}\"", args.prefix);
    println!();
    println!("Use `rmailctl storage s3-test` to verify credentials.");
}

// ─── status ────────────────────────────────────────────────────────────────

fn handle_status(config: &Config) {
    println!("hostname:   {}", config.server.hostname);
    println!(
        "smtp:       {}",
        config
            .server
            .listen_smtp
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "imap:       {}",
        config
            .server
            .listen_imap
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "domains:    {}",
        config
            .domains
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!("users:      {}", config.users.len());
    println!("queue dir:  {}", config.storage.queue_dir.display());
    println!("mailbox dir:{}", config.storage.mailbox_dir.display());
}

// ─── helpers ────────────────────────────────────────────────────────────────

fn parse_queue_state(s: &str) -> Result<rmail_core::QueueState> {
    match s {
        "incoming" => Ok(rmail_core::QueueState::Incoming),
        "active" => Ok(rmail_core::QueueState::Active),
        "deferred" => Ok(rmail_core::QueueState::Deferred),
        "hold" => Ok(rmail_core::QueueState::Hold),
        "bounce" => Ok(rmail_core::QueueState::Bounce),
        "corrupt" => Ok(rmail_core::QueueState::Corrupt),
        _ => anyhow::bail!("unknown queue state: {}", s),
    }
}

fn prompt_password(prompt: &str) -> Result<String> {
    Ok(rpassword::prompt_password(prompt)?)
}
