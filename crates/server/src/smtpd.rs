//! SMTP listener: accepts inbound connections on port 25 / 587 / 465.
//!
//! One Tokio task per accepted connection. A global semaphore caps concurrent sessions.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{error, info, warn, debug};
use rmail_config::Config;
use rmail_dns::Resolver;
use rmail_queue::Queue;
use rmail_mailbox::Maildir;
use rmail_smtp::{
    command::parse_command,
    reply::Reply,
    session::{SmtpSession, RcptCheck, StepResult},
};
use rmail_tls::TlsAcceptor;
use rmail_core::{Address, QueueState};

const MAX_SESSIONS: usize = 1024;

pub async fn listen(
    addr: SocketAddr,
    config: Arc<Config>,
    queue:   Arc<Queue>,
    mailbox: Arc<Maildir>,
    dns:     Arc<Resolver>,
    tls:     Arc<TlsAcceptor>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    let sem = Arc::new(Semaphore::new(MAX_SESSIONS));
    info!(%addr, "SMTP listener ready");

    loop {
        let (stream, peer) = listener.accept().await?;
        let permit = sem.clone().acquire_owned().await?;
        let config  = config.clone();
        let queue   = queue.clone();
        let mailbox = mailbox.clone();
        let dns     = dns.clone();
        let tls     = tls.clone();

        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_session(stream, peer, config, queue, mailbox, dns, tls).await {
                warn!(peer = %peer, "SMTP session error: {}", e);
            }
        });
    }
}

async fn handle_session(
    mut stream: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
    queue: Arc<Queue>,
    mailbox: Arc<Maildir>,
    dns: Arc<Resolver>,
    tls: Arc<TlsAcceptor>,
) -> anyhow::Result<()> {
    info!(peer = %peer, "SMTP connection");

    // Greeting
    let greeting = Reply::greeting(&config.server.hostname).to_string();
    stream.write_all(greeting.as_bytes()).await?;

    let max_bytes = config.max_message_bytes();
    let mut session = SmtpSession::new(&config.server.hostname, max_bytes, peer.ip());
    session.state = rmail_smtp::session::SessionState::Connected;

    // Line reader — plain TCP for now; STARTTLS handled inline
    let mut reader = BufReader::new(stream);
    let mut line   = String::new();
    let mut in_data = false;

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break; // client disconnected
        }

        // DATA body phase
        if in_data {
            if let Some(result) = session.feed_data(
                line.as_bytes(),
                &|addr| check_rcpt(addr, &config, &mailbox),
                &|u, p| verify_auth(u, p, &config),
            ) {
                match result {
                    StepResult::MessageComplete { envelope, body } => {
                        in_data = false;
                        let id = queue.enqueue(envelope, &body).await
                            .map_err(|e| anyhow::anyhow!(e))?;
                        let reply = Reply::ok(format!("2.0.0 OK queued as {}", id));
                        reader.get_mut().write_all(reply.to_string().as_bytes()).await?;
                        // Notify queue manager (fire-and-forget via channel — wired in main)
                    }
                    StepResult::Reply(r) => {
                        reader.get_mut().write_all(r.to_string().as_bytes()).await?;
                        in_data = false;
                    }
                    _ => {}
                }
            }
            continue;
        }

        // Command phase
        let cmd = match parse_command(&line) {
            Ok(c) => c,
            Err(_) => {
                reader.get_mut().write_all(Reply::syntax_error().to_string().as_bytes()).await?;
                continue;
            }
        };

        let result = session.step(
            cmd,
            &|addr| check_rcpt(addr, &config, &mailbox),
            &|u, p| verify_auth(u, p, &config),
        );

        match result {
            StepResult::Reply(r) => {
                reader.get_mut().write_all(r.to_string().as_bytes()).await?;
                if r.to_string().starts_with("354") {
                    in_data = true;
                }
            }
            StepResult::UpgradeTls(r) => {
                let stream = reader.into_inner();
                stream.write_all(r.to_string().as_bytes()).await?;
                // TLS upgrade
                match rmail_tls::upgrade(&tls, stream).await {
                    Ok(tls_stream) => {
                        session.tls_upgraded();
                        info!(peer = %peer, "STARTTLS upgrade complete");
                        // Continue session on TLS stream
                        // (simplified: real impl wraps into BufReader again)
                        return Ok(());
                    }
                    Err(e) => {
                        warn!(peer = %peer, "STARTTLS failed: {}", e);
                        return Ok(());
                    }
                }
            }
            StepResult::MessageComplete { .. } => {} // handled in data loop
            StepResult::Close(r) => {
                reader.get_mut().write_all(r.to_string().as_bytes()).await?;
                break;
            }
        }
    }

    info!(peer = %peer, "SMTP connection closed");
    Ok(())
}

// ─── Helpers ───────────────────────────────────────────────────────────────

fn check_rcpt(addr: &Address, config: &Config, mailbox: &Maildir) -> RcptCheck {
    if !config.is_local_domain(&addr.domain) {
        return RcptCheck::RelayDenied;
    }
    let full = format!("{}@{}", addr.local, addr.domain);
    if config.find_user(&full).is_none() {
        return RcptCheck::UserUnknown;
    }
    RcptCheck::LocalOk
}

fn verify_auth(username: &str, password: &str, config: &Config) -> Option<String> {
    let user = config.find_user(username)?;
    if rmail_auth::password::verify_password(password, &user.password_hash) {
        Some(user.address.clone())
    } else {
        None
    }
}
