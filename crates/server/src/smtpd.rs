//! SMTP session handler — one Tokio task per accepted connection.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use rmail_config::Config;
use rmail_dns::Resolver;
use rmail_queue::Queue;
use rmail_mailbox::Maildir;
use rmail_smtp::{
    command,           // FIX: was `command::parse_command` (non-existent)
    reply::Reply,
    session::{SmtpSession, RcptCheck, StepResult, SessionState},
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
        let permit  = sem.clone().acquire_owned().await?;
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
    stream: TcpStream,
    peer: SocketAddr,
    config: Arc<Config>,
    queue: Arc<Queue>,
    mailbox: Arc<Maildir>,
    dns: Arc<Resolver>,
    tls: Arc<TlsAcceptor>,
) -> anyhow::Result<()> {
    info!(peer = %peer, "SMTP connection");

    let greeting = Reply::greeting(&config.server.hostname).to_string();
    stream.write_all(greeting.as_bytes()).await?;

    let max_bytes = config.max_message_bytes();
    let mut session = SmtpSession::new(&config.server.hostname, max_bytes, peer.ip());
    session.state = SessionState::Connected;

    let mut reader = BufReader::new(stream);

    // FIX: after STARTTLS, continue session loop on TLS stream
    if let Some(tls_stream) = run_command_loop(
        &mut reader, &mut session, peer, &config, &queue, &mailbox,
    ).await? {
        // TLS upgrade requested — perform handshake
        let plain = reader.into_inner();
        match tls.accept(plain).await {  // FIX: was rmail_tls::upgrade() (non-existent)
            Ok(tls_stream) => {
                session.tls_upgraded();
                info!(peer = %peer, "STARTTLS upgrade complete");
                let mut tls_reader = BufReader::new(tls_stream);
                run_command_loop(&mut tls_reader, &mut session, peer, &config, &queue, &mailbox).await?;
            }
            Err(e) => warn!(peer = %peer, "STARTTLS failed: {}", e),
        }
    }

    info!(peer = %peer, "SMTP connection closed");
    Ok(())
}

/// Returns `Some(stream)` if a STARTTLS upgrade is needed, `None` when done.
async fn run_command_loop<S>(
    reader: &mut BufReader<S>,
    session: &mut SmtpSession,
    peer: SocketAddr,
    config: &Arc<Config>,
    queue: &Arc<Queue>,
    mailbox: &Arc<Maildir>,
) -> anyhow::Result<Option<()>>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    let mut in_data = false;
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 { return Ok(None); }

        if in_data {
            if let Some(result) = session.feed_data(
                line.as_bytes(),
                &|addr| check_rcpt(addr, config, mailbox),
                &|u, p| verify_auth(u, p, config),
            ) {
                match result {
                    StepResult::MessageComplete { envelope, body } => {
                        in_data = false;
                        let id = queue.enqueue(envelope, &body).await
                            .map_err(|e| anyhow::anyhow!("{}", e))?;
                        let reply = Reply::ok(format!("2.0.0 OK queued as {}", id));
                        reader.get_mut().write_all(reply.to_string().as_bytes()).await?;
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

        // FIX: was `parse_command` — function is `parse` in command.rs
        let cmd = match command::parse(&line) {
            Ok(c)  => c,
            Err(_) => {
                reader.get_mut().write_all(Reply::syntax_error().to_string().as_bytes()).await?;
                continue;
            }
        };

        let result = session.step(
            cmd,
            &|addr| check_rcpt(addr, config, mailbox),
            &|u, p| verify_auth(u, p, config),
        );

        match result {
            StepResult::Reply(r) => {
                let s = r.to_string();
                let starts_data = s.starts_with("354");
                reader.get_mut().write_all(s.as_bytes()).await?;
                if starts_data { in_data = true; }
            }
            StepResult::UpgradeTls(r) => {
                reader.get_mut().write_all(r.to_string().as_bytes()).await?;
                // Signal to caller that TLS upgrade is needed
                return Ok(Some(()));
            }
            StepResult::MessageComplete { .. } => {}
            StepResult::Close(r) => {
                reader.get_mut().write_all(r.to_string().as_bytes()).await?;
                return Ok(None);
            }
        }
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

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
    // FIX: was verify_password — function is `verify` in auth/password.rs
    if rmail_auth::password::verify(password, &user.password_hash) {
        Some(user.address.clone())
    } else {
        None
    }
}
