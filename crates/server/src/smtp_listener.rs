//! Inbound SMTP listener.
//!
//! Binds the configured TCP ports, accepts connections, and drives the
//! `smtp::Session` state machine for each one.

use crate::connlimit::PerIpLimiter;
use anyhow::Result;
use rmail_auth::fcrdns::FcrdnsResult;
use rmail_config::Config;
use rmail_core::Envelope;
use rmail_dns::Resolver;
use rmail_queue::Queue;
use rmail_smtp::reply::Reply;
use rmail_smtp::session::{Action, Session};
use rmail_tls::TlsAcceptor;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tracing::{error, info, warn};

/// Maximum simultaneous inbound SMTP connections.
const MAX_CONNECTIONS: usize = 1024;
/// Maximum number of sessions simultaneously accumulating a DATA body in
/// memory. Bounds worst-case RAM usage to MAX_DATA_BODIES × max_message_mb.
const MAX_DATA_BODIES: usize = 32;
const MAX_SMTP_LINE: usize = 1000;
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const WRITE_TIMEOUT: Duration = Duration::from_secs(120);

pub async fn run(
    addrs: Vec<SocketAddr>,
    config: Arc<Config>,
    queue: Arc<Queue>,
    tls: Arc<TlsAcceptor>,
    resolver: Arc<Resolver>,
    notify: Arc<Notify>,
) -> Result<()> {
    let sem = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let data_sem = Arc::new(Semaphore::new(MAX_DATA_BODIES));
    let per_ip = PerIpLimiter::new();
    let mut tasks = Vec::new();

    for addr in addrs {
        let config = Arc::clone(&config);
        let queue = Arc::clone(&queue);
        let tls = Arc::clone(&tls);
        let resolver = Arc::clone(&resolver);
        let notify = Arc::clone(&notify);
        let sem = Arc::clone(&sem);
        let data_sem = Arc::clone(&data_sem);
        let per_ip = per_ip.clone();
        tasks.push(tokio::spawn(async move {
            accept_loop(addr, config, queue, tls, resolver, notify, sem, data_sem, per_ip).await
        }));
    }

    for t in tasks {
        t.await??;
    }
    Ok(())
}

struct Ctx {
    config: Arc<Config>,
    queue: Arc<Queue>,
    tls: Arc<TlsAcceptor>,
    resolver: Arc<Resolver>,
    notify: Arc<Notify>,
    data_sem: Arc<Semaphore>,
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    addr: SocketAddr,
    config: Arc<Config>,
    queue: Arc<Queue>,
    tls: Arc<TlsAcceptor>,
    resolver: Arc<Resolver>,
    notify: Arc<Notify>,
    sem: Arc<Semaphore>,
    data_sem: Arc<Semaphore>,
    per_ip: PerIpLimiter,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "SMTP listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let ctx = Ctx {
            config: Arc::clone(&config),
            queue: Arc::clone(&queue),
            tls: Arc::clone(&tls),
            resolver: Arc::clone(&resolver),
            notify: Arc::clone(&notify),
            data_sem: Arc::clone(&data_sem),
        };
        let per_ip = per_ip.clone();
        tokio::spawn(async move {
            let Some(_ip_permit) = per_ip
                .acquire(peer.ip(), ctx.config.rate_limit.smtp_connections_per_ip, permit)
                .await
            else {
                warn!(peer = %peer, "SMTP per-IP connection limit exceeded");
                return;
            };
            let result = if addr.port() == 465 {
                handle_implicit_tls(stream, peer.ip(), ctx).await
            } else {
                handle_plain(stream, peer.ip(), ctx).await
            };
            if let Err(e) = result {
                warn!(peer = %peer, "SMTP session error: {}", e);
            }
        });
    }
}

/// Bound concurrent DATA bodies: holds a semaphore permit while the session
/// is in the DATA state.
struct DataPermit {
    sem: Arc<Semaphore>,
    permit: Option<OwnedSemaphorePermit>,
}

impl DataPermit {
    fn new(sem: Arc<Semaphore>) -> Self {
        Self { sem, permit: None }
    }

    async fn sync(&mut self, session: &Session) {
        if session.in_data() {
            if self.permit.is_none() {
                self.permit = Arc::clone(&self.sem).acquire_owned().await.ok();
            }
        } else {
            self.permit = None;
        }
    }
}

async fn handle_plain(
    stream: tokio::net::TcpStream,
    peer_ip: IpAddr,
    ctx: Ctx,
) -> Result<()> {
    let (mut session, banner) = Session::new(peer_ip, &ctx.config);
    let mut io = BufReader::new(stream);
    write_all_timeout(&mut io, &banner).await?;
    let mut data_permit = DataPermit::new(Arc::clone(&ctx.data_sem));

    loop {
        let Some(line) = read_line_limited(&mut io, MAX_SMTP_LINE).await? else {
            break;
        };

        match session.step(&line, &ctx.config) {
            Action::Reply(bytes) => {
                if !bytes.is_empty() {
                    write_all_timeout(&mut io, &bytes).await?;
                }
            }
            Action::UpgradeTls(bytes) => {
                if !io.buffer().is_empty() {
                    write_all_timeout(
                        &mut io,
                        &Reply::new(554, "5.5.1 Pipelined data before STARTTLS").to_wire(),
                    )
                    .await?;
                    break;
                }
                write_all_timeout(&mut io, &bytes).await?;
                // Consume the underlying stream, upgrade to TLS, restart loop
                let tcp = io.into_inner();
                let tls_stream = ctx.tls.accept(tcp).await?;
                session.mark_tls_active();
                return handle_tls(tls_stream, session, ctx).await;
            }
            Action::Close(bytes) => {
                write_all_timeout(&mut io, &bytes).await?;
                break;
            }
            Action::Enqueue {
                envelope,
                body,
                reply,
            } => {
                data_permit.permit = None;
                if !process_enqueue(*envelope, body, reply, &ctx, &mut io).await? {
                    continue;
                }
            }
        }
        data_permit.sync(&session).await;
    }
    Ok(())
}

async fn handle_implicit_tls(
    stream: tokio::net::TcpStream,
    peer_ip: IpAddr,
    ctx: Ctx,
) -> Result<()> {
    let tls_stream = ctx.tls.accept(stream).await?;
    let (mut session, banner) = Session::new(peer_ip, &ctx.config);
    session.mark_tls_active();
    handle_tls_with_banner(tls_stream, session, ctx, banner).await
}

async fn handle_tls(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    session: Session,
    ctx: Ctx,
) -> Result<()> {
    handle_tls_with_banner(stream, session, ctx, Vec::new()).await
}

async fn handle_tls_with_banner(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    mut session: Session,
    ctx: Ctx,
    banner: Vec<u8>,
) -> Result<()> {
    let mut io = BufReader::new(stream);
    if !banner.is_empty() {
        write_all_timeout(&mut io, &banner).await?;
    }
    let mut data_permit = DataPermit::new(Arc::clone(&ctx.data_sem));
    loop {
        let Some(line) = read_line_limited(&mut io, MAX_SMTP_LINE).await? else {
            break;
        };
        match session.step(&line, &ctx.config) {
            Action::Reply(bytes) => {
                if !bytes.is_empty() {
                    write_all_timeout(&mut io, &bytes).await?;
                }
            }
            Action::Close(bytes) => {
                write_all_timeout(&mut io, &bytes).await?;
                break;
            }
            Action::Enqueue {
                envelope,
                body,
                reply,
            } => {
                data_permit.permit = None;
                if !process_enqueue(*envelope, body, reply, &ctx, &mut io).await? {
                    continue;
                }
            }
            Action::UpgradeTls(_) => {} // already TLS
        }
        data_permit.sync(&session).await;
    }
    Ok(())
}

/// Run inbound authentication, prepend trace headers, enqueue the message.
/// Returns false when the message was rejected (session continues).
async fn process_enqueue<W: AsyncWrite + Unpin>(
    mut envelope: Envelope,
    body: Vec<u8>,
    reply: Vec<u8>,
    ctx: &Ctx,
    io: &mut W,
) -> Result<bool> {
    let auth = authenticate_inbound(&envelope, &body, &ctx.config).await;
    if auth.reject {
        let err = Reply::dmarc_reject().to_wire();
        write_all_timeout(io, &err).await?;
        return Ok(false);
    }
    envelope.quarantine = auth.quarantine;

    // Trace headers, in order: Received (with FCrDNS), Authentication-Results,
    // Received-SPF. Inserted now — before the first on-disk write — so they
    // can never be duplicated by retries.
    let received = build_received(&envelope, &ctx.config.server.hostname, &ctx.resolver).await;
    let body = auth.prepend_headers(received, body);

    match ctx.queue.enqueue(envelope, &body).await {
        Ok(id) => {
            info!(%id, "queued");
            ctx.notify.notify_one();
            write_all_timeout(io, &reply).await?;
        }
        Err(e) => {
            error!("queue error: {}", e);
            let err = Reply::insufficient_storage().to_wire();
            write_all_timeout(io, &err).await?;
        }
    }
    Ok(true)
}

/// Build the `Received:` trace header per RFC 5321 §3.7.2. The parenthesised
/// comment carries the forward-confirmed reverse DNS name when available.
async fn build_received(
    envelope: &Envelope,
    our_hostname: &str,
    resolver: &Resolver,
) -> Vec<u8> {
    let rdns = match rmail_auth::fcrdns::check(envelope.client_ip, resolver).await {
        FcrdnsResult::Pass(name) => name,
        _ => "unknown".to_owned(),
    };
    let ts = envelope
        .received_at
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_else(|_| "unknown".to_owned());
    let first_rcpt = envelope
        .recipients
        .first()
        .map(|r| r.address.to_string())
        .unwrap_or_else(|| "<unknown>".into());
    let with = if envelope.auth_user.is_some() {
        "ESMTPSA"
    } else {
        "ESMTP"
    };
    format!(
        "Received: from {} ({} [{}])\r\n\tby {} (rmail) with {} id {}\r\n\tfor {}; {}\r\n",
        envelope.client_helo,
        rdns,
        envelope.client_ip,
        our_hostname,
        with,
        envelope.id,
        first_rcpt,
        ts,
    )
    .into_bytes()
}

struct InboundAuth {
    reject: bool,
    quarantine: bool,
    authentication_results: Option<String>,
    received_spf: Option<String>,
}

impl InboundAuth {
    fn pass() -> Self {
        Self {
            reject: false,
            quarantine: false,
            authentication_results: None,
            received_spf: None,
        }
    }

    fn prepend_headers(&self, received: Vec<u8>, body: Vec<u8>) -> Vec<u8> {
        let extra_len = self
            .authentication_results
            .as_ref()
            .map(|h| h.len() + "Authentication-Results: \r\n".len())
            .unwrap_or(0)
            + self
                .received_spf
                .as_ref()
                .map(|h| h.len() + "Received-SPF: \r\n".len())
                .unwrap_or(0);
        let mut out = Vec::with_capacity(received.len() + extra_len + body.len());
        out.extend_from_slice(&received);
        if let Some(header) = &self.authentication_results {
            out.extend_from_slice(b"Authentication-Results: ");
            out.extend_from_slice(header.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if let Some(header) = &self.received_spf {
            out.extend_from_slice(b"Received-SPF: ");
            out.extend_from_slice(header.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(&body);
        out
    }
}

async fn authenticate_inbound(envelope: &Envelope, body: &[u8], config: &Config) -> InboundAuth {
    if envelope.auth_user.is_some() || envelope.from.is_null() {
        return InboundAuth::pass();
    }
    let mail_from = envelope.from.as_str();
    let results = rmail_auth::checker::verify(
        body,
        &mail_from,
        &envelope.from.domain,
        &envelope.client_helo,
        envelope.client_ip,
        &config.server.hostname,
    )
    .await;
    let reject = results.should_reject().is_some();
    let quarantine = !reject && results.should_quarantine();
    let received_spf = format!(
        "{} (rmail: domain of {} designates {} as permitted sender) client-ip={}; envelope-from={}; helo={}",
        results.spf.label(),
        envelope.from.domain,
        envelope.client_ip,
        envelope.client_ip,
        mail_from,
        envelope.client_helo
    );
    InboundAuth {
        reject,
        quarantine,
        authentication_results: Some(
            results.header(&config.server.hostname, &envelope.from.domain),
        ),
        received_spf: Some(received_spf),
    }
}

async fn read_line_limited<R>(io: &mut R, limit: usize) -> std::io::Result<Option<Vec<u8>>>
where
    R: AsyncBufRead + Unpin,
{
    timeout(READ_IDLE_TIMEOUT, async {
        let mut line = Vec::new();
        loop {
            let available = io.fill_buf().await?;
            if available.is_empty() {
                return if line.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(line))
                };
            }
            let take = available
                .iter()
                .position(|&b| b == b'\n')
                .map(|p| p + 1)
                .unwrap_or(available.len());
            if line.len() + take > limit {
                io.consume(take);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "line too long",
                ));
            }
            line.extend_from_slice(&available[..take]);
            io.consume(take);
            if line.ends_with(b"\n") {
                return Ok(Some(line));
            }
        }
    })
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "read timeout"))?
}

async fn write_all_timeout<W>(io: &mut W, bytes: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    timeout(WRITE_TIMEOUT, io.write_all(bytes))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "write timeout"))?
}
