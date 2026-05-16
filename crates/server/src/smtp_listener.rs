//! Inbound SMTP listener.
//!
//! Binds the configured TCP ports, accepts connections, and drives the
//! `smtp::Session` state machine for each one.

use anyhow::Result;
use rmail_config::Config;
use rmail_core::Envelope;
use rmail_queue::Queue;
use rmail_smtp::reply::Reply;
use rmail_smtp::session::{Action, Session};
use rmail_tls::TlsAcceptor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{error, info, warn};

/// Maximum simultaneous inbound SMTP connections.
const MAX_CONNECTIONS: usize = 1024;
const MAX_SMTP_LINE: usize = 1000;
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const WRITE_TIMEOUT: Duration = Duration::from_secs(120);

pub async fn run(
    addrs: Vec<SocketAddr>,
    config: Arc<Config>,
    queue: Arc<Queue>,
    tls: Arc<TlsAcceptor>,
) -> Result<()> {
    let sem = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = Vec::new();

    for addr in addrs {
        let config = Arc::clone(&config);
        let queue = Arc::clone(&queue);
        let tls = Arc::clone(&tls);
        let sem = Arc::clone(&sem);
        tasks.push(tokio::spawn(async move {
            accept_loop(addr, config, queue, tls, sem).await
        }));
    }

    for t in tasks {
        t.await??;
    }
    Ok(())
}

async fn accept_loop(
    addr: SocketAddr,
    config: Arc<Config>,
    queue: Arc<Queue>,
    tls: Arc<TlsAcceptor>,
    sem: Arc<Semaphore>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "SMTP listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let config = Arc::clone(&config);
        let queue = Arc::clone(&queue);
        let tls = Arc::clone(&tls);
        tokio::spawn(async move {
            let _permit = permit;
            let result = if addr.port() == 465 {
                handle_implicit_tls(stream, peer.ip(), config, queue, tls).await
            } else {
                handle_plain(stream, peer.ip(), config, queue, tls).await
            };
            if let Err(e) = result {
                warn!(peer = %peer, "SMTP session error: {}", e);
            }
        });
    }
}

async fn handle_plain(
    stream: tokio::net::TcpStream,
    peer_ip: std::net::IpAddr,
    config: Arc<Config>,
    queue: Arc<Queue>,
    tls: Arc<TlsAcceptor>,
) -> Result<()> {
    let (mut session, banner) = Session::new(peer_ip, &config);
    let mut io = BufReader::new(stream);
    write_all_timeout(&mut io, &banner).await?;

    loop {
        let Some(line) = read_line_limited(&mut io, MAX_SMTP_LINE).await? else {
            break;
        };

        match session.step(&line, &config) {
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
                let tls_stream = tls.accept(tcp).await?;
                session.mark_tls_active();
                return handle_tls(tls_stream, session, config, queue).await;
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
                let auth = authenticate_inbound(&envelope, &body, &config).await;
                if auth.reject {
                    let err = Reply::dmarc_reject().to_wire();
                    write_all_timeout(&mut io, &err).await?;
                    continue;
                }
                let body = auth.prepend_headers(body);
                match queue.enqueue(*envelope, &body).await {
                    Ok(id) => {
                        info!(%id, "queued");
                        write_all_timeout(&mut io, &reply).await?;
                    }
                    Err(e) => {
                        error!("queue error: {}", e);
                        let err = Reply::insufficient_storage().to_wire();
                        write_all_timeout(&mut io, &err).await?;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_implicit_tls(
    stream: tokio::net::TcpStream,
    peer_ip: std::net::IpAddr,
    config: Arc<Config>,
    queue: Arc<Queue>,
    tls: Arc<TlsAcceptor>,
) -> Result<()> {
    let tls_stream = tls.accept(stream).await?;
    let (mut session, banner) = Session::new(peer_ip, &config);
    session.mark_tls_active();
    handle_tls_with_banner(tls_stream, session, config, queue, banner).await
}

async fn handle_tls(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    session: Session,
    config: Arc<Config>,
    queue: Arc<Queue>,
) -> Result<()> {
    handle_tls_with_banner(stream, session, config, queue, Vec::new()).await
}

async fn handle_tls_with_banner(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    mut session: Session,
    config: Arc<Config>,
    queue: Arc<Queue>,
    banner: Vec<u8>,
) -> Result<()> {
    let mut io = BufReader::new(stream);
    if !banner.is_empty() {
        write_all_timeout(&mut io, &banner).await?;
    }
    loop {
        let Some(line) = read_line_limited(&mut io, MAX_SMTP_LINE).await? else {
            break;
        };
        match session.step(&line, &config) {
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
                let auth = authenticate_inbound(&envelope, &body, &config).await;
                if auth.reject {
                    let err = Reply::dmarc_reject().to_wire();
                    write_all_timeout(&mut io, &err).await?;
                    continue;
                }
                let body = auth.prepend_headers(body);
                match queue.enqueue(*envelope, &body).await {
                    Ok(_id) => {
                        write_all_timeout(&mut io, &reply).await?;
                    }
                    Err(e) => {
                        error!("queue error: {}", e);
                        let err = Reply::insufficient_storage().to_wire();
                        write_all_timeout(&mut io, &err).await?;
                    }
                }
            }
            Action::UpgradeTls(_) => {} // already TLS
        }
    }
    Ok(())
}

struct InboundAuth {
    reject: bool,
    authentication_results: Option<String>,
    received_spf: Option<String>,
}

impl InboundAuth {
    fn pass() -> Self {
        Self {
            reject: false,
            authentication_results: None,
            received_spf: None,
        }
    }

    fn prepend_headers(&self, body: Vec<u8>) -> Vec<u8> {
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
        if extra_len == 0 {
            return body;
        }
        let mut out = Vec::with_capacity(extra_len + body.len());
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
        authentication_results: Some(results.header(&config.server.hostname)),
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
