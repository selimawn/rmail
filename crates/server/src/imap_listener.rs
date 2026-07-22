//! Inbound IMAP listener.

use crate::connlimit::PerIpLimiter;
use anyhow::Result;
use rmail_config::Config;
use rmail_imap::session::{Action, Session};
use rmail_mailbox::Maildir;
use rmail_tls::TlsAcceptor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{info, warn};

const MAX_CONNECTIONS: usize = 1024;
const MAX_IMAP_LINE: usize = 8192;
const MAX_IMAP_LITERAL: usize = 50 * 1024 * 1024;
/// Must comfortably exceed the 29-minute IDLE window recommended by RFC 2177,
/// otherwise IDLE clients are kicked off mid-idle.
const READ_IDLE_TIMEOUT: Duration = Duration::from_secs(1860);
const WRITE_TIMEOUT: Duration = Duration::from_secs(120);

pub async fn run(
    addrs: Vec<SocketAddr>,
    config: Arc<Config>,
    maildir: Arc<Maildir>,
    tls: Arc<TlsAcceptor>,
) -> Result<()> {
    let sem = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let per_ip = PerIpLimiter::new();
    let mut tasks = Vec::new();
    for addr in addrs {
        let config = Arc::clone(&config);
        let maildir = Arc::clone(&maildir);
        let tls = Arc::clone(&tls);
        let sem = Arc::clone(&sem);
        let per_ip = per_ip.clone();
        tasks.push(tokio::spawn(async move {
            accept_loop(addr, config, maildir, tls, sem, per_ip).await
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
    maildir: Arc<Maildir>,
    tls: Arc<TlsAcceptor>,
    sem: Arc<Semaphore>,
    per_ip: PerIpLimiter,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "IMAP listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let config = Arc::clone(&config);
        let maildir = Arc::clone(&maildir);
        let tls = Arc::clone(&tls);
        let per_ip = per_ip.clone();
        tokio::spawn(async move {
            let Some(_ip_permit) = per_ip
                .acquire(
                    peer.ip(),
                    config.rate_limit.imap_connections_per_ip,
                    permit,
                )
                .await
            else {
                warn!(peer = %peer, "IMAP per-IP connection limit exceeded");
                return;
            };
            let result = if addr.port() == 993 {
                handle_implicit_tls(stream, config, maildir, tls).await
            } else {
                handle_plain(stream, config, maildir, tls).await
            };
            if let Err(e) = result {
                warn!(peer = %peer, "IMAP session error: {}", e);
            }
        });
    }
}

async fn handle_plain(
    stream: tokio::net::TcpStream,
    config: Arc<Config>,
    maildir: Arc<Maildir>,
    tls: Arc<TlsAcceptor>,
) -> Result<()> {
    let (mut session, greeting) = Session::new(false);
    let mut io = BufReader::new(stream);
    write_all_timeout(&mut io, &greeting).await?;
    loop {
        let Some(line) = read_imap_command(&mut io).await? else {
            break;
        };
        match session.step(&line, &config, &maildir).await {
            Action::Reply(out) => {
                if !out.is_empty() {
                    write_all_timeout(&mut io, &out).await?;
                }
            }
            Action::UpgradeTls(out) => {
                if !io.buffer().is_empty() {
                    break;
                }
                write_all_timeout(&mut io, &out).await?;
                let tcp = io.into_inner();
                let tls_stream = tls.accept(tcp).await?;
                session.mark_tls_active();
                return handle_tls(tls_stream, session, config, maildir).await;
            }
            Action::Close(out) => {
                write_all_timeout(&mut io, &out).await?;
                break;
            }
        }
        if session.is_closed() {
            break;
        }
    }
    Ok(())
}

async fn handle_implicit_tls(
    stream: tokio::net::TcpStream,
    config: Arc<Config>,
    maildir: Arc<Maildir>,
    tls: Arc<TlsAcceptor>,
) -> Result<()> {
    let tls_stream = tls.accept(stream).await?;
    let (session, greeting) = Session::new(true);
    handle_tls_with_greeting(tls_stream, session, greeting, config, maildir).await
}

async fn handle_tls(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    session: Session,
    config: Arc<Config>,
    maildir: Arc<Maildir>,
) -> Result<()> {
    handle_tls_with_greeting(stream, session, Vec::new(), config, maildir).await
}

async fn handle_tls_with_greeting(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    mut session: Session,
    greeting: Vec<u8>,
    config: Arc<Config>,
    maildir: Arc<Maildir>,
) -> Result<()> {
    let mut io = BufReader::new(stream);
    if !greeting.is_empty() {
        write_all_timeout(&mut io, &greeting).await?;
    }
    loop {
        let Some(line) = read_imap_command(&mut io).await? else {
            break;
        };
        match session.step(&line, &config, &maildir).await {
            Action::Reply(out) => {
                if !out.is_empty() {
                    write_all_timeout(&mut io, &out).await?;
                }
            }
            Action::UpgradeTls(out) => {
                write_all_timeout(&mut io, &out).await?;
            }
            Action::Close(out) => {
                write_all_timeout(&mut io, &out).await?;
                break;
            }
        }
        if session.is_closed() {
            break;
        }
    }
    Ok(())
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

async fn read_imap_command<R>(io: &mut R) -> std::io::Result<Option<Vec<u8>>>
where
    R: AsyncBufRead + AsyncWrite + Unpin,
{
    let Some(mut line) = read_line_limited(io, MAX_IMAP_LINE).await? else {
        return Ok(None);
    };
    let Some(n) = literal_len(&line) else {
        return Ok(Some(line));
    };
    if n > MAX_IMAP_LITERAL {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "literal too large",
        ));
    }
    if !line.ends_with(b"{0+}\r\n") && !line.ends_with(b"{0+}\n") && !literal_is_nonsync(&line) {
        write_all_timeout(io, b"+ Ready for literal data\r\n").await?;
    }
    let mut literal = vec![0; n];
    timeout(READ_IDLE_TIMEOUT, io.read_exact(&mut literal))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "literal timeout"))??;
    line.extend_from_slice(&literal);
    let mut crlf = [0u8; 2];
    if timeout(READ_IDLE_TIMEOUT, io.read_exact(&mut crlf))
        .await
        .is_ok()
        && crlf != *b"\r\n"
    {
        line.extend_from_slice(&crlf);
    }
    Ok(Some(line))
}

fn literal_len(line: &[u8]) -> Option<usize> {
    let s = std::str::from_utf8(line)
        .ok()?
        .trim_end_matches(['\r', '\n']);
    let start = s.rfind('{')?;
    let lit = s[start + 1..].strip_suffix('}')?;
    let lit = lit.strip_suffix('+').unwrap_or(lit);
    lit.parse().ok()
}

fn literal_is_nonsync(line: &[u8]) -> bool {
    std::str::from_utf8(line)
        .ok()
        .map(|s| s.trim_end_matches(['\r', '\n']).ends_with("+}"))
        .unwrap_or(false)
}

async fn write_all_timeout<W>(io: &mut W, bytes: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    timeout(WRITE_TIMEOUT, io.write_all(bytes))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "write timeout"))?
}
