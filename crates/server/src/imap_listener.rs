//! Inbound IMAP listener.

use anyhow::Result;
use rmail_config::Config;
use rmail_imap::session::{Action, Session};
use rmail_mailbox::Maildir;
use rmail_tls::TlsAcceptor;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{info, warn};

const MAX_CONNECTIONS: usize = 1024;

pub async fn run(
    addrs: Vec<SocketAddr>,
    config: Arc<Config>,
    maildir: Arc<Maildir>,
    tls: Arc<TlsAcceptor>,
) -> Result<()> {
    let sem = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = Vec::new();
    for addr in addrs {
        let config = Arc::clone(&config);
        let maildir = Arc::clone(&maildir);
        let tls = Arc::clone(&tls);
        let sem = Arc::clone(&sem);
        tasks.push(tokio::spawn(async move {
            accept_loop(addr, config, maildir, tls, sem).await
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
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "IMAP listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let permit = Arc::clone(&sem).acquire_owned().await.unwrap();
        let config = Arc::clone(&config);
        let maildir = Arc::clone(&maildir);
        let tls = Arc::clone(&tls);
        tokio::spawn(async move {
            let _permit = permit;
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
    io.get_mut().write_all(&greeting).await?;
    loop {
        let mut line = Vec::new();
        let n = io.read_until(b'\n', &mut line).await?;
        if n == 0 {
            break;
        }
        match session.step(&line, &config, &maildir).await {
            Action::Reply(out) => {
                if !out.is_empty() {
                    io.get_mut().write_all(&out).await?;
                }
            }
            Action::UpgradeTls(out) => {
                io.get_mut().write_all(&out).await?;
                let tcp = io.into_inner();
                let tls_stream = tls.accept(tcp).await?;
                session.mark_tls_active();
                return handle_tls(tls_stream, session, config, maildir).await;
            }
            Action::Close(out) => {
                io.get_mut().write_all(&out).await?;
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
        io.get_mut().write_all(&greeting).await?;
    }
    loop {
        let mut line = Vec::new();
        let n = io.read_until(b'\n', &mut line).await?;
        if n == 0 {
            break;
        }
        match session.step(&line, &config, &maildir).await {
            Action::Reply(out) => {
                if !out.is_empty() {
                    io.get_mut().write_all(&out).await?;
                }
            }
            Action::UpgradeTls(out) => {
                io.get_mut().write_all(&out).await?;
            }
            Action::Close(out) => {
                io.get_mut().write_all(&out).await?;
                break;
            }
        }
        if session.is_closed() {
            break;
        }
    }
    Ok(())
}
