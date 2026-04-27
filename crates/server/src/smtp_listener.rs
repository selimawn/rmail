//! Inbound SMTP listener.
//!
//! Binds the configured TCP ports, accepts connections, and drives the
//! `smtp::Session` state machine for each one.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use anyhow::Result;
use rmail_config::Config;
use rmail_queue::Queue;
use rmail_tls::TlsAcceptor;
use rmail_smtp::session::{Session, Action};

/// Maximum simultaneous inbound SMTP connections.
const MAX_CONNECTIONS: usize = 1024;

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
        let queue  = Arc::clone(&queue);
        let tls    = Arc::clone(&tls);
        let sem    = Arc::clone(&sem);
        tasks.push(tokio::spawn(async move {
            accept_loop(addr, config, queue, tls, sem).await
        }));
    }

    for t in tasks { t.await??; }
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
        let permit  = Arc::clone(&sem).acquire_owned().await.unwrap();
        let config  = Arc::clone(&config);
        let queue   = Arc::clone(&queue);
        let tls     = Arc::clone(&tls);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_plain(stream, peer.ip(), config, queue, tls).await {
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
    io.get_mut().write_all(&banner).await?;

    loop {
        let mut line = Vec::new();
        let n = io.read_until(b'\n', &mut line).await?;
        if n == 0 { break; } // EOF

        match session.step(&line, &config) {
            Action::Reply(bytes) => {
                if !bytes.is_empty() { io.get_mut().write_all(&bytes).await?; }
            }
            Action::UpgradeTls(bytes) => {
                io.get_mut().write_all(&bytes).await?;
                // Consume the underlying stream, upgrade to TLS, restart loop
                let tcp = io.into_inner();
                let tls_stream = tls.accept(tcp).await?;
                session.mark_tls_active();
                return handle_tls(tls_stream, session, config, queue).await;
            }
            Action::Close(bytes) => {
                io.get_mut().write_all(&bytes).await?;
                break;
            }
            Action::Enqueue { envelope, body, reply } => {
                match queue.enqueue(envelope, &body).await {
                    Ok(id) => {
                        info!(%id, "queued");
                        io.get_mut().write_all(&reply).await?;
                    }
                    Err(e) => {
                        error!("queue error: {}", e);
                        let err = rmail_smtp::reply::Reply::insufficient_storage().to_wire();
                        io.get_mut().write_all(&err).await?;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn handle_tls(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    mut session: Session,
    config: Arc<Config>,
    queue: Arc<Queue>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let mut io = BufReader::new(stream);
    loop {
        let mut line = Vec::new();
        let n = io.read_until(b'\n', &mut line).await?;
        if n == 0 { break; }
        match session.step(&line, &config) {
            Action::Reply(bytes) => {
                if !bytes.is_empty() { io.get_mut().write_all(&bytes).await?; }
            }
            Action::Close(bytes) => {
                io.get_mut().write_all(&bytes).await?;
                break;
            }
            Action::Enqueue { envelope, body, reply } => {
                match queue.enqueue(envelope, &body).await {
                    Ok(id) => { io.get_mut().write_all(&reply).await?; }
                    Err(e) => {
                        error!("queue error: {}", e);
                        let err = rmail_smtp::reply::Reply::insufficient_storage().to_wire();
                        io.get_mut().write_all(&err).await?;
                    }
                }
            }
            Action::UpgradeTls(_) => {} // already TLS
        }
    }
    Ok(())
}
