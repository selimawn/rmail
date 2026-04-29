//! Inbound IMAP listener.

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{info, warn};
use anyhow::Result;
use rmail_config::Config;
use rmail_mailbox::Maildir;
use rmail_imap::session::Session;

const MAX_CONNECTIONS: usize = 1024;

pub async fn run(
    addrs: Vec<SocketAddr>,
    config: Arc<Config>,
    maildir: Arc<Maildir>,
) -> Result<()> {
    let sem = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = Vec::new();
    for addr in addrs {
        let config  = Arc::clone(&config);
        let maildir = Arc::clone(&maildir);
        let sem     = Arc::clone(&sem);
        tasks.push(tokio::spawn(async move {
            accept_loop(addr, config, maildir, sem).await
        }));
    }
    for t in tasks { t.await??; }
    Ok(())
}

async fn accept_loop(
    addr: SocketAddr,
    config: Arc<Config>,
    maildir: Arc<Maildir>,
    sem: Arc<Semaphore>,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "IMAP listening");
    loop {
        let (stream, peer) = listener.accept().await?;
        let permit  = Arc::clone(&sem).acquire_owned().await.unwrap();
        let config  = Arc::clone(&config);
        let maildir = Arc::clone(&maildir);
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle(stream, config, maildir).await {
                warn!(peer = %peer, "IMAP session error: {}", e);
            }
        });
    }
}

async fn handle(
    stream: tokio::net::TcpStream,
    config: Arc<Config>,
    maildir: Arc<Maildir>,
) -> Result<()> {
    let (mut session, greeting) = Session::new();
    let mut io = BufReader::new(stream);
    io.get_mut().write_all(&greeting).await?;
    loop {
        let mut line = Vec::new();
        let n = io.read_until(b'\n', &mut line).await?;
        if n == 0 { break; }
        // step() is now async
        let out = session.step(&line, &config, &maildir).await;
        if !out.is_empty() { io.get_mut().write_all(&out).await?; }
        if session.is_closed() { break; }
    }
    Ok(())
}
