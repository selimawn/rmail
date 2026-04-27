//! Outbound SMTP delivery: resolve MX + connect + send.

use std::net::IpAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};
use rmail_core::Address;
use rmail_dns::Resolver;
use rmail_config::Config;

/// Try to deliver `body` to a single remote recipient.
/// Returns Ok(()) on success, Err((smtp_code, message)) on failure.
pub async fn deliver_remote(
    queue_id: &str,
    rcpt: &Address,
    body: &[u8],
    dns: &Resolver,
    config: &Config,
) -> Result<(), (u16, String)> {
    // 1. MX lookup
    let mx_records = dns.mx(&rcpt.domain).await
        .map_err(|e| (450u16, e.to_string()))?;

    for mx in &mx_records {
        // 2. A/AAAA for the exchange
        let ips = match dns.host(&mx.exchange).await {
            Ok(ips) => ips,
            Err(_)  => continue,
        };

        for ip in ips {
            match try_deliver(queue_id, rcpt, body, ip, &mx.exchange, config).await {
                Ok(()) => {
                    info!(queue_id, address = %rcpt, mx = %mx.exchange, "remote delivered");
                    return Ok(());
                }
                Err((code, msg)) if code < 500 => {
                    warn!(queue_id, mx = %mx.exchange, "temp failure {}: {}", code, msg);
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
    Err((450, "all MX servers failed".into()))
}

async fn try_deliver(
    queue_id: &str,
    rcpt: &Address,
    body: &[u8],
    ip: IpAddr,
    mx_host: &str,
    config: &Config,
) -> Result<(), (u16, String)> {
    let addr = format!("{}:25", ip);
    let stream = TcpStream::connect(&addr).await
        .map_err(|e| (450u16, e.to_string()))?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    // Read greeting
    line.clear();
    reader.read_line(&mut line).await.map_err(|e| (450u16, e.to_string()))?;
    check_code(&line, 220)?;

    // EHLO
    send_line(&mut reader, &format!("EHLO {}\r\n", config.server.hostname)).await?;
    read_multiline(&mut reader).await?;

    // MAIL FROM
    send_line(&mut reader, &format!("MAIL FROM:<{}>\r\n", "")).await?;
    read_reply(&mut reader, 250).await?;

    // RCPT TO
    send_line(&mut reader, &format!("RCPT TO:<{}>\r\n", rcpt.as_str())).await?;
    read_reply(&mut reader, 250).await?;

    // DATA
    send_line(&mut reader, "DATA\r\n").await?;
    read_reply(&mut reader, 354).await?;

    // Body (dot-stuffing)
    for chunk in body.split(|&b| b == b'\n') {
        let chunk = chunk.strip_suffix(b"\r").unwrap_or(chunk);
        if chunk.starts_with(b".") {
            reader.get_mut().write_all(b".").await.map_err(|e| (450u16, e.to_string()))?;
        }
        reader.get_mut().write_all(chunk).await.map_err(|e| (450u16, e.to_string()))?;
        reader.get_mut().write_all(b"\r\n").await.map_err(|e| (450u16, e.to_string()))?;
    }
    send_line(&mut reader, ".\r\n").await?;
    read_reply(&mut reader, 250).await?;

    // QUIT
    send_line(&mut reader, "QUIT\r\n").await?;

    Ok(())
}

async fn send_line(reader: &mut BufReader<TcpStream>, s: &str) -> Result<(), (u16, String)> {
    reader.get_mut().write_all(s.as_bytes()).await.map_err(|e| (450u16, e.to_string()))
}

async fn read_reply(reader: &mut BufReader<TcpStream>, expect: u16) -> Result<String, (u16, String)> {
    let mut line = String::new();
    reader.read_line(&mut line).await.map_err(|e| (450u16, e.to_string()))?;
    check_code(&line, expect).map(|_| line)
}

async fn read_multiline(reader: &mut BufReader<TcpStream>) -> Result<(), (u16, String)> {
    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await.map_err(|e| (450u16, e.to_string()))?;
        // Multi-line: `250-`, last line: `250 `
        if line.len() >= 4 && &line[3..4] == " " { break; }
        if line.len() < 4 { break; }
    }
    Ok(())
}

fn check_code(line: &str, expect: u16) -> Result<(), (u16, String)> {
    let code: u16 = line[..3].parse().unwrap_or(0);
    if code == expect {
        Ok(())
    } else if code >= 500 {
        Err((code, line.trim().to_owned()))
    } else {
        Err((code, line.trim().to_owned()))
    }
}
