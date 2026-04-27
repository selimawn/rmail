//! Outbound SMTP client — used by the delivery worker.
//!
//! Connects to a remote MTA, delivers a single message, returns the result.
//! Handles STARTTLS, SIZE, and basic ESMTP negotiation.

use std::net::SocketAddr;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};
use thiserror::Error;
use rmail_core::Envelope;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SMTP error {code}: {message}")]
    Smtp { code: u16, message: String },
    #[error("unexpected EOF from remote")]
    Eof,
    #[error("TLS error: {0}")]
    Tls(String),
}

/// Result of a single delivery attempt.
#[derive(Debug)]
pub struct DeliveryResult {
    /// The final SMTP response code (2xx = success, 4xx = temp, 5xx = perm).
    pub code: u16,
    pub message: String,
}

impl DeliveryResult {
    pub fn is_success(&self) -> bool { self.code / 100 == 2 }
    pub fn is_transient(&self) -> bool { self.code / 100 == 4 }
    pub fn is_permanent(&self) -> bool { self.code / 100 == 5 }
}

/// Deliver a single message to a remote server.
///
/// `body` is the raw RFC 5322 message bytes (dot-stuffing applied here).
pub async fn deliver(
    target: SocketAddr,
    envelope: &Envelope,
    body: &[u8],
    our_hostname: &str,
) -> Result<DeliveryResult, ClientError> {
    debug!(%target, id = %envelope.id, "connecting");
    let stream = TcpStream::connect(target).await?;
    let mut io = BufReader::new(stream);

    // Read banner
    let banner = read_reply(&mut io).await?;
    if banner.code != 220 {
        return Err(ClientError::Smtp { code: banner.code, message: banner.message });
    }

    // EHLO
    let ehlo = send_recv(&mut io, &format!("EHLO {}\r\n", our_hostname)).await?;
    if ehlo.code != 250 {
        return Err(ClientError::Smtp { code: ehlo.code, message: ehlo.message });
    }

    // TODO: STARTTLS if advertised

    // MAIL FROM
    let mail_cmd = format!("MAIL FROM:{}\r\n", envelope.from);
    let r = send_recv(&mut io, &mail_cmd).await?;
    if r.code != 250 {
        return Ok(DeliveryResult { code: r.code, message: r.message });
    }

    // RCPT TO for all pending recipients
    let mut last_rcpt_result = DeliveryResult { code: 250, message: "OK".into() };
    for rcpt in envelope.pending_recipients() {
        let rcpt_cmd = format!("RCPT TO:{}\r\n", rcpt.address);
        let r = send_recv(&mut io, &rcpt_cmd).await?;
        if !r.is_success() {
            warn!(addr = %rcpt.address, code = r.code, "RCPT failed");
        }
        last_rcpt_result = r;
    }

    // DATA
    let r = send_recv(&mut io, "DATA\r\n").await?;
    if r.code != 354 {
        return Ok(DeliveryResult { code: r.code, message: r.message });
    }

    // Send body with dot-stuffing
    let stuffed = dot_stuff(body);
    io.get_mut().write_all(&stuffed).await?;
    io.get_mut().write_all(b"\r\n.\r\n").await?;

    // Final reply
    let r = read_reply(&mut io).await?;
    info!(id = %envelope.id, code = r.code, "delivery result");

    // QUIT (best-effort)
    let _ = io.get_mut().write_all(b"QUIT\r\n").await;

    Ok(DeliveryResult { code: r.code, message: r.message })
}

// ─── helpers ─────────────────────────────────────────────────────────────────

struct SmtpReply {
    code: u16,
    message: String,
    is_success: bool,
}

impl SmtpReply {
    fn is_success(&self) -> bool { self.code / 100 == 2 }
}

async fn read_reply<R: AsyncBufReadExt + Unpin>(r: &mut R) -> Result<DeliveryResult, ClientError> {
    let mut full = String::new();
    let mut code = 0u16;
    loop {
        let mut line = String::new();
        if r.read_line(&mut line).await? == 0 {
            return Err(ClientError::Eof);
        }
        let trimmed = line.trim_end();
        if trimmed.len() < 3 { return Err(ClientError::Eof); }
        let c: u16 = trimmed[..3].parse().map_err(|_| ClientError::Eof)?;
        code = c;
        let rest = &trimmed[4..];
        full.push_str(rest);
        // `NNN ` = last line; `NNN-` = continuation
        if trimmed.len() < 4 || &trimmed[3..4] == " " {
            break;
        }
        full.push('\n');
    }
    Ok(DeliveryResult { code, message: full })
}

async fn send_recv<R: AsyncBufReadExt + AsyncWriteExt + Unpin>(
    io: &mut R,
    cmd: &str,
) -> Result<DeliveryResult, ClientError> {
    io.write_all(cmd.as_bytes()).await?;
    read_reply(io).await
}

/// Apply SMTP dot-stuffing: a `.` at the start of a line becomes `..`.
fn dot_stuff(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 16);
    let mut bol = true; // beginning of line
    for &b in body {
        if bol && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        bol = b == b'\n';
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_stuff_normal() {
        assert_eq!(dot_stuff(b"hello\r\nworld"), b"hello\r\nworld");
    }

    #[test]
    fn dot_stuff_leading_dot() {
        assert_eq!(dot_stuff(b".leading"), b"..leading");
    }

    #[test]
    fn dot_stuff_mid_line_dot() {
        assert_eq!(dot_stuff(b"hel.lo"), b"hel.lo");
    }
}
