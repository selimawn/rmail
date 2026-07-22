//! Outbound SMTP client — used by the delivery worker.
//! Handles STARTTLS, SIZE, and basic ESMTP negotiation.

use rmail_core::{Address, Envelope};
use rmail_tls::{TlsConnector, TlsMode};
use std::net::SocketAddr;
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tracing::{debug, info, warn};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);
const WRITE_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_REPLY_LINE: usize = 8192;

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

#[derive(Debug, Clone)]
pub struct DeliveryResult {
    pub code: u16,
    pub message: String,
}

impl DeliveryResult {
    pub fn is_success(&self) -> bool {
        self.code / 100 == 2
    }
    pub fn is_transient(&self) -> bool {
        self.code / 100 == 4
    }
    pub fn is_permanent(&self) -> bool {
        self.code / 100 == 5
    }
}

#[derive(Debug)]
pub struct DeliveryOutcome {
    pub accepted: Vec<Address>,
    pub rejected: Vec<(Address, DeliveryResult)>,
    pub final_result: DeliveryResult,
}

/// Deliver a single message to a remote MTA.
/// `remote_domain` is the MX hostname used for STARTTLS SNI.
///
/// Opportunistic mode (`require_starttls = false`): certificate verification
/// is disabled (Postfix `may` semantics — many MTAs use self-signed certs)
/// and any STARTTLS failure falls back to a fresh plaintext connection.
/// Strict mode: a verified TLS session is mandatory.
pub async fn deliver(
    target: SocketAddr,
    envelope: &Envelope,
    recipients: &[Address],
    body: &[u8],
    our_hostname: &str,
    remote_domain: &str,
    require_starttls: bool,
) -> Result<DeliveryOutcome, ClientError> {
    debug!(%target, id = %envelope.id, "connecting");
    let mut io = connect_and_ehlo(target, our_hostname).await?;

    // Check for STARTTLS capability in EHLO response
    let has_starttls = io
        .1
        .lines()
        .any(|l| l.trim().eq_ignore_ascii_case("starttls"));

    if has_starttls {
        let r = send_recv(&mut io.0, "STARTTLS\r\n").await?;
        if r.code == 220 {
            let connector = if require_starttls {
                TlsConnector::new()
            } else {
                TlsConnector::permissive()
            };
            let mode = if require_starttls {
                TlsMode::Required
            } else {
                TlsMode::Opportunistic
            };
            let plain = io.0.into_inner();
            match connector.connect(remote_domain, plain, mode).await {
                Ok(Some(tls_stream)) => {
                    debug!(%remote_domain, "STARTTLS established");
                    let mut tls_io = BufReader::new(tls_stream);
                    // Re-EHLO over TLS
                    let ehlo2 =
                        send_recv(&mut tls_io, &format!("EHLO {}\r\n", our_hostname)).await?;
                    if ehlo2.code != 250 {
                        return Err(ClientError::Smtp {
                            code: ehlo2.code,
                            message: ehlo2.message,
                        });
                    }
                    return deliver_inner(&mut tls_io, envelope, recipients, body).await;
                }
                outcome => {
                    if require_starttls {
                        let msg = match outcome {
                            Ok(None) => "STARTTLS failed".to_owned(),
                            Err(e) => format!("STARTTLS handshake failed: {}", e),
                            _ => unreachable!(),
                        };
                        warn!(%remote_domain, "{}", msg);
                        return Err(ClientError::Tls(msg));
                    }
                    // Opportunistic: reconnect and deliver in plaintext.
                    warn!(%remote_domain, "STARTTLS failed, retrying in plaintext");
                    let mut plain_io = connect_and_ehlo(target, our_hostname).await?;
                    return deliver_inner(&mut plain_io.0, envelope, recipients, body).await;
                }
            }
        }
    }
    if require_starttls {
        return Err(ClientError::Tls(format!(
            "{} did not advertise STARTTLS",
            remote_domain
        )));
    }

    deliver_inner(&mut io.0, envelope, recipients, body).await
}

/// Open a TCP connection, read the banner, send EHLO.
/// Returns the buffered stream and the EHLO reply text (for capability checks).
async fn connect_and_ehlo(
    target: SocketAddr,
    our_hostname: &str,
) -> Result<(BufReader<TcpStream>, String), ClientError> {
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timeout"))??;
    let mut io = BufReader::new(stream);

    let banner = read_reply(&mut io).await?;
    if banner.code != 220 {
        return Err(ClientError::Smtp {
            code: banner.code,
            message: banner.message,
        });
    }

    let ehlo = send_recv(&mut io, &format!("EHLO {}\r\n", our_hostname)).await?;
    if ehlo.code != 250 {
        return Err(ClientError::Smtp {
            code: ehlo.code,
            message: ehlo.message,
        });
    }
    Ok((io, ehlo.message))
}

async fn deliver_inner<S>(
    io: &mut S,
    envelope: &Envelope,
    recipients: &[Address],
    body: &[u8],
) -> Result<DeliveryOutcome, ClientError>
where
    S: AsyncBufRead + AsyncWrite + Unpin,
{
    // MAIL FROM
    let r = send_recv(io, &format!("MAIL FROM:{}\r\n", envelope.from)).await?;
    if r.code != 250 {
        let _ = io.write_all(b"QUIT\r\n").await;
        return Ok(DeliveryOutcome {
            accepted: Vec::new(),
            rejected: recipients
                .iter()
                .cloned()
                .map(|addr| (addr, r.clone()))
                .collect(),
            final_result: r,
        });
    }

    // RCPT TO
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for rcpt in recipients {
        let r = send_recv(io, &format!("RCPT TO:{}\r\n", rcpt)).await?;
        if !r.is_success() {
            warn!(addr = %rcpt, code = r.code, "RCPT failed");
            rejected.push((rcpt.clone(), r));
        } else {
            accepted.push(rcpt.clone());
        }
    }

    if accepted.is_empty() {
        let final_result =
            rejected
                .first()
                .map(|(_, r)| r.clone())
                .unwrap_or_else(|| DeliveryResult {
                    code: 554,
                    message: "No valid recipients".into(),
                });
        let _ = io.write_all(b"QUIT\r\n").await;
        return Ok(DeliveryOutcome {
            accepted,
            rejected,
            final_result,
        });
    }

    // DATA
    let r = send_recv(io, "DATA\r\n").await?;
    if r.code != 354 {
        let _ = io.write_all(b"QUIT\r\n").await;
        return Ok(DeliveryOutcome {
            accepted,
            rejected,
            final_result: r,
        });
    }

    // Body with dot-stuffing
    let stuffed = dot_stuff(body);
    write_all_timeout(io, &stuffed).await?;
    write_all_timeout(io, b".\r\n").await?;

    let r = read_reply(io).await?;
    info!(id = %envelope.id, code = r.code, "delivery result");
    let _ = io.write_all(b"QUIT\r\n").await;
    Ok(DeliveryOutcome {
        accepted,
        rejected,
        final_result: r,
    })
}

// ─── helpers ─────────────────────────────────────────────────────────────────

async fn read_reply<R: AsyncBufReadExt + Unpin>(r: &mut R) -> Result<DeliveryResult, ClientError> {
    let mut full = String::new();
    let code = loop {
        let mut line = String::new();
        let n = timeout(COMMAND_TIMEOUT, r.read_line(&mut line))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "reply timeout"))??;
        if n == 0 {
            return Err(ClientError::Eof);
        }
        if line.len() > MAX_REPLY_LINE {
            return Err(ClientError::Smtp {
                code: 500,
                message: "reply line too long".into(),
            });
        }
        let trimmed = line.trim_end();
        if trimmed.len() < 3 {
            return Err(ClientError::Eof);
        }
        let c: u16 = trimmed[..3].parse().map_err(|_| ClientError::Eof)?;
        let rest = if trimmed.len() > 4 { &trimmed[4..] } else { "" };
        full.push_str(rest);
        if trimmed.len() < 4 || &trimmed[3..4] == " " {
            break c;
        }
        full.push('\n');
    };
    Ok(DeliveryResult {
        code,
        message: full,
    })
}

async fn send_recv<S: AsyncBufRead + AsyncWrite + Unpin>(
    io: &mut S,
    cmd: &str,
) -> Result<DeliveryResult, ClientError> {
    write_all_timeout(io, cmd.as_bytes()).await?;
    read_reply(io).await
}

fn dot_stuff(body: &[u8]) -> Vec<u8> {
    let normalized = normalize_crlf(body);
    let mut out = Vec::with_capacity(normalized.len() + 16);
    let mut bol = true;
    for &b in &normalized {
        if bol && b == b'.' {
            out.push(b'.');
        }
        out.push(b);
        bol = b == b'\n';
    }
    if !out.ends_with(b"\r\n") {
        out.extend_from_slice(b"\r\n");
    }
    out
}

async fn write_all_timeout<W: AsyncWrite + Unpin>(
    io: &mut W,
    bytes: &[u8],
) -> Result<(), ClientError> {
    timeout(WRITE_TIMEOUT, io.write_all(bytes))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "write timeout"))??;
    Ok(())
}

fn normalize_crlf(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + 16);
    let mut i = 0;
    while i < body.len() {
        match body[i] {
            b'\r' if body.get(i + 1) == Some(&b'\n') => {
                out.extend_from_slice(b"\r\n");
                i += 2;
            }
            b'\r' | b'\n' => {
                out.extend_from_slice(b"\r\n");
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dot_stuff_normal() {
        assert_eq!(dot_stuff(b"hello\r\nworld"), b"hello\r\nworld\r\n");
    }
    #[test]
    fn dot_stuff_leading_dot() {
        assert_eq!(dot_stuff(b".leading"), b"..leading\r\n");
    }
    #[test]
    fn dot_stuff_mid_line_dot() {
        assert_eq!(dot_stuff(b"hel.lo"), b"hel.lo\r\n");
    }
    #[test]
    fn dot_stuff_normalizes_lf_and_stuffs_each_line() {
        assert_eq!(dot_stuff(b"a\n.b\r\n"), b"a\r\n..b\r\n");
    }
}
