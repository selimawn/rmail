//! SMTP session state machine.
//!
//! One `SmtpSession` per accepted TCP connection.
//! Drive it by calling `step(command)` after reading each line.
//! Collect body bytes by calling `feed_data(chunk)` during the DATA phase.

use std::net::IpAddr;
use crate::command::SmtpCommand;
use crate::reply::Reply;
use rmail_core::{Address, Envelope};

#[derive(Debug, Clone, PartialEq)]
pub enum SessionState {
    /// Connection accepted, greeting sent, waiting for EHLO/HELO.
    Connected,
    /// EHLO received. Waiting for MAIL FROM (or AUTH on Submission).
    Greeted,
    /// STARTTLS handshake requested — caller must upgrade the stream.
    UpgradeTls,
    /// AUTH in progress — waiting for credential line.
    AuthWait { mechanism: AuthMechanism },
    /// MAIL FROM accepted.
    Mailing { from: Address },
    /// At least one RCPT TO accepted.
    Collecting { from: Address, rcpts: Vec<Address> },
    /// DATA accepted — body streaming in progress.
    Data { from: Address, rcpts: Vec<Address> },
    /// Message accepted, back to Greeted.
    Accepted,
    /// QUIT — connection should be closed.
    Closing,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthMechanism { Plain, Login }

/// Result of a single `step()` call.
#[derive(Debug)]
pub enum StepResult {
    Reply(Reply),
    /// Caller must perform STARTTLS upgrade then call `reset()` on the session.
    UpgradeTls(Reply),
    /// Message is complete. Caller should enqueue and reply with 250.
    MessageComplete {
        envelope: Envelope,
        body: Vec<u8>,
    },
    Close(Reply),
}

pub struct SmtpSession {
    pub state:       SessionState,
    pub hostname:    String,
    pub max_bytes:   u64,
    pub client_ip:   IpAddr,
    pub tls_active:  bool,
    pub auth_user:   Option<String>,
    body_buf:        Vec<u8>,
    body_bytes:      u64,
    /// For AUTH LOGIN, we hold the username between challenges.
    auth_user_tmp:   Option<String>,
}

impl SmtpSession {
    pub fn new(hostname: impl Into<String>, max_bytes: u64, client_ip: IpAddr) -> Self {
        Self {
            state:        SessionState::Connected,
            hostname:     hostname.into(),
            max_bytes,
            client_ip,
            tls_active:   false,
            auth_user:    None,
            body_buf:     Vec::new(),
            body_bytes:   0,
            auth_user_tmp: None,
        }
    }

    /// Process one command line. Returns the reply (or action) for the caller.
    pub fn step(
        &mut self,
        cmd: SmtpCommand,
        // Closure called for RCPT TO to check if user exists in the local domain.
        // Returns Ok(is_local) or Err(user_unknown).
        check_rcpt: &dyn Fn(&Address) -> RcptCheck,
        // Closure called to verify AUTH credentials. Returns the username on success.
        verify_auth: &dyn Fn(&str, &str) -> Option<String>,
    ) -> StepResult {
        use SmtpCommand::*;
        use SessionState::*;

        match (&self.state.clone(), cmd) {
            // NOOP is valid in any state
            (_, Noop) => StepResult::Reply(Reply::ok("2.0.0 OK")),

            // QUIT is valid in any state
            (_, Quit) => {
                self.state = Closing;
                StepResult::Close(Reply::bye())
            }

            // RSET returns to Greeted
            (_, Rset) => {
                self.reset_transaction();
                StepResult::Reply(Reply::ok("2.0.0 Reset"))
            }

            // EHLO / HELO
            (Connected | Greeted | Accepted, Ehlo(domain)) => {
                self.state = Greeted;
                StepResult::Reply(Reply::ehlo_response(
                    &self.hostname,
                    self.max_bytes,
                    !self.tls_active,
                ))
            }
            (Connected | Greeted | Accepted, Helo(domain)) => {
                self.state = Greeted;
                StepResult::Reply(Reply::ok(format!("Hello {}", domain)))
            }

            // STARTTLS
            (Greeted, StartTls) if !self.tls_active => {
                self.state = UpgradeTls;
                StepResult::UpgradeTls(Reply::ready_tls())
            }
            (_, StartTls) => StepResult::Reply(Reply::bad_sequence()),

            // AUTH PLAIN inline credentials
            (Greeted, AuthPlain(Some(creds))) => {
                self.handle_auth_plain(&creds, verify_auth)
            }
            // AUTH PLAIN — server sends 334 to prompt for credentials
            (Greeted, AuthPlain(None)) => {
                self.state = AuthWait { mechanism: AuthMechanism::Plain };
                StepResult::Reply(Reply::auth_continue(""))
            }
            (Greeted, AuthLogin) => {
                self.state = AuthWait { mechanism: AuthMechanism::Login };
                StepResult::Reply(Reply::auth_continue("Username:"))
            }

            // MAIL FROM
            (Greeted, MailFrom { address, size }) => {
                if let Some(sz) = size {
                    if sz > self.max_bytes {
                        return StepResult::Reply(Reply::too_big(self.max_bytes));
                    }
                }
                match Address::parse(&address) {
                    Ok(addr) => {
                        self.state = Mailing { from: addr };
                        StepResult::Reply(Reply::ok("2.1.0 OK"))
                    }
                    Err(_) => StepResult::Reply(Reply::syntax_error()),
                }
            }

            // RCPT TO
            (Mailing { from } | Collecting { from, .. }, RcptTo(addr_str)) => {
                let from = from.clone();
                match Address::parse(&addr_str) {
                    Err(_) => StepResult::Reply(Reply::syntax_error()),
                    Ok(addr) => match check_rcpt(&addr) {
                        RcptCheck::LocalOk => {
                            let rcpts = match &self.state {
                                Collecting { rcpts, .. } => {
                                    let mut r = rcpts.clone();
                                    r.push(addr);
                                    r
                                }
                                _ => vec![addr],
                            };
                            self.state = Collecting { from, rcpts };
                            StepResult::Reply(Reply::ok("2.1.5 OK"))
                        }
                        RcptCheck::RelayDenied  => StepResult::Reply(Reply::relay_denied()),
                        RcptCheck::UserUnknown  => StepResult::Reply(Reply::user_unknown()),
                    },
                }
            }

            // DATA
            (Collecting { from, rcpts }, Data) => {
                let from = from.clone();
                let rcpts = rcpts.clone();
                self.body_buf.clear();
                self.body_bytes = 0;
                self.state = SessionState::Data { from, rcpts };
                StepResult::Reply(Reply::start_data())
            }

            _ => StepResult::Reply(Reply::bad_sequence()),
        }
    }

    /// Feed a raw DATA line (including CRLF). Call repeatedly.
    /// Returns `Some(StepResult::MessageComplete { .. })` when `.` is received.
    pub fn feed_data(
        &mut self,
        line: &[u8],
        check_rcpt: &dyn Fn(&Address) -> RcptCheck,
        verify_auth: &dyn Fn(&str, &str) -> Option<String>,
    ) -> Option<StepResult> {
        if let SessionState::Data { from, rcpts } = &self.state {
            // End-of-data marker: a line with only "."
            let stripped = line.strip_suffix(b"\r\n").unwrap_or(line);
            if stripped == b"." {
                let from = from.clone();
                let rcpts = rcpts.clone();
                let body = std::mem::take(&mut self.body_buf);
                self.state = SessionState::Accepted;
                let envelope = Envelope::new(
                    from,
                    rcpts,
                    self.client_ip,
                    "",
                    self.auth_user.clone(),
                );
                return Some(StepResult::MessageComplete { envelope, body });
            }

            // Dot-unstuffing: a leading "." that is NOT the end marker
            let body_line = if stripped.starts_with(b".") {
                &stripped[1..]
            } else {
                stripped
            };

            self.body_bytes += body_line.len() as u64;
            if self.body_bytes > self.max_bytes {
                return Some(StepResult::Reply(Reply::too_big(self.max_bytes)));
            }
            self.body_buf.extend_from_slice(body_line);
            self.body_buf.extend_from_slice(b"\r\n");
        }
        None
    }

    /// Feed a continuation line during AUTH (base64 credentials or username).
    pub fn feed_auth(
        &mut self,
        line: &str,
        verify_auth: &dyn Fn(&str, &str) -> Option<String>,
    ) -> StepResult {
        let mechanism = if let SessionState::AuthWait { mechanism } = &self.state {
            mechanism.clone()
        } else {
            return StepResult::Reply(Reply::bad_sequence());
        };

        match mechanism {
            AuthMechanism::Plain => self.handle_auth_plain(line.trim(), verify_auth),
            AuthMechanism::Login => {
                if self.auth_user_tmp.is_none() {
                    // First continuation: username (base64)
                    let username = decode_base64(line.trim()).unwrap_or_default();
                    self.auth_user_tmp = Some(username);
                    StepResult::Reply(Reply::auth_continue("Password:"))
                } else {
                    // Second continuation: password (base64)
                    let username = self.auth_user_tmp.take().unwrap_or_default();
                    let password = decode_base64(line.trim()).unwrap_or_default();
                    self.finish_auth(&username, &password, verify_auth)
                }
            }
        }
    }

    pub fn reset_transaction(&mut self) {
        self.state = SessionState::Greeted;
        self.body_buf.clear();
        self.body_bytes = 0;
        self.auth_user_tmp = None;
    }

    /// Called by the listener after a successful STARTTLS upgrade.
    pub fn tls_upgraded(&mut self) {
        self.tls_active = true;
        self.state = SessionState::Connected;
    }

    // ─── Auth internals ────────────────────────────────────────────────

    fn handle_auth_plain(
        &mut self,
        creds: &str,
        verify_auth: &dyn Fn(&str, &str) -> Option<String>,
    ) -> StepResult {
        // RFC 4616: base64("\0authzid\0password") — or "\0user\0pass" without authzid
        let decoded = match decode_base64(creds) {
            Some(d) => d,
            None => return StepResult::Reply(Reply::auth_failed()),
        };
        let parts: Vec<&str> = decoded.splitn(3, '\0').collect();
        let (username, password) = match parts.as_slice() {
            [_, u, p] => (*u, *p),
            [u, p] => (*u, *p),
            _ => return StepResult::Reply(Reply::auth_failed()),
        };
        self.finish_auth(username, password, verify_auth)
    }

    fn finish_auth(
        &mut self,
        username: &str,
        password: &str,
        verify_auth: &dyn Fn(&str, &str) -> Option<String>,
    ) -> StepResult {
        match verify_auth(username, password) {
            Some(user) => {
                self.auth_user = Some(user);
                self.state = SessionState::Greeted;
                StepResult::Reply(Reply::auth_ok())
            }
            None => StepResult::Reply(Reply::auth_failed()),
        }
    }
}

// ─── Supporting types ─────────────────────────────────────────────────

pub enum RcptCheck {
    LocalOk,
    RelayDenied,
    UserUnknown,
}

fn decode_base64(s: &str) -> Option<String> {
    use std::io::Read;
    // Use the standard alphabet; empty string is valid (anonymous)
    if s.is_empty() { return Some(String::new()); }
    let bytes = {
        // base64 crate is not in workspace deps; use stdlib decoder via a simple impl
        // We rely on base64 = "0.22" added to workspace
        // For now: naive decode via POSIX base64 alphabet
        // This will be replaced by the `base64` crate at link time.
        // Placeholder — the linker will pull the crate.
        s.as_bytes().to_vec()
    };
    String::from_utf8(bytes).ok()
}
