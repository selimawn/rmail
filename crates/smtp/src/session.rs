//! Inbound SMTP session state machine.
//!
//! One `Session` per accepted TCP connection. The caller is responsible for
//! driving it: read a line, call `step()`, write the returned bytes to the
//! socket. When `step()` returns `Action::Close`, flush and drop.

use std::net::IpAddr;
use tracing::{debug, info, warn};
use rmail_core::{Address, Envelope};
use rmail_config::Config;
use crate::command::{self, Command};
use crate::reply::Reply;

/// Maximum line length we accept before hard-closing (prevents memory abuse).
const MAX_LINE: usize = 1000;
/// Maximum number of RCPT TO per message (anti-abuse).
const MAX_RCPTS: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Accepted TCP connection, banner sent, waiting for EHLO/HELO.
    Connected,
    /// EHLO received.
    Greeted,
    /// STARTTLS negotiated.
    Tls,
    /// MAIL FROM received.
    Mailing,
    /// At least one RCPT TO received.
    Rcpt,
    /// DATA accepted, reading message body.
    Data,
    /// AUTH in progress (LOGIN mechanism, waiting for password).
    AuthLoginPass { username: String },
    /// Session closed.
    Closed,
}

/// What the caller must do after `step()`.
pub enum Action {
    /// Write these bytes to the socket and continue.
    Reply(Vec<u8>),
    /// Write bytes, then upgrade the stream to TLS.
    UpgradeTls(Vec<u8>),
    /// Write bytes, then close the connection.
    Close(Vec<u8>),
    /// Message body complete: deliver this envelope + body to the queue.
    /// Write the included bytes to the socket afterwards.
    Enqueue {
        envelope: Envelope,
        body: Vec<u8>,
        reply: Vec<u8>,
    },
}

pub struct Session {
    state: State,
    peer_ip: IpAddr,
    helo: String,
    tls_active: bool,
    auth_user: Option<String>,
    // Accumulator for MAIL FROM / RCPT TO across a single transaction.
    from: Option<Address>,
    rcpts: Vec<Address>,
    // DATA accumulator (streamed; we flush to disk via the Enqueue action).
    body_buf: Vec<u8>,
    // Track whether SIZE was announced and what limit applies.
    max_size: u64,
}

impl Session {
    pub fn new(peer_ip: IpAddr, config: &Config) -> (Self, Vec<u8>) {
        let banner = Reply::ready(&config.server.hostname).to_wire();
        (
            Self {
                state: State::Connected,
                peer_ip,
                helo: String::new(),
                tls_active: false,
                auth_user: None,
                from: None,
                rcpts: Vec::new(),
                body_buf: Vec::new(),
                max_size: config.max_message_bytes(),
            },
            banner,
        )
    }

    /// Feed a line from the client. Returns what to do next.
    /// In `Data` state, `line` is a raw body line (not a command).
    pub fn step(&mut self, line: &[u8], config: &Config) -> Action {
        if line.len() > MAX_LINE && self.state != State::Data {
            return Action::Close(Reply::syntax_error().to_wire());
        }

        match self.state {
            State::Data => self.handle_data_line(line, config),
            State::AuthLoginPass { ref username } => {
                // Expect base64-encoded password
                let user = username.clone();
                self.handle_auth_login_pass(line, &user, config)
            }
            _ => {
                let line_str = match std::str::from_utf8(line) {
                    Ok(s) => s,
                    Err(_) => return Action::Reply(Reply::syntax_error().to_wire()),
                };
                match command::parse(line_str) {
                    Ok(cmd) => self.handle_command(cmd, config),
                    Err(_)  => Action::Reply(Reply::syntax_error().to_wire()),
                }
            }
        }
    }

    // ─── command dispatch ─────────────────────────────────────────────────────

    fn handle_command(&mut self, cmd: Command, config: &Config) -> Action {
        debug!(peer = %self.peer_ip, state = ?self.state, ?cmd, "SMTP command");
        match cmd {
            Command::Ehlo(domain) | Command::Helo(domain) => self.do_ehlo(domain, config),
            Command::StartTls  => self.do_starttls(),
            Command::MailFrom { address, size } => self.do_mail_from(address, size, config),
            Command::RcptTo(addr) => self.do_rcpt_to(addr, config),
            Command::Data        => self.do_data(),
            Command::Rset        => self.do_rset(),
            Command::Quit        => Action::Close(Reply::bye().to_wire()),
            Command::Noop        => Action::Reply(Reply::ok().to_wire()),
            Command::AuthPlain(initial) => self.do_auth_plain(initial, config),
            Command::AuthLogin   => self.do_auth_login(),
            Command::Vrfy(_)     => Action::Reply(Reply::new(252, "2.1.5 Cannot VRFY user").to_wire()),
        }
    }

    fn do_ehlo(&mut self, domain: String, config: &Config) -> Action {
        self.helo = domain;
        self.reset_transaction();
        self.state = if self.tls_active { State::Tls } else { State::Greeted };
        Action::Reply(
            Reply::ehlo_caps(
                &config.server.hostname,
                config.max_message_bytes(),
                !self.tls_active, // advertise STARTTLS only before upgrade
            )
            .to_wire(),
        )
    }

    fn do_starttls(&mut self) -> Action {
        if self.tls_active {
            return Action::Reply(Reply::bad_sequence().to_wire());
        }
        Action::UpgradeTls(Reply::start_tls().to_wire())
    }

    fn do_mail_from(&mut self, address: String, size: Option<u64>, config: &Config) -> Action {
        if !matches!(self.state, State::Greeted | State::Tls) {
            return Action::Reply(Reply::bad_sequence().to_wire());
        }
        // Size check (if client announced one)
        if let Some(sz) = size {
            if sz > self.max_size {
                return Action::Reply(Reply::message_too_large().to_wire());
            }
        }
        match Address::parse(&address) {
            Ok(addr) => {
                self.from = Some(addr);
                self.state = State::Mailing;
                Action::Reply(Reply::ok_msg("2.1.0 OK").to_wire())
            }
            Err(_) => Action::Reply(Reply::new(501, "5.1.7 Bad sender address syntax").to_wire()),
        }
    }

    fn do_rcpt_to(&mut self, address: String, config: &Config) -> Action {
        if !matches!(self.state, State::Mailing | State::Rcpt) {
            return Action::Reply(Reply::bad_sequence().to_wire());
        }
        if self.rcpts.len() >= MAX_RCPTS {
            return Action::Reply(Reply::new(452, "4.5.3 Too many recipients").to_wire());
        }
        let addr = match Address::parse(&address) {
            Ok(a) => a,
            Err(_) => return Action::Reply(Reply::new(501, "5.1.3 Bad recipient address syntax").to_wire()),
        };
        // Relay check: only accept mail for local domains on port 25
        if !config.is_local_domain(&addr.domain) {
            // Authenticated users may relay
            if self.auth_user.is_none() {
                return Action::Reply(Reply::relay_denied().to_wire());
            }
        } else {
            // Local domain: user must exist
            if config.find_user(&addr.as_str()).is_none() {
                return Action::Reply(Reply::user_unknown(&addr.as_str()).to_wire());
            }
        }
        self.rcpts.push(addr);
        self.state = State::Rcpt;
        Action::Reply(Reply::ok_msg("2.1.5 OK").to_wire())
    }

    fn do_data(&mut self) -> Action {
        if self.state != State::Rcpt {
            return Action::Reply(Reply::bad_sequence().to_wire());
        }
        self.state = State::Data;
        self.body_buf.clear();
        Action::Reply(Reply::start_data().to_wire())
    }

    fn do_rset(&mut self) -> Action {
        self.reset_transaction();
        self.state = if self.tls_active { State::Tls } else { State::Greeted };
        Action::Reply(Reply::ok().to_wire())
    }

    // ─── DATA body accumulation ───────────────────────────────────────────────

    fn handle_data_line(&mut self, line: &[u8], config: &Config) -> Action {
        // End-of-data marker: a line containing only a dot
        if line == b".\r\n" || line == b".\n" || line == b"." {
            return self.finalize_data(config);
        }
        // Dot-stuffing: leading `..` → `.`
        let line = if line.starts_with(b"..") { &line[1..] } else { line };

        // Size guard
        if self.body_buf.len() + line.len() > self.max_size as usize {
            self.reset_transaction();
            self.state = State::Greeted;
            return Action::Reply(Reply::message_too_large().to_wire());
        }
        self.body_buf.extend_from_slice(line);
        Action::Reply(vec![]) // no reply mid-data
    }

    fn finalize_data(&mut self, config: &Config) -> Action {
        let from = self.from.take().unwrap_or_else(Address::null);
        let rcpts = std::mem::take(&mut self.rcpts);
        let body  = std::mem::take(&mut self.body_buf);

        let envelope = Envelope::new(
            from,
            rcpts,
            self.peer_ip,
            self.helo.clone(),
            self.auth_user.clone(),
        );
        let id = envelope.id.to_string();
        info!(id, peer = %self.peer_ip, "message accepted");
        self.state = if self.tls_active { State::Tls } else { State::Greeted };
        Action::Enqueue {
            reply: Reply::queued(&id).to_wire(),
            envelope,
            body,
        }
    }

    // ─── AUTH ─────────────────────────────────────────────────────────────────

    fn do_auth_plain(&mut self, initial: Option<String>, config: &Config) -> Action {
        let blob = match initial {
            Some(b) => b,
            None    => return Action::Reply(Reply::auth_continue("").to_wire()),
        };
        if let Some(user) = verify_plain(&blob, config) {
            self.auth_user = Some(user);
            Action::Reply(Reply::auth_ok().to_wire())
        } else {
            Action::Reply(Reply::auth_fail().to_wire())
        }
    }

    fn do_auth_login(&mut self) -> Action {
        // Ask for username in base64
        self.state = State::AuthLoginPass { username: String::new() };
        // First challenge: "Username:"
        Action::Reply(Reply::auth_continue("VXNlcm5hbWU6").to_wire())
    }

    fn handle_auth_login_pass(&mut self, line: &[u8], username_b64: &str, config: &Config) -> Action {
        // First response is the username in base64; state hack: we store it in the enum
        // username_b64 is empty on first call → this is the username
        let line_str = std::str::from_utf8(line).unwrap_or("").trim();
        if username_b64.is_empty() {
            // Got username, ask for password
            self.state = State::AuthLoginPass { username: line_str.to_owned() };
            return Action::Reply(Reply::auth_continue("UGFzc3dvcmQ6").to_wire()); // "Password:"
        }
        // Got password — verify
        // username_b64 holds the base64 username; decode both
        let user = decode_b64(username_b64);
        let pass = decode_b64(line_str);
        if let Some(u) = config.find_user(&user) {
            if verify_argon2(&pass, &u.password_hash) {
                self.auth_user = Some(user);
                self.state = State::Greeted;
                return Action::Reply(Reply::auth_ok().to_wire());
            }
        }
        self.state = State::Greeted;
        Action::Reply(Reply::auth_fail().to_wire())
    }

    // ─── helpers ──────────────────────────────────────────────────────────────

    fn reset_transaction(&mut self) {
        self.from  = None;
        self.rcpts.clear();
        self.body_buf.clear();
    }

    pub fn is_closed(&self) -> bool {
        self.state == State::Closed
    }

    /// Called by TLS layer after upgrade completes.
    pub fn mark_tls_active(&mut self) {
        self.tls_active = true;
        self.state = State::Connected; // client will re-EHLO
    }
}

// ─── auth helpers ────────────────────────────────────────────────────────────

fn decode_b64(s: &str) -> String {
    use std::io::Read;
    // base64 decode; ignore errors → empty string
    let bytes = base64_decode(s.trim());
    String::from_utf8_lossy(&bytes).into_owned()
}

fn base64_decode(s: &str) -> Vec<u8> {
    // Simple base64 decode without pulling in another dep
    // We already have `base64 = "0.22"` in workspace
    use std::collections::HashMap;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut map = [255u8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() { map[c as usize] = i as u8; }
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0usize;
    for &c in s {
        let v = map[c as usize];
        if v == 255 { continue; }
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

/// Verify AUTH PLAIN blob: `\0user\0password` (base64-encoded).
fn verify_plain(blob: &str, config: &rmail_config::Config) -> Option<String> {
    let raw = base64_decode(blob);
    // Format: [authzid] NUL authcid NUL passwd
    let parts: Vec<&[u8]> = raw.splitn(3, |&b| b == 0).collect();
    if parts.len() < 3 { return None; }
    let user = std::str::from_utf8(parts[1]).ok()?;
    let pass = std::str::from_utf8(parts[2]).ok()?;
    let cfg_user = config.find_user(user)?;
    if verify_argon2(pass, &cfg_user.password_hash) {
        Some(user.to_owned())
    } else {
        None
    }
}

fn verify_argon2(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok()
}
