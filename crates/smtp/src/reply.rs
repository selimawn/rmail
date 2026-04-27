//! SMTP reply codes and helpers (RFC 5321 §4.2).

use std::fmt;

/// An SMTP reply: numeric code + human-readable text.
#[derive(Debug, Clone)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Reply {
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        Self { code, lines: vec![text.into()] }
    }

    pub fn multiline(code: u16, lines: Vec<String>) -> Self {
        Self { code, lines }
    }

    // ─── Canned replies ───────────────────────────────────────────────

    pub fn greeting(hostname: &str) -> Self {
        Self::new(220, format!("{hostname} rmail ESMTP ready"))
    }

    pub fn ehlo_response(hostname: &str, max_size: u64, tls: bool) -> Self {
        let mut lines = vec![
            hostname.to_owned(),
            format!("SIZE {max_size}"),
            "8BITMIME".to_owned(),
            "ENHANCEDSTATUSCODES".to_owned(),
            "AUTH PLAIN LOGIN".to_owned(),
        ];
        if tls {
            lines.insert(1, "STARTTLS".to_owned());
        }
        Self::multiline(250, lines)
    }

    pub fn ok(msg: impl Into<String>) -> Self       { Self::new(250, msg) }
    pub fn start_data() -> Self                     { Self::new(354, "End data with <CR><LF>.<CR><LF>") }
    pub fn bye() -> Self                            { Self::new(221, "Bye") }
    pub fn ready_tls() -> Self                      { Self::new(220, "Ready to start TLS") }
    pub fn auth_continue(challenge: &str) -> Self   { Self::new(334, challenge.to_owned()) }
    pub fn auth_ok() -> Self                        { Self::new(235, "2.7.0 Authentication successful") }

    // 4xx
    pub fn temp_unavailable() -> Self {
        Self::new(421, "4.3.2 Service temporarily unavailable")
    }
    pub fn insufficient_storage() -> Self {
        Self::new(452, "4.3.1 Insufficient system storage")
    }

    // 5xx
    pub fn syntax_error() -> Self        { Self::new(500, "5.5.2 Syntax error") }
    pub fn bad_sequence() -> Self        { Self::new(503, "5.5.1 Bad sequence of commands") }
    pub fn relay_denied() -> Self        { Self::new(550, "5.7.1 Relay access denied") }
    pub fn user_unknown() -> Self        { Self::new(550, "5.1.1 User unknown") }
    pub fn auth_failed() -> Self         { Self::new(535, "5.7.8 Authentication credentials invalid") }
    pub fn policy_reject(msg: &str) -> Self { Self::new(550, format!("5.7.1 {msg}")) }
    pub fn too_big(limit: u64) -> Self {
        Self::new(552, format!("5.3.4 Message exceeds maximum size ({limit} bytes)"))
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let last = self.lines.len() - 1;
        for (i, line) in self.lines.iter().enumerate() {
            if i == last {
                writeln!(f, "{} {}", self.code, line)?;
            } else {
                writeln!(f, "{}-{}", self.code, line)?;
            }
        }
        Ok(())
    }
}
