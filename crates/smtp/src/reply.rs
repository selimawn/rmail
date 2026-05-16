//! SMTP reply codes and formatted response lines (RFC 5321 §4.2).

use std::fmt;

/// A single SMTP reply: numeric code + lines of text.
#[derive(Debug, Clone)]
pub struct Reply {
    pub code: u16,
    pub lines: Vec<String>,
}

impl Reply {
    pub fn new(code: u16, text: impl Into<String>) -> Self {
        Self {
            code,
            lines: vec![text.into()],
        }
    }

    pub fn multiline(code: u16, lines: Vec<String>) -> Self {
        Self { code, lines }
    }

    /// Render as SMTP wire format (CRLF terminated).
    pub fn to_wire(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let last = self.lines.len().saturating_sub(1);
        for (i, line) in self.lines.iter().enumerate() {
            let sep = if i == last { ' ' } else { '-' };
            out.extend_from_slice(format!("{}{}{}", self.code, sep, line).as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        out
    }
}

impl fmt::Display for Reply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(&self.to_wire()))
    }
}

// ─── constructors for common replies ─────────────────────────────────────────

impl Reply {
    pub fn ready(hostname: &str) -> Self {
        Self::new(220, format!("{} rmail ESMTP ready", hostname))
    }

    pub fn bye() -> Self {
        Self::new(221, "2.0.0 Bye")
    }

    pub fn ok() -> Self {
        Self::new(250, "2.0.0 OK")
    }

    pub fn ok_msg(msg: impl Into<String>) -> Self {
        Self::new(250, msg)
    }

    /// EHLO capability lines.
    /// `tls_active` = whether the current session is already running over TLS.
    /// We advertise STARTTLS only before TLS is established and AUTH only after,
    /// so credentials never travel in cleartext.
    pub fn ehlo_caps(hostname: &str, max_size: u64, tls_active: bool) -> Self {
        let mut lines = vec![
            hostname.to_owned(),
            format!("SIZE {}", max_size),
            "8BITMIME".to_owned(),
            "SMTPUTF8".to_owned(),
            "ENHANCEDSTATUSCODES".to_owned(),
            "PIPELINING".to_owned(),
        ];
        if !tls_active {
            lines.push("STARTTLS".to_owned());
        } else {
            lines.push("AUTH PLAIN LOGIN".to_owned());
        }
        Self::multiline(250, lines)
    }

    pub fn start_tls() -> Self {
        Self::new(220, "2.0.0 Ready to start TLS")
    }

    pub fn start_data() -> Self {
        Self::new(354, "End data with <CR><LF>.<CR><LF>")
    }

    pub fn queued(id: &str) -> Self {
        Self::new(250, format!("2.0.0 OK queued as {}", id))
    }

    pub fn auth_continue(challenge: &str) -> Self {
        Self::new(334, challenge.to_owned())
    }

    pub fn auth_ok() -> Self {
        Self::new(235, "2.7.0 Authentication successful")
    }

    pub fn auth_fail() -> Self {
        Self::new(535, "5.7.8 Authentication credentials invalid")
    }

    // ─── 4xx (transient) ─────────────────────────────────────────────────────

    pub fn too_busy() -> Self {
        Self::new(421, "4.3.2 Service temporarily unavailable")
    }

    pub fn insufficient_storage() -> Self {
        Self::new(452, "4.3.1 Insufficient storage")
    }

    // ─── 5xx (permanent) ─────────────────────────────────────────────────────

    pub fn syntax_error() -> Self {
        Self::new(500, "5.5.2 Syntax error, command unrecognised")
    }

    pub fn bad_sequence() -> Self {
        Self::new(503, "5.5.1 Bad sequence of commands")
    }

    pub fn relay_denied() -> Self {
        Self::new(550, "5.7.1 Relay access denied")
    }

    pub fn user_unknown(addr: &str) -> Self {
        Self::new(550, format!("5.1.1 <{}>: User unknown", addr))
    }

    pub fn message_too_large() -> Self {
        Self::new(552, "5.3.4 Message size exceeds limit")
    }

    pub fn dmarc_reject() -> Self {
        Self::new(550, "5.7.1 Message rejected due to DMARC policy")
    }

    pub fn tls_required() -> Self {
        Self::new(530, "5.7.0 Must issue a STARTTLS command first")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_single_line() {
        let r = Reply::new(250, "2.0.0 OK");
        assert_eq!(r.to_wire(), b"250 2.0.0 OK\r\n");
    }

    #[test]
    fn wire_multiline() {
        let r = Reply::multiline(
            250,
            vec![
                "example.com".into(),
                "SIZE 26214400".into(),
                "STARTTLS".into(),
            ],
        );
        let wire = String::from_utf8(r.to_wire()).unwrap();
        assert!(wire.starts_with("250-example.com\r\n"));
        assert!(wire.ends_with("250 STARTTLS\r\n"));
    }

    #[test]
    fn ehlo_caps_pre_tls_advertises_starttls_not_auth() {
        let r = Reply::ehlo_caps("mail.example.com", 26214400, false);
        let wire = String::from_utf8(r.to_wire()).unwrap();
        assert!(wire.contains("STARTTLS"));
        assert!(!wire.contains("AUTH"));
    }

    #[test]
    fn ehlo_caps_post_tls_advertises_auth_not_starttls() {
        let r = Reply::ehlo_caps("mail.example.com", 26214400, true);
        let wire = String::from_utf8(r.to_wire()).unwrap();
        assert!(!wire.contains("STARTTLS"));
        assert!(wire.contains("AUTH PLAIN LOGIN"));
    }
}
