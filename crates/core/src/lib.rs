//! Core types for rmail.
//! No I/O, no async. Pure data structures shared by every crate.

use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use thiserror::Error;

// ─── QueueId ─────────────────────────────────────────────────────────────────

/// Unique identifier for a queued message.
/// Format: `YYYYMMDDHHmmss.XXXXXX` (hex entropy from pid + nanoseconds).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueueId(pub String);

impl QueueId {
    pub fn generate() -> Self {
        let now = OffsetDateTime::now_utc();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let entropy = (std::process::id() as u64)
            .wrapping_mul(0x9e3779b97f4a7c15)
            ^ nanos as u64;
        Self(format!(
            "{}{:02}{:02}{:02}{:02}{:02}.{:06X}",
            now.year(),
            now.month() as u8,
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
            entropy & 0xFFFFFF,
        ))
    }
}

impl fmt::Display for QueueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ─── Address ─────────────────────────────────────────────────────────────────

/// A parsed RFC 5321 email address.
///
/// Local-part is normalized to lowercase. Per RFC 5321 §2.4 the local-part
/// is technically case-sensitive, but in practice every modern MTA normalizes
/// to avoid duplicate accounts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    pub local: String,
    pub domain: String,
}

impl Address {
    /// Parse from `<user@domain>` or `user@domain`.
    /// An empty/null address `<>` returns `Address::null()`.
    ///
    /// Strict: rejects multiple angle brackets, lone brackets, whitespace,
    /// control characters, leading/trailing/consecutive dots, oversized parts,
    /// and any character outside the RFC 5321 atext + dot set for local-part
    /// or LDH for domain.
    pub fn parse(s: &str) -> Result<Self, CoreError> {
        let s = s.trim();
        let has_open = s.starts_with('<');
        let has_close = s.ends_with('>');
        let s = match (has_open, has_close) {
            (true, true) => &s[1..s.len() - 1],
            (false, false) => s,
            _ => return Err(CoreError::InvalidAddress(s.to_owned())),
        };
        let s = s.trim();
        if s.is_empty() {
            return Ok(Self::null());
        }
        let at = s.rfind('@').ok_or_else(|| CoreError::InvalidAddress(s.to_owned()))?;
        let local = &s[..at];
        let domain = &s[at + 1..];
        if local.is_empty() || domain.is_empty() {
            return Err(CoreError::InvalidAddress(s.to_owned()));
        }
        if local.len() > 64 || domain.len() > 253 {
            return Err(CoreError::InvalidAddress(s.to_owned()));
        }
        if !local.chars().all(is_atext_or_dot) {
            return Err(CoreError::InvalidAddress(s.to_owned()));
        }
        if !domain.chars().all(is_domain_char) {
            return Err(CoreError::InvalidAddress(s.to_owned()));
        }
        if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
            return Err(CoreError::InvalidAddress(s.to_owned()));
        }
        if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
            return Err(CoreError::InvalidAddress(s.to_owned()));
        }
        Ok(Self {
            local:  local.to_lowercase(),
            domain: domain.to_lowercase(),
        })
    }

    /// The null reverse-path used in bounces and DSNs.
    pub fn null() -> Self {
        Self { local: String::new(), domain: String::new() }
    }

    pub fn is_null(&self) -> bool {
        self.local.is_empty()
    }

    pub fn as_str(&self) -> String {
        if self.is_null() {
            String::new()
        } else {
            format!("{}@{}", self.local, self.domain)
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_null() {
            write!(f, "<>")
        } else {
            write!(f, "<{}@{}>", self.local, self.domain)
        }
    }
}

/// RFC 5322 atext + `.` (used between atoms).
fn is_atext_or_dot(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '/'
                | '=' | '?' | '^' | '_' | '`' | '{' | '|' | '}' | '~' | '.'
        )
}

/// LDH (letters, digits, hyphen) plus the dot separator.
fn is_domain_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '-')
}

// ─── Recipient ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipient {
    pub address: Address,
    pub status: DeliveryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// Awaiting a delivery attempt.
    Pending,
    /// Successfully handed off to the remote MTA or written to local Maildir.
    Delivered,
    /// Permanent failure — a bounce notice will be generated.
    Failed { code: u16, message: String },
    /// Bounce notice generated and sent.
    Bounced,
}

// ─── Envelope ────────────────────────────────────────────────────────────────

/// The SMTP routing envelope, persisted alongside the raw message body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub id: QueueId,
    /// MAIL FROM (null `<>` for bounces/DSNs)
    pub from: Address,
    /// One entry per RCPT TO, each with independent delivery tracking.
    pub recipients: Vec<Recipient>,
    pub received_at: OffsetDateTime,
    pub client_ip: IpAddr,
    /// EHLO/HELO hostname as claimed by the connecting client.
    pub client_helo: String,
    /// Present when the message arrived via an authenticated Submission session.
    pub auth_user: Option<String>,
    /// Number of delivery attempts made so far.
    pub retry_count: u32,
    /// Unix epoch second of the next scheduled retry (None = try now).
    pub next_retry_at: Option<i64>,
}

impl Envelope {
    pub fn new(
        from: Address,
        recipients: Vec<Address>,
        client_ip: IpAddr,
        client_helo: impl Into<String>,
        auth_user: Option<String>,
    ) -> Self {
        Self {
            id: QueueId::generate(),
            from,
            recipients: recipients
                .into_iter()
                .map(|a| Recipient { address: a, status: DeliveryStatus::Pending })
                .collect(),
            received_at: OffsetDateTime::now_utc(),
            client_ip,
            client_helo: client_helo.into(),
            auth_user,
            retry_count: 0,
            next_retry_at: None,
        }
    }

    pub fn pending_recipients(&self) -> impl Iterator<Item = &Recipient> {
        self.recipients.iter().filter(|r| r.status == DeliveryStatus::Pending)
    }

    pub fn all_done(&self) -> bool {
        self.recipients.iter().all(|r| r.status != DeliveryStatus::Pending)
    }

    pub fn mark_delivered(&mut self, address: &Address) {
        if let Some(r) = self.recipients.iter_mut().find(|r| &r.address == address) {
            r.status = DeliveryStatus::Delivered;
        }
    }

    pub fn mark_failed(&mut self, address: &Address, code: u16, message: String) {
        if let Some(r) = self.recipients.iter_mut().find(|r| &r.address == address) {
            r.status = DeliveryStatus::Failed { code, message };
        }
    }
}

// ─── Message ─────────────────────────────────────────────────────────────────

/// A complete queued message: envelope metadata + path to raw RFC 5322 body on disk.
/// The body is *never* loaded into memory by this type.
pub struct Message {
    pub envelope: Envelope,
    /// Path to the `.eml` file (raw RFC 5322 bytes, dot-stuffing already decoded).
    pub body_path: PathBuf,
    pub size: u64,
}

// ─── Queue state ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueState {
    Incoming,
    Active,
    Deferred,
    Hold,
    Bounce,
    Corrupt,
}

impl QueueState {
    pub fn dir_name(self) -> &'static str {
        match self {
            Self::Incoming => "incoming",
            Self::Active   => "active",
            Self::Deferred => "deferred",
            Self::Hold     => "hold",
            Self::Bounce   => "bounce",
            Self::Corrupt  => "corrupt",
        }
    }
}

// ─── Errors ──────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid email address: {0}")]
    InvalidAddress(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_parse_normal() {
        let a = Address::parse("<alice@example.com>").unwrap();
        assert_eq!(a.local, "alice");
        assert_eq!(a.domain, "example.com");
    }

    #[test]
    fn address_parse_bare() {
        let a = Address::parse("bob@gmail.com").unwrap();
        assert_eq!(a.local, "bob");
    }

    #[test]
    fn address_parse_null() {
        let a = Address::parse("<>").unwrap();
        assert!(a.is_null());
    }

    #[test]
    fn address_parse_invalid() {
        assert!(Address::parse("notanemail").is_err());
    }

    #[test]
    fn address_parse_rejects_multi_brackets() {
        assert!(Address::parse("<<a@b>>").is_err());
        assert!(Address::parse("<<<a@b>>>").is_err());
    }

    #[test]
    fn address_parse_rejects_lone_bracket() {
        assert!(Address::parse("<a@b").is_err());
        assert!(Address::parse("a@b>").is_err());
    }

    #[test]
    fn address_parse_rejects_whitespace() {
        assert!(Address::parse("a b@example.com").is_err());
        assert!(Address::parse("a@exa mple.com").is_err());
    }

    #[test]
    fn address_parse_rejects_consecutive_dots() {
        assert!(Address::parse("a..b@example.com").is_err());
        assert!(Address::parse("a@example..com").is_err());
    }

    #[test]
    fn address_parse_lowercases() {
        let a = Address::parse("Alice@Example.COM").unwrap();
        assert_eq!(a.local, "alice");
        assert_eq!(a.domain, "example.com");
    }

    #[test]
    fn address_parse_plus_addressing() {
        let a = Address::parse("user+tag@example.com").unwrap();
        assert_eq!(a.local, "user+tag");
    }

    #[test]
    fn queue_id_format() {
        let id = QueueId::generate();
        // YYYYMMDDHHmmss.XXXXXX — 21 chars
        assert!(id.0.len() >= 21);
        assert!(id.0.contains('.'));
    }
}
