//! Core types for rmail.
//! No I/O, no async. Pure data structures shared by every crate.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use time::OffsetDateTime;

// ─── QueueId ──────────────────────────────────────────────────────────────────────

/// Unique identifier for a queued message.
/// Format: `YYYYMMDDHHmmss.<pid><counter><nanos>` in hex.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QueueId(pub String);

impl QueueId {
    pub fn generate() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let now = OffsetDateTime::now_utc();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        let pid = std::process::id();
        let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
        Self(format!(
            "{}{:02}{:02}{:02}{:02}{:02}.{:08X}{:016X}{:08X}",
            now.year(),
            now.month() as u8,
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
            pid,
            counter,
            nanos,
        ))
    }
}

impl fmt::Display for QueueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ─── Address ──────────────────────────────────────────────────────────────────────

/// A parsed RFC 5321 email address.
///
/// **Normalisation**: both `local` and `domain` are stored lowercased.
/// RFC 5321 §2.4 permits a case-sensitive local-part, but every modern MTA
/// treats it case-insensitively in practice. We do the same.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    pub local: String,
    pub domain: String,
}

impl Address {
    /// Parse from `<user@domain>` or `user@domain`.
    ///
    /// Accepts at most one matching pair of angle brackets. Unbalanced or
    /// nested brackets, empty local-part or domain, or strings with no `@`
    /// are all rejected. The empty/null address `<>` (or just whitespace
    /// inside brackets) returns [`Address::null`].
    pub fn parse(s: &str) -> Result<Self, CoreError> {
        let s = s.trim();
        // Accept exactly one optional pair of angle brackets, no nesting.
        let inner = match (s.starts_with('<'), s.ends_with('>')) {
            (true, true) => &s[1..s.len() - 1],
            (false, false) => s,
            _ => return Err(CoreError::InvalidAddress(s.to_owned())),
        };
        let inner = inner.trim();
        if inner.is_empty() {
            return Ok(Self::null());
        }
        // Catch nested brackets such as `<<a@b>>` or `<a<b>@c>`.
        if inner.contains('<') || inner.contains('>') {
            return Err(CoreError::InvalidAddress(s.to_owned()));
        }
        let at = inner
            .rfind('@')
            .ok_or_else(|| CoreError::InvalidAddress(s.to_owned()))?;
        let local = &inner[..at];
        let domain = &inner[at + 1..];
        if local.is_empty() || domain.is_empty() {
            return Err(CoreError::InvalidAddress(s.to_owned()));
        }
        // Reject whitespace, control chars and path-traversal sequences.
        // The local-part is used as a filesystem path component by Maildir.
        let bad = |p: &str| {
            p.chars().any(|c| c.is_whitespace() || c.is_control())
                || p.contains("..")
                || p.contains('/')
                || p.contains('\\')
        };
        if bad(local) || bad(domain) {
            return Err(CoreError::InvalidAddress(s.to_owned()));
        }
        Ok(Self {
            local: local.to_lowercase(),
            domain: domain.to_lowercase(),
        })
    }

    /// The null reverse-path used in bounces and DSNs.
    pub fn null() -> Self {
        Self {
            local: String::new(),
            domain: String::new(),
        }
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

// ─── Recipient ────────────────────────────────────────────────────────────────────

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

// ─── Envelope ────────────────────────────────────────────────────────────────────

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
    /// DMARC quarantine: deliver local recipients to Junk instead of INBOX.
    pub quarantine: bool,
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
                .map(|a| Recipient {
                    address: a,
                    status: DeliveryStatus::Pending,
                })
                .collect(),
            received_at: OffsetDateTime::now_utc(),
            client_ip,
            client_helo: client_helo.into(),
            auth_user,
            retry_count: 0,
            next_retry_at: None,
            quarantine: false,
        }
    }

    pub fn pending_recipients(&self) -> impl Iterator<Item = &Recipient> {
        self.recipients
            .iter()
            .filter(|r| r.status == DeliveryStatus::Pending)
    }

    pub fn all_done(&self) -> bool {
        self.recipients
            .iter()
            .all(|r| r.status != DeliveryStatus::Pending)
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

// ─── Message ──────────────────────────────────────────────────────────────────────

/// A complete queued message: envelope metadata + storage-local body reference.
/// The body is *never* loaded into memory by this type.
pub struct Message {
    pub envelope: Envelope,
    /// Backend-local reference to the raw RFC 5322 body.
    pub body_ref: String,
    pub size: u64,
}

// ─── Queue state ──────────────────────────────────────────────────────────────────

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
            Self::Active => "active",
            Self::Deferred => "deferred",
            Self::Hold => "hold",
            Self::Bounce => "bounce",
            Self::Corrupt => "corrupt",
        }
    }
}

// ─── Errors ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid email address: {0}")]
    InvalidAddress(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ─── Tests ─────────────────────────────────────────────────────────────────────

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
    fn address_parse_unbalanced_open() {
        assert!(Address::parse("<a@b").is_err());
    }

    #[test]
    fn address_parse_unbalanced_close() {
        assert!(Address::parse("a@b>").is_err());
    }

    #[test]
    fn address_parse_nested_brackets_rejected() {
        assert!(Address::parse("<<a@b>>").is_err());
    }

    #[test]
    fn address_parse_empty_local() {
        assert!(Address::parse("@example.com").is_err());
    }

    #[test]
    fn address_parse_empty_domain() {
        assert!(Address::parse("alice@").is_err());
    }

    #[test]
    fn address_parse_lowercase_normalisation() {
        let a = Address::parse("Alice@Example.COM").unwrap();
        assert_eq!(a.local, "alice");
        assert_eq!(a.domain, "example.com");
    }

    #[test]
    fn address_parse_rejects_whitespace() {
        assert!(Address::parse("al ice@example.com").is_err());
        assert!(Address::parse("alice@exa mple.com").is_err());
    }

    #[test]
    fn address_parse_rejects_path_traversal() {
        assert!(Address::parse("../etc@example.com").is_err());
        assert!(Address::parse("a/b@example.com").is_err());
        assert!(Address::parse("alice@example.com/x").is_err());
    }

    #[test]
    fn address_parse_rejects_control_chars() {
        assert!(Address::parse("al\tice@example.com").is_err());
    }

    #[test]
    fn queue_id_format() {
        let id = QueueId::generate();
        // YYYYMMDDHHmmss.XXXXXX — 21 chars
        assert!(id.0.len() >= 21);
        assert!(id.0.contains('.'));
    }
}
