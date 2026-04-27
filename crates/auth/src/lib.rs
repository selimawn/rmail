//! Authentication and mail authentication.
//!
//! - `verify_password` — SASL credential check (argon2id)
//! - `AuthChecker`     — SPF / DKIM / DMARC verification on inbound messages

pub mod password;
pub mod checker;
