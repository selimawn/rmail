//! argon2id password hashing and verification.
//! Used by `rmailctl user add` and SMTP/IMAP AUTH.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::sync::OnceLock;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("hashing error: {0}")]
    Hash(String),
    #[error("invalid hash format")]
    InvalidHash,
}

/// Hash a plaintext password. Returns a PHC-format string.
pub fn hash(password: &str) -> Result<String, PasswordError> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| PasswordError::Hash(e.to_string()))
}

/// Verify a plaintext password against a PHC-format hash.
/// Returns `true` if the password is correct.
pub fn verify(password: &str, hash: &str) -> bool {
    let parsed = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

/// A real argon2id hash of a random dummy password.
///
/// Verify unknown usernames against this so that a failed login costs the
/// same time as a real one — prevents user enumeration via timing.
pub fn dummy_hash() -> &'static str {
    static HASH: OnceLock<String> = OnceLock::new();
    HASH.get_or_init(|| hash("rmail dummy password for missing users").expect("dummy hash"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let h = hash("hunter2").unwrap();
        assert!(verify("hunter2", &h));
        assert!(!verify("wrong", &h));
    }
}
