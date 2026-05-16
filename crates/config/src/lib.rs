//! Configuration file parsing and validation.
//!
//! Usage:
//! ```rust,ignore
//! let config = Config::load(Path::new("/etc/rmail/rmail.toml"))?;
//! ```

use serde::Deserialize;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub storage: StorageConfig,
    pub tls: TlsConfig,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub delivery: DeliveryConfig,
    #[serde(default, rename = "domain")]
    pub domains: Vec<DomainConfig>,
    #[serde(default, rename = "user")]
    pub users: Vec<UserConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub hostname: String,
    pub listen_smtp: Vec<SocketAddr>,
    pub listen_imap: Vec<SocketAddr>,
    #[serde(default = "default_max_message_mb")]
    pub max_message_mb: u64,
}

fn default_max_message_mb() -> u64 {
    25
}

#[derive(Debug, Clone, Deserialize)]
pub struct StorageConfig {
    pub queue_dir: PathBuf,
    pub mailbox_dir: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DnsConfig {
    /// Enable DNSSEC validation on Cloudflare resolver.
    #[serde(default)]
    pub dnssec: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeliveryConfig {
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_initial_retry_secs")]
    pub initial_retry_secs: u64,
    #[serde(default = "default_max_retry_secs")]
    pub max_retry_secs: u64,
    #[serde(default = "default_bounce_after_hours")]
    pub bounce_after_hours: u64,
}

fn default_max_retries() -> u32 {
    25
}
fn default_initial_retry_secs() -> u64 {
    300
}
fn default_max_retry_secs() -> u64 {
    14400
}
fn default_bounce_after_hours() -> u64 {
    120
}

impl Default for DeliveryConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            initial_retry_secs: default_initial_retry_secs(),
            max_retry_secs: default_max_retry_secs(),
            bounce_after_hours: default_bounce_after_hours(),
        }
    }
}

/// Next retry delay using exponential backoff with a ceiling.
pub fn next_retry_delay(config: &DeliveryConfig, retry_count: u32) -> u64 {
    let delay = config.initial_retry_secs * (1u64 << retry_count.min(6));
    delay.min(config.max_retry_secs)
}

#[derive(Debug, Clone, Deserialize)]
pub struct DomainConfig {
    pub name: String,
    pub dkim_selector: String,
    pub dkim_key: PathBuf,
    pub dmarc_rua: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserConfig {
    /// Full email address: `user@domain`
    pub address: String,
    /// argon2id hash produced by `rmailctl user add`
    pub password_hash: String,
}

// ─── Load + validate ─────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("validation error: {0}")]
    Validation(String),
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&raw)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.server.hostname.is_empty() {
            return Err(ConfigError::Validation("server.hostname is empty".into()));
        }
        if self.server.listen_smtp.is_empty() {
            return Err(ConfigError::Validation(
                "server.listen_smtp must have at least one address".into(),
            ));
        }
        Ok(())
    }

    /// Returns true if `domain` is a domain this server hosts.
    pub fn is_local_domain(&self, domain: &str) -> bool {
        self.domains
            .iter()
            .any(|d| d.name.eq_ignore_ascii_case(domain))
    }

    /// Find a user by full email address (case-insensitive).
    pub fn find_user(&self, address: &str) -> Option<&UserConfig> {
        self.users
            .iter()
            .find(|u| u.address.eq_ignore_ascii_case(address))
    }

    /// Find domain config by name (case-insensitive).
    pub fn find_domain(&self, name: &str) -> Option<&DomainConfig> {
        self.domains
            .iter()
            .find(|d| d.name.eq_ignore_ascii_case(name))
    }

    pub fn max_message_bytes(&self) -> u64 {
        self.server.max_message_mb * 1024 * 1024
    }
}
