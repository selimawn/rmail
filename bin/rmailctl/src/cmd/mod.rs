//! CLI command tree.

pub mod domain;
pub mod user;
pub mod queue;

use std::path::PathBuf;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "rmailctl", about = "rmail admin CLI")]
pub struct Cli {
    #[arg(short, long, default_value = "/etc/rmail/rmail.toml")]
    pub config: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Manage hosted domains
    Domain(domain::DomainArgs),
    /// Manage users
    User(user::UserArgs),
    /// Inspect / manage the mail queue
    Queue(queue::QueueArgs),
    /// Show server status
    Status,
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        let config = rmail_config::Config::load(&self.config)?;
        match self.command {
            Commands::Domain(a) => domain::run(a, &config).await,
            Commands::User(a)   => user::run(a, &config).await,
            Commands::Queue(a)  => queue::run(a, &config).await,
            Commands::Status    => {
                println!("hostname : {}", config.server.hostname);
                println!("domains  : {}", config.domains.len());
                println!("users    : {}", config.users.len());
                Ok(())
            }
        }
    }
}
