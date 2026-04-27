//! rmailctl — rmail admin CLI
//!
//! Commands:
//!   domain add/remove/list/dns
//!   user add/remove/list/passwd
//!   queue list/show/flush/delete/hold/release
//!   status

mod cmd;

use clap::Parser;
use cmd::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rmailctl=warn".parse().unwrap()),
        )
        .init();

    Cli::parse().run().await
}
