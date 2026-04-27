//! `rmailctl user` subcommands.

use clap::{Args, Subcommand};
use rmail_config::Config;
use rmail_auth::password::{hash_password, verify_password};
use rmail_mailbox::Maildir;
use rmail_core::Address;

#[derive(Args)]
pub struct UserArgs {
    #[command(subcommand)]
    pub command: UserCmd,
}

#[derive(Subcommand)]
pub enum UserCmd {
    /// Add a new user
    Add {
        address: String,
        #[arg(long)]
        password: Option<String>,
    },
    /// List all users
    List,
    /// Remove a user
    Remove { address: String },
    /// Verify a password (for testing)
    Verify {
        address: String,
        #[arg(long)]
        password: String,
    },
}

pub async fn run(args: UserArgs, config: &Config) -> anyhow::Result<()> {
    match args.command {
        UserCmd::Add { address, password } => {
            let pw = match password {
                Some(p) => p,
                None => {
                    // Prompt interactively
                    print!("Password: ");
                    use std::io::{self, BufRead};
                    io::stdout().flush().ok();
                    let stdin = io::stdin();
                    stdin.lock().lines().next()
                        .and_then(|l| l.ok())
                        .unwrap_or_default()
                }
            };
            let hash = hash_password(&pw)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            println!("Add to your config:");
            println!();
            println!("[[user]]");
            println!("address       = \"{}\"", address);
            println!("password_hash = \"{}\"", hash);
        }

        UserCmd::List => {
            for u in &config.users {
                println!("{}", u.address);
            }
        }

        UserCmd::Remove { address } => {
            println!("Remove the [[user]] block with address = \"{}\" from your config.", address);
        }

        UserCmd::Verify { address, password } => {
            match config.find_user(&address) {
                None => println!("User not found: {}", address),
                Some(u) => {
                    if verify_password(&password, &u.password_hash) {
                        println!("OK: password matches");
                    } else {
                        println!("FAIL: password does not match");
                    }
                }
            }
        }
    }
    Ok(())
}
