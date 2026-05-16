//! `rmailctl domain` subcommands.

use clap::{Args, Subcommand};
use rmail_config::Config;
use rmail_dns::Resolver;

#[derive(Args)]
pub struct DomainArgs {
    #[command(subcommand)]
    pub command: DomainCmd,
}

#[derive(Subcommand)]
pub enum DomainCmd {
    /// Add a domain to the config (prints the lines to add)
    Add { name: String },
    /// List hosted domains
    List,
    /// Print required DNS records
    Dns {
        name: String,
        /// Export format: cloudflare | bind
        #[arg(long)]
        export: Option<String>,
    },
}

pub async fn run(args: DomainArgs, config: &Config) -> anyhow::Result<()> {
    match args.command {
        DomainCmd::Add { name } => {
            println!("Add the following to your config file:");
            println!();
            println!("[[domain]]");
            println!("name          = \"{}\"", name);
            println!("dkim_selector = \"rmail\"");
            println!("dkim_key      = \"/etc/rmail/dkim/{}.key\"", name);
            println!();
            println!("Then run: rmailctl domain dns {} to get the DNS records.", name);
        }

        DomainCmd::List => {
            if config.domains.is_empty() {
                println!("No domains configured.");
            }
            for d in &config.domains {
                println!("{}", d.name);
            }
        }

        DomainCmd::Dns { name, export } => {
            let resolver = Resolver::new(false);
            let server_ip = match resolver.host(&config.server.hostname).await {
                Ok(ips) => ips
                    .into_iter()
                    .next()
                    .map(|ip| ip.to_string())
                    .unwrap_or_else(|| "<YOUR_SERVER_IP>".to_string()),
                Err(_) => "<YOUR_SERVER_IP>".to_string(),
            };
            let server_ip = server_ip.as_str();
            let selector  = config.find_domain(&name)
                .map(|d| d.dkim_selector.as_str())
                .unwrap_or("rmail");
            let dmarc_rua = config.find_domain(&name)
                .and_then(|d| d.dmarc_rua.as_deref())
                .unwrap_or(&format!("dmarc@{}", name));

            match export.as_deref() {
                Some("cloudflare") => print_cloudflare_json(&name, server_ip, selector, dmarc_rua),
                Some("bind")       => print_bind_zone(&name, server_ip, selector, dmarc_rua),
                _                  => print_human(&name, server_ip, selector, dmarc_rua),
            }
        }
    }
    Ok(())
}

fn print_human(domain: &str, ip: &str, selector: &str, dmarc_rua: &str) {
    println!("DNS records for {}:", domain);
    println!();
    println!("  MX    {}               10 mail.{}", domain, domain);
    println!("  A     mail.{}          {}", domain, ip);
    println!("  TXT   {}               v=spf1 mx -all", domain);
    println!("  TXT   {}._domainkey.{} v=DKIM1; k=rsa; p=<PASTE_YOUR_PUBLIC_KEY>", selector, domain);
    println!("  TXT   _dmarc.{}        v=DMARC1; p=quarantine; rua=mailto:{}", domain, dmarc_rua);
    println!("  TXT   _smtp._tls.{}    v=TLSRPTv1; rua=mailto:tlsrpt@{}", domain, domain);
    println!();
    println!("  PTR   {} -> mail.{}", ip, domain);
    println!("        (Set this on your hosting provider's reverse DNS settings)");
    println!();
    println!("  DKIM key: generate with:");
    println!("    openssl genrsa -out /etc/rmail/dkim/{}.key 2048", domain);
    println!("    openssl rsa -in /etc/rmail/dkim/{}.key -pubout | grep -v '^--' | tr -d '\\n'", domain);
}

fn print_cloudflare_json(domain: &str, ip: &str, selector: &str, dmarc_rua: &str) {
    // Cloudflare bulk import format: array of record objects
    println!("[");
    println!("  {{\"type\":\"MX\",\"name\":\"{}\",\"content\":\"mail.{}\",\"priority\":10,\"ttl\":3600}},", domain, domain);
    println!("  {{\"type\":\"A\",\"name\":\"mail.{}\",\"content\":\"{}\",\"ttl\":3600}},", domain, ip);
    println!("  {{\"type\":\"TXT\",\"name\":\"{}\",\"content\":\"v=spf1 mx -all\",\"ttl\":3600}},", domain);
    println!("  {{\"type\":\"TXT\",\"name\":\"{}._domainkey.{}\",\"content\":\"v=DKIM1; k=rsa; p=REPLACE_WITH_PUBKEY\",\"ttl\":3600}},", selector, domain);
    println!("  {{\"type\":\"TXT\",\"name\":\"_dmarc.{}\",\"content\":\"v=DMARC1; p=quarantine; rua=mailto:{}\",\"ttl\":3600}},", domain, dmarc_rua);
    println!("  {{\"type\":\"TXT\",\"name\":\"_smtp._tls.{}\",\"content\":\"v=TLSRPTv1; rua=mailto:tlsrpt@{}\",\"ttl\":3600}}", domain, domain);
    println!("]");
}

fn print_bind_zone(domain: &str, ip: &str, selector: &str, dmarc_rua: &str) {
    println!("$ORIGIN {}.", domain);
    println!("@            IN  MX  10  mail.{}", domain);
    println!("mail         IN  A   {}", ip);
    println!("@            IN  TXT \"v=spf1 mx -all\"");
    println!("{}._domainkey IN  TXT \"v=DKIM1; k=rsa; p=REPLACE_WITH_PUBKEY\"", selector);
    println!("_dmarc       IN  TXT \"v=DMARC1; p=quarantine; rua=mailto:{}\"", dmarc_rua);
    println!("_smtp._tls   IN  TXT \"v=TLSRPTv1; rua=mailto:tlsrpt@{}\"", domain);
}
