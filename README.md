# rmail

A mail engine written 100% in Rust. Receives and sends email — like Postfix, but modern async Rust.

## What it is

`rmail` is a single binary that:

- Receives mail via **SMTP** (port 25 / 587 / 465)
- Sends mail via **SMTP** to other MTAs (with persistent retry queue)
- Serves mailboxes via **IMAP4rev2** (port 143 / 993)
- Handles TLS, SASL auth, DKIM signing, SPF / DMARC verification
- Stores mail in **Maildir** format
- Ships with `rmailctl` for admin: domain management, DNS export, user CRUD, queue inspection

No plugin system. No protocol abstractions. Just SMTP + IMAP, written directly.

## Quick start

```bash
# build (when ready)
cargo build --release

# create a domain
rmailctl domain add example.com

# get the DNS records you need to publish
rmailctl domain dns example.com

# export them as a Cloudflare-importable JSON
rmailctl domain dns example.com --export cloudflare > example.com.json

# add a user
rmailctl user add alice@example.com

# run the daemon
rmail --config /etc/rmail/rmail.toml
```

## Documentation

- [HANDOFF.md](HANDOFF.md) — full project handoff: architecture, tech stack, build phases
- [docs/dns-records.md](docs/dns-records.md) — every DNS record a mail server needs, explained
- [docs/postfix-mapping.md](docs/postfix-mapping.md) — how rmail's modules map to Postfix's processes
- [config/rmail.toml.example](config/rmail.toml.example) — annotated config

## Status

🚧 Pre-alpha. Active development.

## License

TBD.
