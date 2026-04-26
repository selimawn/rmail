# rmail — Project Handoff

Single entry point for any developer (or AI agent) picking up the project. Read top to bottom before writing any code.

---

## 1. Mission

Build a **lightweight mail engine** in Rust. Two responsibilities, no more:

1. **Receive** email via SMTP.
2. **Send** email via SMTP.

Plus one supporting protocol so users can read their inbox:

3. **Serve** mailboxes via IMAP.

That's it. No webmail. No filter language. No abstractions over "mail backends". The code talks SMTP and IMAP directly.

## 2. Inspiration: Postfix

Postfix splits the MTA into focused processes that communicate via Unix sockets:

| Postfix process | Job |
|-----------------|-----|
| `master` | Supervises everything |
| `smtpd` | Receives incoming SMTP |
| `cleanup` | Validates + canonicalizes incoming mail |
| `qmgr` | Decides what to deliver, when, in what order |
| `smtp` | Outgoing SMTP client |
| `local` | Delivers to local mailboxes |
| `bounce` | Generates bounce messages |
| `pickup` | Reads from `maildrop` (local submission) |

We keep the **same logical separation** but collapse it to a **single async binary** running on Tokio. Each "Postfix process" becomes a Tokio task or module. Same robustness, less infra, one log stream.

## 3. Mapping Postfix → rmail

| Postfix | rmail |
|---------|-------|
| `master` | `bin/rmail` main + Tokio runtime |
| `smtpd` (port 25/587/465) | `server::smtpd::listener` |
| `smtp` (outbound) | `server::delivery::worker` |
| `cleanup` | `server::cleanup::task` |
| `qmgr` | `server::queue::manager` |
| `local` | `mailbox::deliver_local` |
| `bounce` | `server::bounce::generate` |
| `pickup` | not needed (no `sendmail` compat in v1) |
| `trivial-rewrite` | `core::address::canonicalize` |

## 4. Workspace layout

```
rmail/
├── Cargo.toml                     # workspace root
├── README.md
├── HANDOFF.md                     # ← you are here
├── LICENSE                        # TBD
├── .gitignore
├── rust-toolchain.toml
├── config/
│   └── rmail.toml.example
├── docs/
│   ├── dns-records.md
│   └── postfix-mapping.md
├── crates/
│   ├── core/                      # types only, zero deps on other rmail crates
│   ├── config/                    # TOML parsing, validation
│   ├── queue/                     # on-disk queue (Postfix-like layout)
│   ├── mailbox/                   # Maildir storage
│   ├── smtp/                      # RFC 5321 — parser, state machine, in & out
│   ├── imap/                      # RFC 9051 — parser, state machine
│   ├── dns/                       # resolver wrappers + DNS zone export
│   ├── tls/                       # rustls helpers, STARTTLS upgrade
│   ├── auth/                      # SASL, DKIM signing, SPF/DMARC eval
│   └── server/                    # orchestration: listeners, qmgr, delivery
└── bin/
    ├── rmail/                     # daemon binary
    └── rmailctl/                  # admin CLI
```

### Why crates?

Each crate has **one job**. Separated for compile times and clear boundaries — not for plugin abstraction. There's exactly one implementation of each. No traits where a single struct does the job.

Dependency direction: `bin/*` → `server` → (`smtp`, `imap`, `queue`, `mailbox`, `auth`, `dns`, `tls`, `config`) → `core`. Strictly acyclic.

## 5. Tech stack (locked in)

| Concern | Crate |
|---------|-------|
| Async runtime | `tokio` |
| TLS | `tokio-rustls` + `rustls` + `rustls-pemfile` |
| DNS | `hickory-resolver` |
| SMTP/IMAP grammar | `nom` (hand-written) |
| Email parsing (RFC 5322) | `mail-parser` |
| Email building | `mail-builder` |
| DKIM/SPF/DMARC | `mail-auth` (stalwartlabs) |
| Config | `serde` + `toml` |
| CLI | `clap` |
| Passwords | `argon2` |
| Logging | `tracing` + `tracing-subscriber` |
| Errors | `thiserror` (libs), `anyhow` (binaries) |
| Time | `time` |

No `async-trait`. No `Box<dyn Anything>` unless we have a measured reason. Concrete types end-to-end.

## 6. Data model

```rust
// crates/core/src/lib.rs

pub struct QueueId(pub String);          // e.g. "20260426143012.A1B2C3"

pub struct Address {
    pub local: String,
    pub domain: String,
}

pub struct Envelope {
    pub id: QueueId,
    pub from: Address,                    // MAIL FROM
    pub to: Vec<Address>,                 // RCPT TO
    pub received_at: OffsetDateTime,
    pub client_ip: IpAddr,
    pub client_helo: String,
    pub auth_user: Option<String>,        // Some(_) = authenticated submission
}

pub struct Message {
    pub envelope: Envelope,
    pub body_path: PathBuf,               // raw RFC 5322 bytes on disk
    pub size: u64,
}
```

Messages are **never held entirely in RAM**. Body lives on disk; we stream it.

## 7. Queue (on-disk, Postfix-style)

```
/var/lib/rmail/queue/
├── incoming/   newly accepted, pending cleanup
├── active/     being delivered right now
├── deferred/   delivery failed, scheduled retry
├── hold/       admin paused
├── bounce/     bounce-in-progress
└── corrupt/    parse failed; needs human
```

Each queued message is **two files**:
- `<QueueId>.env` — bincode-encoded `Envelope`
- `<QueueId>.eml` — raw RFC 5322 bytes

Atomic moves between dirs (`rename(2)`) drive the state machine. No DB needed.

## 8. Mailbox (Maildir++)

```
/var/lib/rmail/mail/
└── example.com/
    └── alice/
        ├── cur/
        ├── new/
        ├── tmp/
        └── .Sent/, .Drafts/, .Trash/
```

One message = one file. Lock-free (atomic rename from `tmp/` to `new/`). IMAP server reads from `cur/` + `new/`.

## 9. Config (TOML)

```toml
[server]
hostname        