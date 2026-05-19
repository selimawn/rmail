# rmail — Full Review Handoff

Date: 2026-05-19 · Branch: `main` @ a94be73 · Scope: every `.rs`, `.toml`, doc, workflow.
Methodology: full read of the workspace, code-path tracing, threat modelling against RFC 5321 (SMTP), RFC 9051 (IMAP4rev2), RFC 6376 (DKIM), RFC 7208 (SPF), RFC 7489 (DMARC), RFC 8461 (MTA-STS), and OWASP categories applicable to network daemons.

This document supersedes `REVIEW.md` for the **current state of `main`** — many of the findings from `REVIEW.md` (dead `smtpd.rs`, unbounded line reads, no I/O timeouts, hardcoded UIDVALIDITY, broken `cmd/` alt CLI) have since been fixed. Findings below are against `a94be73`.

---

## 0 — Executive summary

`rmail` is a coherent, well-decomposed Rust mail engine inspired explicitly by Postfix. The architecture is sound, the queue layer is the strongest part of the codebase, and the inbound SMTP / IMAP protocol surfaces have been hardened since the previous review. **Build is clean** (no warnings, clippy passes, rustfmt clean, ~15 unit tests pass).

It is **not production-ready**, but the gap is narrower than it looks. The remaining blockers cluster into four categories:

1. **One critical authenticated-user vulnerability** (IMAP path traversal in folder operations) that, combined with the daemon running as root for port 25 binding, equals arbitrary file deletion / creation on the host filesystem.
2. **Three high-severity hardening gaps**: DNS resolved over plain UDP for outbound MX (allowing on-path attackers to redirect mail), no privilege separation / drop, and `mail-auth` resolver rebuilt per inbound message (DoS amplification).
3. **Memory model for inbound DATA** still buffers the whole message in RAM, contradicting the HANDOFF claim that "messages are never held entirely in RAM".
4. **IMAP correctness drift**: UID derivation is not collision-free, `BODYSTRUCTURE` is a constant stub, `SEARCH` does not parse `OR` / `NOT` / parentheses, no per-user quota. Real-world clients (Thunderbird, Apple Mail, Outlook) will work for trivial cases and corrupt or stall on edge cases.

The good news: every issue below is fixable with bounded, mechanical work. None requires architectural change.

---

## 1 — What works well (keep these decisions)

### 1.1 Architecture
- **Strictly acyclic crate graph**: `bin/* → server → (smtp, imap, queue, mailbox, auth, dns, tls, config) → core`. No `async-trait`, no `Box<dyn Anything>` outside of the storage backend enum. Concrete types end-to-end. Compile times stay sane, refactors are local.
- **Postfix-inspired separation collapsed into a single Tokio binary**. The mapping is documented and consistent: `master = bin/rmail`, `smtpd = server::smtp_listener + smtp::session`, `qmgr = server::queue_manager`, `smtp(out) = server::delivery + smtp::client`, `local = mailbox::Maildir`, `bounce = server::bounce`. One log stream, one supervision tree.
- **Storage backends as enum, not trait**. `Queue { Local | S3 }` and `Maildir { local | Option<S3Store> }`. Idiomatic Rust, no virtual dispatch tax, identical surface API. The S3 path was added in PR #8 without restructuring the local path — that's the right discipline.

### 1.2 SMTP inbound (after PR #6/#7 hardening)
- TLS-before-AUTH is enforced. Pre-TLS EHLO does not advertise `AUTH`; post-TLS EHLO does not advertise `STARTTLS`. Tested (`ehlo_caps_pre_tls_advertises_starttls_not_auth`, `ehlo_caps_post_tls_advertises_auth_not_starttls`).
- AUTH PLAIN / LOGIN both reject without TLS with 530 5.7.0.
- **Anti-spoofing on MAIL FROM** for authenticated sessions: a logged-in user cannot send as anyone but themselves (null sender `<>` allowed for DSN). The null reverse-path edge case is correctly handled.
- **Account-enumeration mitigation on AUTH**: a constant-time `dummy_password_hash` (lazy `OnceLock<String>`) is verified even when the user does not exist, so timing does not leak whether an account is provisioned. Good defensive engineering.
- Bare `<LF>` is detected and rejected with 500 5.5.2 in every state including `DATA` — closes the Postfix/Exim/Sendmail "SMTP smuggling" CVE-2023-51766 class.
- `Received:` trace header is prepended **before enqueue**, so it cannot be duplicated by retries.
- Read-line is now bounded (`read_line_limited` with explicit limit per protocol), `WRITE_TIMEOUT = 120s`, `READ_IDLE_TIMEOUT = 300s`. Slow-loris is closed.
- Pipelining before `STARTTLS` is detected (`io.buffer().is_empty()` check) and rejected with 554 — closes the STARTTLS command-injection class (CVE-2011-0411 / Postfix CVE-2011-1720 style).
- 100 RCPT per message cap; per-IP connection cap (default 32); global cap 1024.

### 1.3 Queue (the strongest layer)
- **Two-rename commit protocol**: `.eml` first (body), then `.env` (envelope = commit marker). If we crash between the two, the envelope is still in the source dir = the message logically stays in its old state. Orphan body is cleaned on next `recover()`.
- Every state-changing operation is followed by a `fsync_dir(parent)` so the rename is durable across kernel crashes — the comment in `queue/src/lib.rs:606` correctly notes that `fsync(file)` is insufficient on most Unix filesystems.
- `recover()` sweep at startup quarantines envelopes-without-bodies into `corrupt/` and deletes orphan bodies. Idempotent, single-pass, fsync at the end.
- The S3 backend uses the same surface API and the same recovery semantics, port one for one.

### 1.4 Maildir
- One file = one message, `tmp → new` atomic rename, `cur/` for IMAP-seen, `:2,FLAGS` suffix, sorted-and-deduped flag normalisation. Lock-free, multi-reader safe.
- `move_to_cur` adds `S` flag on SELECT.
- S3 mode mirrors Maildir++ semantics using key prefixes; `.keep` placeholders preserve empty-folder existence.

### 1.5 TLS
- rustls 0.23 + tokio-rustls 0.26. TLS 1.2 / 1.3 only (no SSLv3 / 1.0 / 1.1).
- 10 s handshake timeout in both directions; outbound `TlsMode::Opportunistic | Required` is explicit at the type level.
- Outbound uses `webpki-roots` and `ServerName::try_from(domain)` for hostname validation when `Required`.

### 1.6 Outbound delivery
- MX records sorted by priority, all targets tried in order. Per-MX timeout (120 s).
- **Null MX (RFC 7505)** is detected (`records[0].exchange == "."`) and yields a permanent 550 5.1.10. Good.
- **MTA-STS** policy discovery is implemented: TXT `_mta-sts.<domain>` lookup followed by HTTPS fetch of `.well-known/mta-sts.txt`, parsed into `mode` and `mx` patterns. Enforce mode upgrades the outbound TLS policy to `Required` and constrains MX selection.
- **DKIM signing** is automatic for any outbound whose `MAIL FROM` domain is hosted locally. RSA-SHA256, headers `From/To/Subject/Date/Message-ID/MIME-Version/Content-Type` covered by the signature.
- 4xx (transient) vs 5xx (permanent) properly distinguished; permanent failures recorded per-recipient on the envelope and trigger bounce after retry budget.

### 1.7 CI and release engineering
- One workflow does `fmt --check`, `build --workspace`, `test --workspace`, `clippy -- -D warnings` on every push.
- Release matrix builds for linux x86_64 / aarch64, macOS x86_64 / aarch64, attaches tarballs to a GH release per tag (and a rolling pre-release on `main`).
- Cache key on `Cargo.toml` hash — sane.

### 1.8 rmailctl
- Subcommand surface covers domain / user / queue / storage / status.
- `domain dns <name> --export cloudflare` emits Cloudflare bulk-import JSON; `--export bind` emits zone-file syntax. Practical for ops bootstrap.
- `queue` exposes list / show / flush / delete / hold / release — sufficient for human triage.
- `storage s3-test` runs a put / get / delete healthcheck against the configured bucket.

---

## 2 — Non-security weaknesses

### 2.1 Inbound DATA still buffered fully in RAM
`crates/smtp/src/session.rs:69`: `body_buf: Vec<u8>` accumulates the entire message body before enqueue. With `max_message_mb = 25` and 1024 connection permits, worst-case resident set is 25 GB just for in-flight bodies. The HANDOFF claims "messages are never held entirely in RAM" — this is currently false.

**Fix sketch**: open the `.eml` in `tmp/<id>` as soon as DATA starts, stream lines into it, fsync data, then `rename → incoming/<id>.eml`, then write envelope, then `rename → incoming/<id>.env`. Same commit-marker discipline as today's `enqueue`.

### 2.2 IMAP UID generation is not collision-free
`crates/imap/src/session.rs:932`:
```rust
let epoch = ts.saturating_sub(1_600_000_000);
Some(epoch.saturating_mul(1024).saturating_add(counter.min(1023)))
```
The counter is capped at 1023, so any user who appends more than 1024 messages in the same wall-second collides UIDs. The `unique_filename` counter monotonically increments across the process lifetime, so after `~1024 × n_seconds_alive` messages the counter is well above 1023 and gets clamped → guaranteed collision.

`UIDVALIDITY` is derived from `hash(user, mailbox)` (no longer hardcoded — good), but a deterministic UIDVALIDITY plus collision-prone UIDs means **IMAP client caches will mis-attribute message bodies after a collision**.

**Fix sketch**: store the next-UID counter in a file per mailbox (`uidnext`), incremented atomically on APPEND / move. Or switch to a Maildir-uniquename → UID map stored alongside `cur/`.

### 2.3 IMAP `BODYSTRUCTURE` is a constant stub
`crates/imap/src/session.rs:511`:
```rust
parts.push(b"BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0)".to_vec());
```
Any client that uses BODYSTRUCTURE to decide whether to fetch MIME parts (`BODY[1.MIME]`, etc.) will see "this message has no attachments" for every message, regardless of content. Webmail UIs that hide the paperclip icon based on bodystructure will silently fail to indicate attachments.

**Fix sketch**: parse the message with `mail-parser` (already a workspace dep) and emit a real bodystructure.

### 2.4 IMAP SEARCH is one-pass keyword matcher
`crates/imap/src/session.rs:1075` (`tokenize_search`) and `:1096` (`search_matches`): no `OR`, no `NOT`, no parenthesised grouping, no date criteria (`SINCE`, `BEFORE`, `ON`), no `HEADER` lookup, no `KEYWORD` / `UNKEYWORD`. Real clients build SEARCH queries with OR/NOT routinely — many will get spurious NO or empty result sets.

### 2.5 Two dead `mail-auth` wrappers
`crates/auth/src/spf.rs`, `dkim.rs`, `dmarc.rs` each build a fresh `MailAuthResolver::new_cloudflare_tls()` and duplicate what `checker::verify` already does in one pass. None of them are called from the listeners (only `checker::verify` is). `dkim::verify` returns `DkimVerdict::None` on success without actually verifying anything (per its own comment).

**Fix**: delete `spf.rs`, `dmarc.rs`, and the `verify` function in `dkim.rs`. Keep `dkim::sign` (used by outbound delivery). The audit pipeline lives only in `checker.rs`.

### 2.6 DKIM key read from disk on every outbound send
`crates/server/src/delivery.rs:223`:
```rust
let key = match tokio::fs::read(&domain.dkim_key).await { … }
```
Per-message I/O for a key that does not change at runtime. For a domain sending N messages/sec, that's N disk reads/sec for the same 1.7 KB PEM. Cache the parsed `RsaKey<Sha256>` per domain in an `Arc`-shared `HashMap` initialised at startup.

### 2.7 `MailAuthResolver` rebuilt per inbound message
`crates/auth/src/checker.rs:127`:
```rust
let resolver = match MailAuthResolver::new_cloudflare_tls() { … };
```
Every inbound message DATA finalization triggers a new resolver construction. This is also a DNS-over-TLS handshake setup (Cloudflare DoT) → a TLS connection establishment. An attacker who can push the inbound rate up — e.g. by sending many tiny messages to a non-existent user (rejected at RCPT TO before this code, so safe) or to existing locals — multiplies DoT handshakes 1:1.

**Fix**: build the resolver once at startup, store in `Arc<MailAuthResolver>`, share. The TODO comment in the file already flags this.

### 2.8 `is_not_found` for S3 errors uses string matching
`crates/queue/src/lib.rs:587`:
```rust
fn is_not_found(error: &str) -> bool {
    error.contains("NoSuchKey") || error.contains("NotFound") || error.contains("404") || error.contains("not found")
}
```
Fragile. AWS SDK exposes typed `SdkError<GetObjectError>` with `as_service_error()` → `is_no_such_key()`. Use that.

### 2.9 `S3Queue::exists` uses GET instead of HEAD
Every existence check downloads the full object body even when only presence is needed. With 25 MB bodies this is a per-check 25 MB round trip vs. a near-zero HEAD. Use `head_object`.

### 2.10 DNS lookup failure silently re-queues forever
`crates/server/src/delivery.rs:42` returns `MxTargets::LookupFailed` and the calling loop continues without marking the recipient — the qmgr will defer and retry indefinitely (well, until `bounce_after_hours`). This is correct in terms of eventual bounce, but the recipient sees nothing for up to 5 days while DNS is broken. A short-window classifier ("3 transient lookup failures in a row → temporarily mark Failed") would surface problems faster.

### 2.11 Duplicated line-reader code
`smtp_listener.rs` and `imap_listener.rs` have ~30 lines of identical `read_line_limited`. Move to a tiny helper crate or a `pub` function in `rmail-core`.

### 2.12 Documentation drift in HANDOFF / mapping docs
`HANDOFF.md` is truncated at section 9 (`[server] hostname = "mail.example.com"`) but the README references chapters 10+. The `Message` struct shown in §6 still has the simplified shape; the real `Envelope` has `recipients: Vec<Recipient>` with per-recipient status. `docs/postfix-mapping.md` references files that no longer exist at the cited paths (these were inherited from `REVIEW.md`'s findings; check if they have been corrected — appears partial).

### 2.13 Tests cover parsers only
Roughly fifteen tests, all of them targeting `Address::parse`, the SMTP command parser, `Reply::ehlo_caps`, `dot_stuff`, IMAP `Session::new` greeting, `password::roundtrip`. **There are zero integration tests** for the SMTP session state machine end-to-end, the IMAP session end-to-end, the queue under fault injection (process killed mid-rename), or the delivery worker against a fake remote MTA. Given how much state lives in `session.rs`, this is a real gap.

---

## 3 — Security audit

Severity rubric:
- **Critical**: authenticated or unauthenticated attacker can cause data loss / RCE / arbitrary file access in default config.
- **High**: attacker can read mail not addressed to them, redirect mail in transit, or DoS the server cheaply.
- **Medium**: attacker can degrade quality of service, enumerate users, or exploit weak defaults.
- **Low / info**: defense-in-depth gaps, fragile assumptions, hygiene.

### S-1 (Critical) — IMAP path traversal in folder operations

**Where**: `crates/mailbox/src/lib.rs:70` (`Maildir::folder_dir`).

```rust
fn folder_dir(&self, user: &Address, folder: &str) -> PathBuf {
    let base = self.user_dir(user);
    if folder == "INBOX" {
        base
    } else {
        base.join(format!(".{}", folder))
    }
}
```

`folder` comes directly from IMAP commands (`CREATE`, `DELETE`, `RENAME`, `SELECT`, `EXAMINE`, `LIST`, `STATUS`, `APPEND`, `COPY`, `MOVE`) via `unquote(rest)` with **no sanitization** of `/`, `..`, or path separators. The leading `.` is intended as a Maildir++ subfolder marker but only protects against folder names starting with non-`.` characters.

**Concrete exploit** (alice@example.com, authenticated, TLS):

| IMAP command | Resulting filesystem path |
|---|---|
| `CREATE "./../target"` | `<root>/example.com/alice/../../target` = `<root>/target` |
| `CREATE "/foo/../../../etc/rmail"` | `<root>/./foo/../../../etc/rmail` = `<root>/../../etc/rmail` |
| `DELETE "./../../../etc/rmail"` (calls `fs::remove_dir_all`) | recursively deletes `/etc/rmail` if the daemon has permission |

The `DELETE` path is the worst: `fs::remove_dir_all` is recursive and follows the resolved path. Combined with the fact that the daemon **must run as root** to bind ports 25/587/465/143/993 and never drops privileges (see S-2), an authenticated mailbox user can delete arbitrary directories on the host.

The `RENAME` and `COPY/MOVE` paths give arbitrary-write inside the filesystem (subject to user uid permissions, which when root, means everywhere).

**Trust boundary**: any authenticated IMAP user. Provisioning a user is a config-level action, but compromised user credentials (phishing, leak, weak passwords) escalate immediately to host-level filesystem damage.

**Fix**:
1. Reject any folder name containing `..` as a path component, `/`, NUL, control characters, or starting with `.`.
2. Canonicalise the resulting path with `tokio::fs::canonicalize` and assert it has `self.user_dir(user)` as prefix before any I/O.
3. Maildir++ folder names in the IMAP wire are conventionally limited to `[A-Za-z0-9 _.-]` with `.` as hierarchy separator inside the folder name itself. Whitelist this.

The minimum acceptable patch is the canonicalize-and-prefix check; rejecting `..` alone is necessary but not sufficient (symlinks could be planted).

### S-2 (High) — No privilege separation, daemon stays root

The example config binds `0.0.0.0:25`, `:587`, `:465`, `:143`, `:993`. All five are privileged ports on Linux. The daemon must therefore start as root (or be given `CAP_NET_BIND_SERVICE`). `bin/rmail/src/main.rs` never drops privileges, never switches uid/gid after the bind, never chroots, never sets `nobody`-style isolation.

Consequence: everything in §3 — the path traversal, the DKIM key reads, the queue / Maildir I/O, the bincode envelope deserialization — runs with full root authority. There is no defense in depth between an IMAP-session bug and the rest of the system.

**Fix**:
- After bind, drop to a `_rmail` user/group via `setgid` + `setuid` (or use systemd's `User=` + `AmbientCapabilities=CAP_NET_BIND_SERVICE`).
- Make `queue_dir`, `mailbox_dir`, `tls.key` owned by `_rmail` and 0750 / 0640.
- Recommend systemd hardening flags in the docs: `NoNewPrivileges=`, `ProtectSystem=strict`, `ProtectHome=`, `PrivateTmp=`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`.

Until S-1 is patched, S-2 is what turns it from "delete some maildirs" into "delete `/etc/passwd`".

### S-3 (High) — Outbound MX resolution over plain UDP

**Where**: `crates/dns/src/lib.rs:53`–`75`:

```rust
config.add_name_server(NameServerConfig {
    socket_addr: addr,
    protocol: Protocol::Udp,
    tls_dns_name: None,
    tls_config: None,
    …
});
```

The `hickory-resolver` crate is pulled with the `dns-over-rustls` feature enabled in `Cargo.toml` but **not actually used** at runtime — the Cloudflare nameservers are added with `Protocol::Udp` (and `Protocol::Tcp` as TCP fallback for large responses). DNSSEC validation is off by default (`dnssec = false`). The system resolver is bypassed (good intention) but the on-wire DNS lookup is **plaintext UDP to 1.1.1.1**.

Consequence: an on-path attacker (your ISP, a rogue VPN, a malicious WiFi, a state-level adversary) can spoof MX / A / AAAA / TXT responses for arbitrary domains. The effect on outbound delivery:
- Spoofed MX → outbound SMTP connects to attacker-controlled IP → mail content disclosed in transit unless STARTTLS + MTA-STS Required catches it. With opportunistic TLS (the default), the attacker's cert can be self-signed and rmail will still hand over the body. **Plaintext exfiltration of all outbound mail to non-MTA-STS recipient domains is possible.**
- Spoofed `_mta-sts.<domain>` TXT → MTA-STS lookup fails, fallback to opportunistic, same exfiltration path.

Note that `crates/auth/src/checker.rs` uses `MailAuthResolver::new_cloudflare_tls()` for inbound SPF/DKIM/DMARC — that path **is** DoT. So the project already has the building blocks for DoT; it's just inconsistent across modules.

**Fix**: switch `crates/dns/src/lib.rs` to use `Protocol::Tls` with `tls_dns_name: Some("cloudflare-dns.com".into())` and `tls_config: Some(<shared rustls config>)`. Re-validate that hickory's caching still works under DoT.

### S-4 (High) — Existing `Authentication-Results` headers from inbound mail are not stripped

**Where**: `crates/server/src/smtp_listener.rs:298`–`325` (`InboundAuth::prepend_headers`).

rmail prepends its own `Authentication-Results: …` and `Received-SPF: …` headers based on its own SPF/DKIM/DMARC verdict. But it does not remove any `Authentication-Results:` headers that were already present in the message body. An attacker who sends mail to rmail can include a forged `Authentication-Results: mail.example.com; dkim=pass …` line in the body — the rmail-generated header will be **above** it, but downstream MUAs and forwarding MTAs may pick the wrong one (RFC 8601 §5.2 says agents SHOULD trust the topmost header that matches the trust boundary, but implementations vary).

**Fix**: strip any `Authentication-Results:` header whose `authserv-id` matches `config.server.hostname` from the inbound body before prepending. Postfix's `policyd-spf` and Gmail's pipeline both do this.

### S-5 (High) — Inbound DATA buffered in RAM, scales poorly under load

Already covered as §2.1. Filed here because the consequence is a cheap DoS: 1024 simultaneous connections each sending 25 MB at the rate-limited maximum size = 25 GB resident. On a 4 GB VM the OOM killer triggers and kills `rmail` mid-write — which the queue recovery on restart will handle for in-flight messages, but the service is dead until restart.

### S-6 (Medium) — Bounce backscatter possible (SPF-fail does not reject)

**Where**: `crates/auth/src/checker.rs:34`–`40`:

```rust
pub fn should_reject(&self) -> Option<&'static str> {
    if matches!(self.dmarc, DmarcOutcome::Reject | DmarcOutcome::Quarantine) {
        Some("Message rejected due to DMARC policy")
    } else {
        None
    }
}
```

Only DMARC=reject (or quarantine) blocks the message. SPF=fail alone, with no DKIM signature and no DMARC record on the sending domain, lets the message through. If subsequent delivery fails (local mailbox over quota in a future quota implementation, or relayed downstream that bounces), rmail generates a bounce to the spoofed MAIL FROM — sending bounce mail to the victim of the spoof. Classic backscatter.

Today the local-recipient check at RCPT TO time (`config.find_user(&addr.as_str()).is_none() → 550 5.1.1`) limits this because rejection happens before queueing. But once delivery_failure / bounce_after_hours fires, the bounce IS generated and sent to whatever the spoofed MAIL FROM was. Wormholes: when a user is locally provisioned but their `Maildir` is missing on disk, the qmgr marks `Failed` and the bounce generator fires — `MailboxError::UserNotFound`. This is reachable in practice during partial restore from backup.

**Fix**: when `SPF=fail` and the message lacks a passing DKIM signature aligned with the sender domain, reject at DATA time (550 5.7.1) instead of accepting. Configurable via `[inbound] spf_fail_reject = true`.

### S-7 (Medium) — User enumeration via RCPT TO

`crates/smtp/src/session.rs:238`:
```rust
} else if config.find_user(&addr.as_str()).is_none() {
    return Action::Reply(Reply::user_unknown(&addr.as_str()).to_wire());
}
```

Existing users get `250 2.1.5 OK`, unknown users get `550 5.1.1 User unknown`. The semantics are RFC-compliant but an attacker can iterate the local-part dictionary and learn which addresses exist before AUTH. Combined with weak passwords this accelerates credential stuffing — though `dummy_password_hash` protects against AUTH-time enumeration.

**Fix**: optional `[inbound] accept_unknown_recipients = true` mode that accepts the RCPT TO and bounces later, the way `qmail` does. Or: hard rate-limit on 550 5.1.1 responses per IP.

### S-8 (Medium) — `DANE = true` is a placebo

`crates/server/src/delivery.rs:150`–`153`:
```rust
if config.outbound_tls.dane {
    policy.require_starttls = true;
}
```

The flag exists in config and only forces `require_starttls = true`. **No TLSA records are fetched, no certificate verification against TLSA hashes is performed.** Operators enabling `dane = true` will believe they have DANE protection; they have opportunistic-TLS-as-required, which is strictly weaker than DANE.

**Fix (short term)**: rename the flag to `require_outbound_tls` or remove it from the config until properly implemented. Misleading config is worse than missing config.

**Fix (long term)**: implement RFC 7672 (SMTP DANE): query `_25._tcp.<mx-hostname>` TLSA records, validate the certificate chain against the TLSA hash. Requires DNSSEC (i.e. the resolver must validate, hence requires `validate = true` AND DoT/DoH to a validating resolver). This unblocks S-3 too.

### S-9 (Medium) — Authentication rate-limiting is per-IP only

`crates/server/src/smtp_listener.rs:36`: `per_ip: Mutex<HashMap<IpAddr, usize>>` caps simultaneous connections per IP (default 32). There is **no rate limit per username**. A distributed brute-force from many IPs against a single account is not throttled; argon2id verification time is the only barrier (~80 ms with default params), which means ~12 attempts/sec from each attacker IP × N attackers = thousands of attempts/sec.

**Fix**: keep a sliding-window counter per `auth_user` candidate (failed attempts in the last 5 min), reject AUTH with 535 5.7.0 + tarpit delay after threshold.

### S-10 (Medium) — S3 credentials in cleartext config

`crates/config/src/lib.rs:65`:
```rust
pub struct S3StorageConfig {
    pub access_key_id: String,
    pub secret_access_key: String,
    …
}
```

The TOML file holds raw AWS credentials. No env-var substitution (`${RMAIL_S3_SECRET}`), no AWS profile / IMDS / EC2 instance role / web-identity support. The `tls.key` path is similar but at least keyfiles can be permission-protected; cleartext credentials in a TOML often end up in operator dotfiles, ansible repos, and screen recordings.

**Fix**: support `aws_credential_types::Credentials::from_env()` and the standard AWS provider chain (`aws-config` already does this); accept `access_key_id = "${RMAIL_AWS_KEY_ID}"` as expansion.

### S-11 (Medium) — Config file not permission-checked

`Config::load` calls `std::fs::read_to_string(path)` without inspecting the mode. A world-readable `rmail.toml` leaks user password hashes (recoverable via argon2 cracking) and S3 credentials. There is no warning logged.

**Fix**: on load, `stat()` the file; if mode is world-readable (`mode & 0o004`), warn loudly. If group-readable, warn unless the group is `_rmail`.

### S-12 (Medium) — DKIM signing does not over-sign or oversigned-headers protection

`crates/auth/src/dkim.rs:62`–`70`: signs `From / To / Subject / Date / Message-ID / MIME-Version / Content-Type` with single-coverage (`h=` count = 1). An attacker who can inject duplicate `From:` headers (e.g., through a vulnerable forwarder downstream) could add a forged `From:` above the signed one — the signature still passes (it covers the bottom one) but MUAs display the top one.

**Fix**: enable `oversign` for `From`, `Subject`, `Reply-To`, `Sender` in `DkimSigner` — `mail-auth` exposes this.

### S-13 (Low) — `Address::parse` does not reject control characters

`crates/core/src/lib.rs:69`–`97`: validates only the angle-bracket balance, the `@` presence, and non-empty local/domain. Does not reject `\r`, `\n`, NUL, or other control characters in `local` or `domain`.

In practice, the SMTP line reader splits on `\n` and the command parser rejects bare CR/LF before this code is reached, so an attacker over the wire cannot inject these via MAIL FROM / RCPT TO. **However**, addresses also enter the system from:
1. Config file (`Config::load` → `validate`): an operator who pastes a malformed address with embedded CR/LF passes validation.
2. Queue body deserialization (bincode-decoded `Envelope.from`): a queue dir compromised at the file-system level can inject anything.

Both are out-of-band trust boundaries, but defense in depth is cheap. Reject CR / LF / NUL / `;` / `,` in local-part. Restrict domain-part to `[A-Za-z0-9.-]` + IDNA punycode.

### S-14 (Low) — `bincode = "1"`

bincode 1.x has known DoS vectors against malicious size hints (large `Vec<T>` headers). The queue dir is server-only and not network-reachable, so the trust boundary is filesystem-level. Still, the upgrade to bincode 2.x (which has explicit configuration of size limits per deserialization) is mechanical.

### S-15 (Low) — Password not zeroized after hashing in rmailctl

`bin/rmailctl/src/main.rs:246`: `let password = prompt_password(…)?;` → `let hash = …::hash(&password)?;` — `password: String` remains in memory after hashing until process exit. The process is short-lived, so the window is small, but a core dump during this window would contain the plaintext.

**Fix**: use the `zeroize` crate and `Zeroizing<String>`.

### S-16 (Low) — No SMTP `RCPT` rate limit per session

A single SMTP session can issue 100 RCPT TO commands (`MAX_RCPTS = 100`). A spammer doing 100 RCPT × N connections × M ms/RCPT is a tarpit-friendly attack vector. Today rmail responds quickly (no tarpit). Considering tarpit pacing for >10 RCPT/session is standard practice.

### S-17 (Low) — VRFY returns 252 always (info disclosure prevention works)

`crates/smtp/src/session.rs:154`: `Reply::new(252, "2.1.5 Cannot VRFY user")`. RFC 5321 §3.5.3 permits this exact response. ✓ No fix needed. Logged here for completeness.

### S-18 (Low) — Resource exhaustion via slow DATA

A peer can send DATA at one byte every 299 seconds and reset the read timeout. Per session this can keep a permit alive for `25 MB × 299s` ≈ 230 years. With 32 connections from a single IP this is 32 permits held indefinitely.

Today the global `MAX_CONNECTIONS = 1024` and per-IP cap (32) limit the impact, but a 32-IP botnet from a single ASN gets 1024 / 32 = 32 ASNs to fully starve the listener. Worth a per-message wall-clock timeout (e.g. 30 minutes from MAIL FROM to final dot).

### S-19 (Info) — No anti-virus / anti-spam scanning hooks

rmail accepts all content that passes SPF/DKIM/DMARC and size limits. There is no policy daemon, no SpamAssassin / Rspamd integration, no `header_checks` / `body_checks` à la Postfix. This is explicitly out of HANDOFF scope but worth flagging — for production deployment, expect to need either a milter-style interface or a content-policy callback.

### S-20 (Info) — No fuzzing harness

Parsers are hand-written nom (SMTP commands) and hand-rolled (IMAP commands, sequence sets, IMAP literals). These run on attacker-controlled input. None of them has a `cargo fuzz` corpus checked into the repo. Adding `cargo-fuzz` targets for `smtp::command::parse`, `imap::command::parse`, `parse_sequence_set`, `parse_uid_set`, and `tokenize_imap_args` would catch panics and silent mis-parses before they ship.

### S-21 (Info) — Argon2 default parameters

`crates/auth/src/password.rs:21`: `Argon2::default()` produces `argon2id v=19 m=19456 (≈19 MB) t=2 p=1`. These are OWASP's minimum recommendations as of 2024 and adequate for interactive logins. For higher assurance (operator master passwords, postmaster accounts), bump to `m=131072 t=4 p=2`. Currently uniform across all users.

---

## 4 — Recommended remediation priorities

```
P0 (do before any real deployment):
  • S-1  IMAP folder-name path traversal — canonicalise + prefix check
  • S-2  Drop privileges after bind; ship a hardened systemd unit
  • S-3  Switch crates/dns to DoT (Protocol::Tls), share resolver with mail-auth
  • §2.1 Stream DATA to disk, stop buffering full bodies in RAM

P1 (next sprint):
  • S-4  Strip our-own Authentication-Results from inbound body before prepending
  • S-7  Resolver cache: share Arc<MailAuthResolver> across all inbound sessions
  • §2.6 Cache parsed DKIM keys per domain (RsaKey<Sha256>) in Arc<RwLock<…>>
  • S-6  Reject at DATA on SPF=fail (configurable, default-on)
  • §2.2 Fix IMAP UID generation: per-mailbox uidnext file, atomic increment
  • S-9  Per-username AUTH failure rate limit
  • §2.13 Add SMTP / IMAP / queue integration tests (smoke + crash injection)

P2 (quality of life):
  • S-8  Either implement RFC 7672 DANE properly, or remove the flag
  • §2.3 Real BODYSTRUCTURE via mail-parser
  • §2.4 IMAP SEARCH: OR / NOT / parentheses / date criteria
  • S-10/S-11 Config: env-var expansion + permission check
  • S-12 DKIM oversign for From/Subject/Reply-To/Sender
  • §2.5 Delete dead spf.rs / dmarc.rs / dkim::verify wrappers
  • §2.9 S3 exists() → head_object
  • §2.8 S3 errors via typed SDK error variants
  • S-20 Fuzz harnesses for the four parsers

P3 (polish):
  • S-13 Reject control chars in Address::parse
  • S-14 bincode 1 → 2
  • S-15 zeroize passwords in rmailctl
  • S-16 RCPT tarpit
  • S-18 Per-message wall-clock timeout
  • §2.12 Sync HANDOFF.md + docs/postfix-mapping.md to current code layout
```

---

## 5 — Test coverage gap (concrete proposal)

Today: 15 unit tests, parsers + ehlo + greeting + dot-stuff + hash.

Minimum bar to call this beta:
- **SMTP session integration**: spin up `TcpListener` in a test, run a real socket through HELO → STARTTLS (with self-signed cert) → AUTH → MAIL → RCPT (accepted + rejected) → DATA (dot-stuffed, dot-stuffed-edge, max-size) → QUIT. ~10 scenarios.
- **IMAP session integration**: same shape — login + LIST + SELECT + APPEND (with literal) + FETCH (with BODY[]) + STORE + EXPUNGE + COPY + LOGOUT. ~12 scenarios.
- **Queue crash injection**: `tokio::fs::write` shim that fails after N bytes, asserts recovery moves orphans to `corrupt/` and never loses an `.env` whose `.eml` exists.
- **Delivery worker against a mock MTA**: a `TcpListener` in the test that speaks SMTP back. Test 4xx/5xx/timeout/STARTTLS-fallback/MX-priority-fallover.
- **Path-traversal regression**: once S-1 is fixed, lock it down with explicit tests.

These tests are not optional for a daemon that holds people's mail.

---

## 6 — Verdict

`rmail` is the kind of project that's a small number of pull requests away from being safely deployable for a single-person or small-team mail setup, and a larger but still bounded number of PRs away from being suitable for a 100-user team. The architectural choices are right; the rust hygiene is high; the queue is correct.

**Do not deploy on the public internet today** until S-1, S-2, S-3, and §2.1 are addressed. After that, it's a real, well-engineered mail engine.

— end of handoff
