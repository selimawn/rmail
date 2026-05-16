# rmail — full review (branch `review-fullOpus`)

Date: 2026-05-16 · Reviewer: full read of every `.rs`, `.toml`, doc, workflow, plus `cargo build`, `cargo test`, `cargo clippy`, `cargo fmt --check`.

## TL;DR

- **Builds clean.** No warnings, clippy passes, fmt clean, 28 unit tests pass.
- **But there are two parallel implementations of the SMTP listener and the CLI** — one wired in, one dead-but-checked-in. The dead ones reference functions and types that do not exist (`SmtpSession`, `RcptCheck`, `Reply::greeting`, `hash_password`, `verify_password`, …). They are not in any `mod` declaration so the workspace still compiles — but they will mislead any future reader, and on the day someone wires them in, the build breaks. **This is the single biggest coherence problem in the repo.**
- **Two production-blocking security issues:**
  1. Unbounded line reads on every listener — straightforward OOM DoS.
  2. No I/O timeouts anywhere — a single slow-loris client can sit on one of the 1024 connection permits indefinitely.
- **The IMAP server is closer to a demo than a server.** UIDs are FNV hashes of filenames (non-monotonic, can collide), `UIDVALIDITY` is hardcoded to `1`, `INTERNALDATE` is hardcoded to `01-Jan-2024`, `FETCH BODY[]` corrupts non-UTF-8 bytes (= every attachment), `STORE` ignores every flag except `\Deleted`, `APPEND`/`COPY`/`MOVE`/`CREATE`/`DELETE`/`RENAME` are not implemented, literals (`{n}`) are not parsed, `SEARCH` understands six one-word criteria. Real clients (Thunderbird, Apple Mail, Outlook) will silently corrupt mailboxes against this implementation.
- **Auth pipeline only half-applied.** SPF / DKIM / DMARC results are computed and used for a reject decision, but the `Authentication-Results:` and `Received-SPF:` headers are never inserted into the message body. DMARC `quarantine` is silently treated as pass. FCrDNS is implemented but never called.
- The on-disk **queue is solid** — atomic two-rename commit protocol, fsync on the parent dir, sane recovery sweep. Best part of the codebase.
- The **outbound SMTP client is mostly OK** but has no per-command timeouts, no DANE/MTA-STS (so any active attacker can downgrade to plaintext), and a small dot-stuffing trailer bug.

---

## 0 — Build & test state

```
cargo build --workspace      → ok, no warnings
cargo clippy --workspace --all-targets → ok, no warnings
cargo fmt --all -- --check   → ok
cargo test --workspace       → 28 passed, 0 failed, 1 doc-test ignored
```

Test coverage is low: SMTP command parser, SMTP reply formatter, address parser, dot-stuff, IMAP greeting, password hash roundtrip. No tests for the IMAP command parser, no integration tests for either session state machine, nothing for the queue, nothing for the maildir, nothing for delivery.

---

## 1 — Dead code & coherence (CRITICAL)

These are not compiled today, but they exist in `src/` and will compile-fail the day someone adds them to a `mod` declaration.

### 1.1 `crates/server/src/smtpd.rs` — broken alternate SMTP listener
- `crates/server/src/lib.rs:1` declares `bounce cleanup delivery imap_listener queue_manager smtp_listener`, **not `smtpd`**.
- `smtpd.rs` imports `tokio`, `tracing`, `rmail_smtp` items (`SmtpSession`, `RcptCheck`, `StepResult`, `SessionState`), and calls `Reply::greeting()`, `Reply::ok(format!())`, `session.tls_upgraded()` — **none of which exist** in the current `rmail_smtp` crate.
- Confirmed by running `rustc` on the file: 30+ errors before the imports even resolve.
- **Fix:** delete `crates/server/src/smtpd.rs`. The real listener is `smtp_listener.rs`.

### 1.2 `bin/rmailctl/src/cmd/*` — broken alternate CLI
- `bin/rmailctl/src/main.rs` is the active entrypoint and defines its `Cmd`/`DomainCmd`/`UserCmd`/`QueueCmd` enums inline. It does **not** `mod cmd;`.
- `bin/rmailctl/src/cmd/mod.rs`, `domain.rs`, `user.rs`, `queue.rs` are an unused parallel implementation.
- `cmd/user.rs:5` imports `rmail_auth::password::{hash_password, verify_password}` — the actual names in `crates/auth/src/password.rs` are `hash` / `verify`. Compile fail if wired up.
- `cmd/domain.rs:64–66` has a temporary-lifetime bug:
  ```rust
  .unwrap_or(&format!("dmarc@{}", name))
  ```
  `&format!(...)` produces a reference to a `String` that is dropped at end of statement — UB at best, borrow-check fail at worst.
- **Fix:** delete `bin/rmailctl/src/cmd/` entirely, or wire it up and delete the inline implementation in `main.rs`. Pick one.

### 1.3 `crates/auth/src/{spf,dkim,dmarc}.rs` — stubs that duplicate `checker.rs`
- `checker::verify()` does the full SPF + DKIM + DMARC pipeline in one resolver call.
- `spf::verify()`, `dkim::verify()`, `dmarc::evaluate()` each build a **separate** `MailAuthResolver` and run *the same* lookups again.
- `dkim::verify` returns `DkimVerdict::None` on success without actually verifying anything (per its own comment line 39: "use checker::verify for full DNS-based verification").
- Nothing in the project calls these standalone entry points. They are dead.
- **Fix:** delete them, or rewrite them as thin wrappers around `checker`. Right now they pretend to be useful APIs and aren't.

### 1.4 `HANDOFF.md` and `docs/postfix-mapping.md` point to nonexistent paths
- `docs/postfix-mapping.md:11` says `smtpd` lives at `crates/server/src/smtpd/listener.rs`. Reality: `crates/server/src/smtp_listener.rs`.
- `docs/postfix-mapping.md:13` says `smtp` (outbound) lives at `crates/server/src/delivery/worker.rs`. Reality: `crates/server/src/delivery.rs`.
- `docs/postfix-mapping.md:14` says `local` lives at `crates/mailbox/src/deliver.rs`. Reality: it's a method on `Maildir` in `crates/mailbox/src/lib.rs`.
- `docs/postfix-mapping.md:17` says `trivial-rewrite` lives at `crates/core/src/address.rs`. Reality: address is inside `crates/core/src/lib.rs`.
- `HANDOFF.md:9` and §4 layout treat the project as in design phase, but the project compiles and runs — the doc never says "alpha" or "implemented", and §6 shows a `Message` struct (`from`, `to`, `recipients`) that no longer matches the real `Envelope` in `crates/core/src/lib.rs` (which has `recipients: Vec<Recipient>` with per-recipient status).
- **Fix:** rewrite both docs against the real layout, or delete the stale tables.

### 1.5 Two `prepend_received` implementations
- `crates/smtp/src/session.rs:417` `prepend_received()` — used.
- `crates/server/src/cleanup.rs:11` `add_received_header()` — different signature, **never called**.
- **Fix:** delete `cleanup.rs` (the cleanup-as-a-step idea was inherited from Postfix mapping but the inbound session already does it inline) or move the helper to one place and reuse it.

---

## 2 — Security (CRITICAL)

### 2.1 Unbounded line read — direct OOM DoS
`crates/server/src/smtp_listener.rs:89`, `:175`; `crates/server/src/imap_listener.rs:80`, `:142`:
```rust
let n = io.read_until(b'\n', &mut line).await?;
```
`AsyncBufReadExt::read_until` has no length cap. If a peer sends 50 GB of bytes with no `\n`, the `Vec<u8>` grows to 50 GB before the SMTP `MAX_LINE = 1000` check at `crates/smtp/src/session.rs:93` even runs.

The `MAX_LINE` check in `session.rs` is misplaced — it can only catch lines that *did* terminate. To stop the actual abuse you need either:
- `AsyncBufReadExt::take(MAX_LINE+1).read_until(b'\n', ...)`, or
- a manual loop reading at most `MAX_LINE+1` bytes.

This is the same bug in IMAP, which has *no* per-line cap at all (`MAX_LINE` only exists for SMTP).

**Severity: critical.** Two TCP connections (one per listener) put the daemon into OOM-kill.

### 2.2 No I/O timeouts — slow-loris
Nowhere in `smtp_listener`, `imap_listener`, `smtp::client`, `tls` does any read or write have a deadline. (The `TlsAcceptor::accept` and outbound `TlsConnector::connect` have a 10 s handshake timeout — good — but everything *after* the handshake is unbounded.)

A peer that opens a TCP connection and sends nothing holds one of the `Semaphore::new(MAX_CONNECTIONS=1024)` permits forever. 1024 IPs DoS the server. Same for clients that send one byte every minute.

**Fix:** wrap each `read_until` and `write_all` in `tokio::time::timeout(read_idle, ...)`. Recommended: 5 min between commands (RFC 5321 §4.5.3.2.7 says servers SHOULD allow 5 min between commands and 10 min between DATA chunks).

### 2.3 IMAP `FETCH BODY[]` corrupts every non-ASCII attachment
`crates/imap/src/session.rs:377–393`:
```rust
parts.push(format!(
    "{} {{{}}}\r\n{}",
    label,
    body.len(),
    String::from_utf8_lossy(&body)
));
```
`String::from_utf8_lossy` replaces every invalid byte with `U+FFFD` (3 bytes in UTF-8) and forces UTF-8. As soon as a message contains a binary attachment (every PDF, every image, every signed S/MIME envelope) the IMAP literal:
- has wrong byte count (`body.len()` is the original, the string is longer or shorter)
- has different bytes than what's on disk

The client parses the literal length, reads that many bytes, gets out of sync with the IMAP framing, and the session breaks.

**Severity: critical for usability.** Anything beyond ASCII text mail is broken.

**Fix:** stop building responses with `format!`. Use a `Vec<u8>` writer and `extend_from_slice(&body)` for literal bodies. Same applies to `Rfc822Header` and `Envelope`.

### 2.4 STARTTLS does not discard pre-handshake state (per RFC 3207 §4.2)
`crates/smtp/src/session.rs:382-385`:
```rust
pub fn mark_tls_active(&mut self) {
    self.tls_active = true;
    self.state = State::Connected;
}
```
RFC 3207 §4.2: "the SMTP server MUST discard any knowledge obtained from the client … which was not obtained from the TLS negotiation itself." We do *not* reset `helo`, `from`, `rcpts`, `auth_user`, or `body_buf`. (We can't have auth pre-TLS so `auth_user` is fine, but the others all leak.)

Also: the pre-TLS BufReader buffer is dropped via `into_inner()` (good — kills STARTTLS-injection of pipelined commands), but the code never explicitly checks the buffer is empty. RFC 3207 implies that any buffered data after `STARTTLS\r\n` should be **rejected, not dropped**. A correct implementation aborts the connection if data remains in the buffer at upgrade time.

**Fix:** in `mark_tls_active`, call `reset_transaction()` and clear `helo`. In the listener, before `io.into_inner()`, peek the buffer (`io.buffer().is_empty()`) and close the connection if not.

### 2.5 DMARC `quarantine` is silently accepted as pass
`crates/auth/src/checker.rs:33–41`:
```rust
pub fn should_reject(&self) -> Option<&'static str> {
    if self.dmarc == DmarcOutcome::Reject { … } else { None }
}
```
A message with `DmarcOutcome::Quarantine` returns `None` → the listener enqueues it normally → it goes into `INBOX`, not `Junk`. So `p=quarantine` policies are ignored.

**Fix:** either move quarantined mail to `.Junk` at local-delivery time, or also reject. Today's behavior tells the world we honor DMARC when we don't.

### 2.6 `Authentication-Results:` header never written
`crates/auth/src/checker.rs:21-31` defines `AuthResults::header()`. It returns a `String`. Nothing in the codebase calls it. The function is dead.

Downstream IMAP clients have no way to see SPF/DKIM/DMARC results — those headers are how mail clients display the green "verified" lock. Per RFC 8601, an MTA that performs auth checks MUST add the `Authentication-Results:` field (when the receiving administrative domain wants its results visible).

**Fix:** in `smtp_listener::should_reject_inbound` (which already runs `checker::verify`), pass the result up; before `queue.enqueue(envelope, body)`, prepend `Authentication-Results: <result>\r\n` to `body`. While there, prepend `Received-SPF:` too.

### 2.7 FCrDNS implemented but never invoked
`crates/auth/src/fcrdns.rs` is a complete, working FCrDNS checker. **No caller**. Big mail receivers (Gmail, Outlook) reject mail from peers without forward-confirmed reverse DNS. To accept mail at parity we should run the check and add `iprev=` to `Authentication-Results`.

**Fix:** call it from `smtp_listener::accept_loop` after `listener.accept()`; cache result for the session; include in `Authentication-Results`.

### 2.8 Password verification — no constant-time short-circuit on "user not found"
`crates/smtp/src/session.rs:397-411`:
```rust
let cfg_user = config.find_user(user)?;            // ← returns immediately
if rmail_auth::password::verify(pass, &cfg_user.password_hash) { … }
```
When the user doesn't exist, `find_user` returns `None` and we skip the argon2 verification entirely. Argon2 verify takes ~50 ms; `find_user` is sub-microsecond. A timing attacker can enumerate valid usernames trivially.

**Fix:** always run argon2 verify against a known-bad reference hash when the user is missing.

### 2.9 RCPT enumeration leak
`crates/smtp/src/session.rs:226-229`: returns `550 User unknown` on missing user vs `250` on accepted. Standard `VRFY`-style probing leak — but at least `VRFY` itself returns 252. Either rate-limit RCPTs per IP, or accept all RCPTs and bounce in the queue. Tracking issue, not a fix-now.

### 2.10 SASL PLAIN authzid is ignored
`crates/smtp/src/session.rs:397-411`:
```rust
let parts: Vec<&[u8]> = raw.splitn(3, |&b| b == 0).collect();
…
let user = std::str::from_utf8(parts[1]).ok()?;   // authcid
let pass = std::str::from_utf8(parts[2]).ok()?;
```
RFC 4616 §2: if authzid is non-empty and ≠ authcid, the server MUST verify the authcid is authorized to act as authzid. We ignore authzid entirely. The MAIL FROM spoofing check at `session.rs:184-196` mitigates the practical exploit (the auth_user we record is authcid, so MAIL FROM must match it), but the principle is broken and a future regression in the MAIL FROM check would expose it.

**Fix:** reject AUTH PLAIN with non-empty authzid that doesn't match authcid.

### 2.11 IMAP `LOGIN` accepts password tokenised by `split_whitespace`
`crates/imap/src/command.rs:278-281`:
```rust
fn tokenize_imap_args(s: &str) -> impl Iterator<Item = &str> {
    s.split_whitespace().map(|t| t.trim_matches('"'))
}
```
A password that contains a literal space cannot be transmitted. Worse, a password that contains a `"` will be silently mutilated. And there's no support for IMAP literals (`LOGIN "user" {12}\r\n<12 bytes>`), which is the canonical way to send a password with quotes or non-ASCII.

**Fix:** parse IMAP arguments per RFC 9051 §4.3 — atoms, quoted strings (with `\"` escape), and literals `{n}`.

### 2.12 No rate limiting per IP, no slow-down on failed auth
A single IP can drive thousands of failed `AUTH PLAIN` attempts/sec until the box CPU dies (argon2 is the hot path now and intentionally slow). Need at least a per-IP failure counter with exponential backoff or temp-ban.

### 2.13 Outbound SMTP — no DANE / MTA-STS
`crates/smtp/src/client.rs:82-122`: if the remote MX advertises STARTTLS we upgrade with opportunistic policy. If it doesn't advertise STARTTLS, we deliver in plaintext. If the cert is invalid we abort STARTTLS and fall back to *unprotected* plaintext (line 113: "STARTTLS fallback requires reconnect" — actually returns an error, but the calling delivery worker treats that as a transient failure and retries, possibly via a different MX — no policy enforcement).

An active attacker can strip STARTTLS from the EHLO response and intercept all outbound mail in cleartext. This is the entire point of MTA-STS (RFC 8461) and DANE (RFC 7672). Neither is implemented.

**Fix:** at minimum, look up `_mta-sts.<domain>` and `_smtp._tls.<domain>` (TLSRPT) and apply policy. DANE requires DNSSEC validation, which our resolver supports via `validate: bool`, but it's off by default.

### 2.14 Outbound SMTP — no `\r\n` normalisation
`crates/smtp/src/client.rs:193-195`:
```rust
let stuffed = dot_stuff(body);
io.write_all(&stuffed).await?;
io.write_all(b"\r\n.\r\n").await?;
```
If the on-disk body ends with `\r\n`, this writes `…\r\n\r\n.\r\n` — a spurious blank line before the dot. Many recipients tolerate it, some don't. Worse, if the body has bare `\n` line endings (because some upstream tool delivered them that way), the dot-stuffing and the trailer are inconsistent.

**Fix:** before sending, normalize body to CRLF; then write body, then write `b".\r\n"` only after confirming body ends with `\r\n`.

### 2.15 Logging is a PII bucket
Many `info!` calls record peer IP + authenticated user (`crates/smtp/src/session.rs:314, 359, 365`; `crates/imap/src/session.rs:165, 169`). Plus password-related events log the username on failure. GDPR-relevant. Not a code-correctness bug, but worth a config switch and a 30-day rotation policy.

---

## 3 — IMAP correctness (HIGH)

The IMAP server compiles, accepts connections, and responds to a narrow happy-path. Beyond that:

### 3.1 UIDs are FNV hashes — violates IMAP4rev2 §2.3.1.1
`crates/imap/src/session.rs:664-671`:
```rust
fn uid_for_filename(filename: &str) -> u32 {
    let mut hash: u32 = 2_166_136_261;
    for b in filename.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(16_777_619);
    }
    hash.max(1)
}
```
RFC 9051 §2.3.1.1: "Unique Identifiers (UIDs) are assigned in a **strictly ascending fashion** in the mailbox; as each message is added to the mailbox it is assigned a higher UID than the message(s) which were added previously." FNV doesn't satisfy this. Worse:
- 32-bit FNV collisions are common at scale.
- `next_uid` = `max(existing UIDs) + 1` (line 655-662). On collision two messages share a UID. On bounded hash space, eventual wraparound.

Every IMAP client that uses UIDs for incremental sync (Thunderbird, Apple Mail, Outlook, mobile mail apps, mbsync) caches `(UID, hash-of-headers)` to know what's new. With non-monotonic UIDs:
- Cached UID `12345` after server restart may map to a different message (a different filename now hashes to `12345`).
- Newly delivered messages may have UIDs *lower* than older messages → client thinks "nothing new".

### 3.2 `UIDVALIDITY` is the literal `1`
`crates/imap/src/session.rs:226, 298`:
```rust
out.extend(Response::ok("*", "[UIDVALIDITY 1] UIDs valid").to_wire());
…
StatusItem::UidValidity => "UIDVALIDITY 1".into(),
```
Clients use UIDVALIDITY to detect "the mailbox has changed, throw out my cache". Pinning it to 1 means *any* server-side change to UID assignment will silently corrupt every client cache without notification.

**Fix:** persist a per-mailbox UIDVALIDITY (e.g. unix timestamp at creation) into a `.uidvalidity` file in the maildir.

### 3.3 `INTERNALDATE` is hardcoded
`crates/imap/src/session.rs:375`:
```rust
parts.push("INTERNALDATE \"01-Jan-2024 00:00:00 +0000\"".into());
```
Every message has the same internal date — date sorting in clients is broken. `INTERNALDATE` should come from the maildir filename timestamp (the `<unix-ts>` prefix) or the file mtime.

### 3.4 `STORE` only handles `\Deleted`
`crates/imap/src/session.rs:430-481`: `do_store` checks `flags.iter().any(|f| f == "\\Deleted")` and ignores every other flag. Marking a message as read in any IMAP client does nothing on disk. Marking as starred does nothing. Marking as draft does nothing. And there's no distinction between `+FLAGS`, `-FLAGS`, `FLAGS` (replace).

### 3.5 `APPEND`, `COPY`, `MOVE`, `CREATE`, `DELETE`, `RENAME`, `SUBSCRIBE`, `UNSUBSCRIBE`, `LSUB`, `IDLE` (real), `AUTHENTICATE`
- `APPEND` returns `NO APPEND not implemented` (`session.rs:144-146`). This breaks saving sent mail and drafts.
- `COPY`, `MOVE`, `CREATE`, `DELETE`, `RENAME` not in the `Command` enum at all → `BAD Command parse error`.
- `AUTHENTICATE` not implemented — the capabilities string advertises `AUTH=PLAIN AUTH=LOGIN` (line 79-85) which refer to SASL mechanisms via `AUTHENTICATE`. Clients trying SASL get `BAD Command parse error`.
- `IDLE` returns `+ idling` as an *untagged* (`* + idling`) response (`session.rs:140`), which is malformed. Per RFC 9051 §6.3.13 the response is the bare continuation `+ idling\r\n` (no `*`).
- Capabilities advertise `LITERAL+` and `UIDPLUS` but the parser doesn't support literals at all.

### 3.6 IMAP literal syntax (`{n}` and `{n+}`) not parsed
`crates/imap/src/command.rs` parses commands by `splitn(3, ' ')`. There's no recognition of `LOGIN user {12}\r\n<12 bytes>` or `APPEND INBOX {2048}\r\n<2048 bytes>`. Real clients send literals for anything non-trivial; rmail will respond `BAD` to all of them.

### 3.7 `SEARCH` understands six criteria
`crates/imap/src/session.rs:531-552`: only `ALL`, `UNSEEN`, `SEEN`, `FLAGGED`, `UNFLAGGED`, `DELETED`. Unknown criteria match *every* message:
```rust
_ => true, // unknown criteria → match all
```
A client searching for `FROM "boss"` gets every message. A client searching for `BCC "spy"` gets every message. Privacy leak waiting to happen.

### 3.8 `LIST` ignores reference and pattern
`crates/imap/src/session.rs:233-265`: returns every folder regardless of arguments. RFC 9051 §6.3.9 specifies pattern matching with `*` and `%`.

### 3.9 `DONE` accepted outside IDLE
`crates/imap/src/session.rs:57-59`:
```rust
if line_str.eq_ignore_ascii_case("DONE") {
    return Action::Reply(Response::untagged("OK IDLE terminated").to_wire());
}
```
This fires whether or not the client is in IDLE. And the response shape is wrong — successful IDLE completion is a tagged `OK` on the original IDLE tag, not an untagged.

### 3.10 `SELECT` always reports `READ-WRITE` and moves `new/` → `cur/`
- `crates/imap/src/session.rs:227`: always tags `[READ-WRITE]`. `EXAMINE` should be read-only — the dispatch maps both to `do_select` (`session.rs:107-109`).
- `session.rs:202-211`: SELECT silently `move_to_cur`'s every new/ message, marking them as `\Seen`. Per RFC 9051 §7.5.1, messages in `\Recent` should appear in `new/` until the *next* SELECT — that's how `\Recent` works. Marking them seen on SELECT is wrong.

### 3.11 `FETCH ENVELOPE` is a fixed template
`session.rs:687-700`:
```rust
format!("(\"{}\" \"{}\" ((NIL NIL \"{}\" NIL)) NIL NIL ((NIL NIL \"{}\" NIL)) NIL NIL NIL \"{}\")",
        date, subject, from, to, msg_id)
```
- Header values are inserted raw into IMAP quoted strings without escaping `"` or `\`. Any subject containing a quote breaks the parse.
- ENVELOPE structure is fixed-shape regardless of actual headers (reply-to, cc, bcc, sender, in-reply-to all forced to `NIL`).
- Header value extraction is `header_value()` (line 702-711), a one-line-only matcher — folded headers (RFC 5322 §2.2.3) are truncated at the fold.

### 3.12 `BODY[]`, `BODY.PEEK[…]`, structure
- Only `BODY[]` and `BODY.PEEK[any]` are routed; both return the whole body.
- `BODY[HEADER.FIELDS (From To)]`, `BODY[TEXT]`, `BODY[1]`, `BODY[1.MIME]` — all return whole body.
- `BODYSTRUCTURE` not implemented — clients that show attachment summaries before downloading them are broken.

### 3.13 `STATUS RECENT` is wrong
`session.rs:296`: `StatusItem::Recent => format!("RECENT {}", unseen)` — uses the unseen count for the recent count. They're independent IMAP flags.

### 3.14 LSUB / SUBSCRIBE / UNSUBSCRIBE missing
Many older clients still expect them.

---

## 4 — SMTP correctness (HIGH)

### 4.1 No `ENHANCEDSTATUSCODES` advertised, but used
EHLO caps don't list `ENHANCEDSTATUSCODES`; reply lines use `2.0.0`, `5.7.1`, etc. Clients that don't see the capability may not parse the codes. Add it to `Reply::ehlo_caps`.

### 4.2 No `PIPELINING` advertised
Optional; cosmetic perf hit on large recipient lists.

### 4.3 No `CHUNKING` (BDAT); optional, fine.

### 4.4 `MAX_LINE = 1000` includes CRLF — checking against the raw line that *includes* CRLF
RFC 5321 §4.5.3.1.6 specifies max 1000 octets including the trailing CRLF. The check is `line.len() > MAX_LINE` which is correct only if `line` has CRLF. `read_until(b'\n')` includes the `\n` but might be missing `\r` (if the client sent bare LF) — that's a 999-octet check, but no big deal. The bigger problem is §2.1 (unbounded read before the check).

### 4.5 Bare `LF` is silently accepted as a line ending
`session.rs:257`: `if line == b".\r\n" || line == b".\n" || line == b"."`. SMTP requires CRLF; bare LF is a long-standing source of SMTP smuggling vulnerabilities (CVE-2023-51764, CVE-2023-46604, etc.). Postfix's default since 2024 rejects bare LF in DATA.

**Fix:** in DATA mode, reject any line whose terminator is not CRLF (4xx temp error or hard-close). Outside DATA, similarly reject bare LF commands.

### 4.6 No SMTP-Smuggling (CVE-2023-51764) defenses
The DATA termination check accepts `.\n` (line 257) — exactly the unsafe form that was exploited in the December 2023 SMTP smuggling round. Even sites that "only" accept LF-terminated dots got compromised.

### 4.7 `MAIL FROM` SIZE parser silently truncates on overflow
`crates/smtp/src/command.rs:115`: `n.parse().unwrap_or(0)` — a `SIZE=99999999999999999999` becomes `SIZE=0`, which then passes the `sz > max_size` check at session.rs:175. This is exploitable for resource exhaustion if the SIZE-check is the only gate; today the `body_buf` check at line 265 catches it. But the design intent of accepting `SIZE=` is to short-circuit oversize messages *before* DATA. The current behavior turns "say you'll send 9999 GB" into "I trust the SIZE=0".

**Fix:** parse failure → reject MAIL FROM with `501 5.5.4 BAD SIZE parameter`.

### 4.8 `MAIL FROM` parameters silently dropped
The parser accepts SIZE but ignores BODY=, AUTH=, RET=, ENVID=, SMTPUTF8 (advertised in EHLO!), NOTIFY=. Clients sending `BODY=8BITMIME` get no acknowledgment; clients sending DSN parameters get them lost. Since we advertise `SMTPUTF8`, we should at least accept it as a no-op parameter on MAIL FROM, not error out. Currently MAIL FROM with an unknown parameter still parses because the parser is permissive — but the parameter is discarded.

### 4.9 RCPT TO doesn't parse parameters
`crates/smtp/src/command.rs:118-124`: takes everything up to whitespace as the address. So `RCPT TO:<a@b> NOTIFY=SUCCESS` parses `<a@b>` correctly because of the whitespace stop. But anything attached without whitespace breaks: `RCPT TO:<a@b>NOTIFY=…`. Edge.

### 4.10 No `Received-SPF:` or `Authentication-Results:` injected
See §2.6.

### 4.11 `Received:` line uses `client_helo` for both hostname and parenthetical
`crates/smtp/src/session.rs:432-442`:
```rust
"Received: from {} ({} [{}])\r\n…",
envelope.client_helo,    // first {}
envelope.client_helo,    // second {} — should be FCrDNS-confirmed name or "unknown"
envelope.client_ip,
```
RFC 5321 §4.4: the parenthetical is the verified hostname (FCrDNS), not the client-claimed HELO. We have FCrDNS code; not used (§2.7).

### 4.12 `VRFY` returns `252 Cannot VRFY`
That's the polite "I can't tell" response — fine.

### 4.13 `EXPN` not handled — falls through to syntax error
Minor, but should return `502 Command not implemented` rather than syntax error.

### 4.14 No connection greeting timeout
RFC 5321 §4.5.3.2.1 says the server greeting should appear within 5 min. We send immediately, but a misbehaving listener could delay; not protected.

### 4.15 Multiple `MAIL FROM` after RCPT silently allowed?
`session.rs:170-172`: requires `Greeted | Tls`. So after `MAIL FROM` succeeds (state = Mailing) a second `MAIL FROM` returns bad sequence. ✓

### 4.16 No `RSET` after `DATA` failure during accumulation
On line-too-long in DATA (line 96-103), we reset transaction and set state back to Greeted/Tls. But what about a malformed `.` (e.g. bare LF dot we now reject)? Need consistent reset semantics.

---

## 5 — Outbound delivery / queue / mailbox

### 5.1 `QueueId` entropy = 24 bits
`crates/core/src/lib.rs:25-35`: `entropy & 0xFFFFFF` — 16M values. At sustained high throughput collisions become probable per birthday paradox at ~4000 messages/second. Each collision = silent message-overwrite (`fs::File::create` truncates).

**Fix:** use a per-second monotonic counter, or 64-bit randomness, or `uuid::Uuid::new_v4()`.

### 5.2 `Queue::enqueue` doesn't check for duplicate ID
`crates/queue/src/lib.rs:81-105`: creates `.eml` and `.env` blindly. If a collision happens (§5.1) the second message destroys the first.

**Fix:** `O_EXCL` create (`OpenOptions::new().create_new(true)`); if file exists, regenerate ID and retry.

### 5.3 `transition` not atomic across both renames
`crates/queue/src/lib.rs:118-133`: renames `.eml`, then `.env`. The doc-comment correctly notes "if we crash between the two renames, body is in destination and envelope is in source — message remains in old state, body is an orphan." Recovery sweeps the orphan. Good.

But two concurrent `tick()` runs (the queue manager loop is single-task, so OK in practice) or two parallel callers could both see the same message in `incoming/` and both try to transition — race. Not currently possible by construction, but the queue API doesn't enforce single-writer per ID.

### 5.4 Recovery doesn't fsync `Corrupt` after renames
`crates/queue/src/lib.rs:271`: fsyncs `Corrupt` once at end. Good. But each `fs::rename` between source and corrupt also needs the source dir fsynced — covered by the loop's `fsync_dir(&dir)` at line 269. ✓

### 5.5 Outbound MX with no retry-per-MX timeout
`crates/server/src/delivery.rs:46-95`: for each MX target, calls `client::deliver`. No per-MX timeout. A blackholed MX hangs the delivery worker indefinitely (TCP RTO default = minutes).

**Fix:** wrap `client::deliver` in `tokio::time::timeout(120s)`.

### 5.6 Outbound: `delivered_or_permanent` set on `rejected`, never on `accepted` — break logic confusing
`delivery.rs:44-99`: the inner loop sets `delivered_or_permanent = true` only on rejected permanent codes, then breaks on success. The `break` after the success case is unconditional (line 69). On all-transient, we continue to next MX. ✓ but the variable's name and the rejected-only set logic is confusing — `delivered_or_permanent` is misleading.

### 5.7 Outbound: `accepted` lost on partial-permanent rejections
If MX1 rejects 3 of 4 recipients permanently and accepts 1, but DATA fails transiently — the `accepted` list is built but the message stays in the queue. On retry, MX1 will reject the same 3 and also resend to the 1 that was already accepted = duplicate. We don't track per-recipient delivery state across attempts; `mark_failed` is called only on permanent reject, never on transient.

**Fix:** track per-recipient `Pending` → `Delivered` updates persistently so a partial DATA failure doesn't cause duplicate delivery on retry.

### 5.8 Null MX (RFC 7505) not handled
`crates/dns/src/lib.rs:99-114`: returns all MX records, including the special `0 .` "null MX" indicating the domain doesn't accept mail. Delivery attempt to host `""` will fail — but with a wasted retry budget. Should detect and bounce immediately with `550 5.1.10`.

### 5.9 No IPv6 preference
`delivery.rs:140-144`: both v4 and v6 are tried in DNS order. Acceptable.

### 5.10 No SOCKS / outbound IP binding
Not needed for v1.

### 5.11 Maildir `unique_filename` not standard Maildir
`crates/mailbox/src/lib.rs:232-242`: format `<ts>.<pid>_<counter>.rmail`. Real Maildir uses `<ts>.<pid>_<counter>.<hostname>` (Bernstein spec). Some non-rmail tools (mutt, mu, notmuch) parse the hostname. Loss is mild.

### 5.12 Maildir flags handling: only `S`, `F`, `T` extracted
`mailbox/src/lib.rs:135-145` extracts S/F/T into `seen/flagged/deleted`. `R` (replied / `\Answered`), `D` (draft) are ignored. IMAP `FLAGS` response in `do_fetch` (`imap/src/session.rs:354-367`) emits `\Seen \Flagged \Deleted` but not `\Answered \Draft`.

### 5.13 `move_to_cur` strips `\Recent` semantics
See §3.10.

### 5.14 No quota
Not blocking.

---

## 6 — Auth / DNS / TLS

### 6.1 `mail-auth` builds its own resolver — costly
`crates/auth/src/checker.rs:127`:
```rust
let resolver = match MailAuthResolver::new_cloudflare_tls() { … };
```
Built fresh on **every inbound message**. That's a new DoT connection setup per mail. Plus we already have an `rmail_dns::Resolver`, so we have two DNS stacks talking to two different resolvers.

Same problem in `dmarc::evaluate` and `spf::verify` (which are dead code anyway, §1.3).

**Fix:** build the `MailAuthResolver` once in main, wrap in `Arc`, share. Or replace `mail-auth`'s resolver with our `hickory_resolver` directly (the project's TODO at `checker.rs:126`).

### 6.2 Authentication-Results header includes user-controlled HELO without escaping
`checker.rs:21-31`: doesn't matter today because the header is never used (§2.6). But if it gets wired in, the `spf.domain()` (which is `""`) and the parsed HELO could include LF/`;` from the client, breaking the header.

### 6.3 `mail-auth` 0.5 (lockfile 0.5.1) is two majors behind
The latest is in the 0.6.x line at minimum. Worth a dependency bump as a follow-up. Also locks in transitive `rustls` 0.21 alongside our `rustls` 0.23 — two TLS stacks compiled in.

### 6.4 DNSSEC default off
`config/rmail.toml.example:34`: `dnssec = false`. Without DNSSEC we can't enforce DANE TLSA records. Hard to flip on without breaking — but should at least be documented.

### 6.5 `TlsAcceptor::from_pem` doesn't support reload
The cert is loaded once at startup. Let's Encrypt renewals require a daemon restart, dropping all connections. Should support SIGHUP-triggered reload.

### 6.6 `TlsConnector::new()` rebuilds the ClientConfig per call
`crates/smtp/src/client.rs:90`: `let connector = TlsConnector::new();` — every outbound delivery rebuilds the entire `RootCertStore` from `webpki_roots`. Should be Arc'd at startup.

### 6.7 No SNI multi-domain serving
One server cert. Hosting multiple domains requires a multi-SAN cert. Documented? No.

### 6.8 No client-cert auth (acceptable for v1).

### 6.9 `Resolver` doesn't honor `/etc/hosts` and explicitly says so — good — but a side effect is that locally-hosted domains can't resolve their own MX records during integration tests. Worth a config switch for dev environments.

### 6.10 `Resolver::txt` joins multiple character-strings with no separator
`crates/dns/src/lib.rs:140-149`: `txt.iter().map(...).collect::<String>()`. RFC 1035 says multiple character-strings in a single TXT record are concatenated for application use, which is what we do. ✓

### 6.11 `Resolver::mx` always returns `Err` on empty result
`crates/dns/src/lib.rs:110-112`. But hickory returns `Err` already on NXDOMAIN. The empty case here is "MX returned but list is empty after iter" — unusual. ✓

### 6.12 Password hashing: argon2 default params
`crates/auth/src/password.rs:21`: `Argon2::default()`. Per `argon2` 0.5: `m_cost=19456 KiB, t_cost=2, p=1`. That's the OWASP-2023 minimum. Acceptable. Document if you intend to tune.

---

## 7 — Config / CLI / docs

### 7.1 Config validation is anemic
`crates/config/src/lib.rs:138-148`: only checks `hostname` and `listen_smtp` non-empty. Doesn't:
- check `listen_imap` non-empty
- check `tls.cert` / `tls.key` files exist (TLS load will fail later with a less actionable error)
- check `storage.queue_dir` is writable
- validate the domain list (no `[[domain]]` with bad characters, no duplicates, no overlap with subdomains)
- validate user addresses parse via `Address::parse`
- validate that every user's domain is in `[[domain]]`

### 7.2 CLI `rmailctl user add --password X` exposes the password to shell history
`bin/rmailctl/src/cmd/user.rs:18-22` (dead) and `bin/rmailctl/src/main.rs:212` (live) both either accept a password on the command line or read it from stdin with no echo suppression (`bin/rmailctl/src/main.rs:390-397`):
```rust
fn prompt_password(prompt: &str) -> Result<String> {
    use std::io::Write;
    print!("{}", prompt);
    std::io::stdout().flush()?;
    let mut pw = String::new();
    std::io::stdin().read_line(&mut pw)?;
    Ok(pw.trim().to_owned())
}
```
- Echoes password to terminal.
- `--password` flag (in the dead `cmd/user.rs`) is bad UX even when dead.

**Fix:** add the `rpassword` crate; use `rpassword::prompt_password`.

### 7.3 `rmailctl user add` doesn't actually edit the config
It prints the lines for the user to paste. Same for `domain add`, `user remove`. The doc-comment says "config file editing is not yet automated" — fine, but document that this is the intended UX, not a TODO.

### 7.4 `rmailctl user add` doesn't create the user's Maildir
A new user has no `cur/`, `new/`, `tmp/` until `Maildir::create_user` is called somewhere. Today, the first delivery returns `MailboxError::UserNotFound` and the queue manager bounces. **The user is added in config but has no inbox.** Major UX trap.

**Fix:** `rmailctl user add` should create the Maildir tree.

### 7.5 `Queue::Show` envelope dump omits per-recipient status
`bin/rmailctl/src/main.rs:266-281`. The dead `bin/rmailctl/src/cmd/queue.rs:60-64` actually does print it. Use that.

### 7.6 No `--dry-run`, no `--json`, no `--quiet` flags
Operational tooling needs scripting hooks.

### 7.7 No `rmailctl status` connects to the queue or shows live counts
`main.rs:340-374`: prints config only.

### 7.8 No reload, no SIGHUP

### 7.9 No graceful shutdown
`bin/rmail/src/main.rs:96-100`: `tokio::select!` only waits for tasks to *error*. On SIGTERM the process is killed mid-write; in-flight delivery state goes back to `active/` (because the body+env are durable, but a successful delivery whose RCPT/DATA response was being read but not yet `mark_delivered`'d will deliver twice on next start).

**Fix:** add `tokio::signal::ctrl_c()` arm; on signal, drain the connection semaphore, finish in-flight queue ticks, exit.

### 7.10 Docs disagree with code
See §1.4.

---

## 8 — Specifics by file

### `crates/core/src/lib.rs`
- `QueueId::generate` — 24-bit entropy (§5.1).
- `Address::parse` — solid; good test coverage.
- `Envelope::pending_recipients` borrows immutably while `mark_delivered`/`mark_failed` take `&mut self`. No issue today; could pinch later.

### `crates/config/src/lib.rs`
- `next_retry_delay`: `initial * 2^retry_count.min(6)` ceiling at `max_retry_secs`. Backoff capped at 64x initial. Good.
- Default `bounce_after_hours = 120` = 5 days. Postfix default is 5 days. ✓

### `crates/queue/src/lib.rs`
- Best-designed module. Crash-safe enqueue with body-then-env-then-fsync, atomic transition, recovery sweep.
- Minor: `update_envelope` uses `path.with_extension("tmp")` — for `id.env` this becomes `id.tmp`. If two updates race they'd collide on tmp. In practice the queue manager is single-threaded per id, so OK. Worth a `.env.tmp.<pid>` style for paranoia.

### `crates/mailbox/src/lib.rs`
- `deliver` does write → fsync → rename → fsync_dir. ✓ best practice.
- `move_to_cur` opens the parent's parent to find `cur/`. Fragile; assumes path layout. OK because it's only called from our IMAP code that knows the layout.
- `expunge` permanently removes — no cur/.Trash move. RFC 9051 §6.4.3: EXPUNGE deletes. ✓
- No flock or file locking. Maildir is officially lock-free, but parallel delivery + EXPUNGE race could leave a `cur/` entry briefly missing. Acceptable.

### `crates/smtp/src/session.rs`
- `do_mail_from` MAIL FROM spoofing check: only triggers when `auth_user.is_some()`. For non-authenticated (port 25) traffic, any MAIL FROM is accepted, including local-domain spoofing. SPF/DMARC at queue time catches it.
- `do_rcpt_to` `relay_denied` on non-local + unauth. ✓
- `handle_data_line`: dead `b"."` branch (line 257); bare-LF accepted (§4.5); unbounded body limited only by `max_size`. ✓ but should also enforce per-line max within DATA.

### `crates/smtp/src/client.rs`
- STARTTLS fallback returns `Err(ClientError::Tls("…requires reconnect"))` (`client.rs:111-115`) — but the delivery worker treats any `Err` as a transient failure. Effect: opportunistic STARTTLS failure is a no-op per attempt with no plaintext fallback. Probably the safer behavior, but inconsistent with the doc.
- `read_reply`: assumes server speaks ASCII/UTF-8. A non-UTF-8 byte in a reply terminates the connection. Possible but unusual.

### `crates/imap/src/session.rs`
- See §3.

### `crates/auth/src/checker.rs`
- See §6.1, §2.5, §2.6.

### `crates/tls/src/lib.rs`
- Reasonable rustls wrapper. Add: cert reload, ClientConfig caching, ALPN if you ever want HTTP front-door (not needed).

### `crates/server/src/smtp_listener.rs` & `imap_listener.rs`
- §2.1, §2.2, §2.6, §2.7 all apply.
- `should_reject_inbound` runs the *full* SPF+DKIM+DMARC pipeline per message. This is also where the result should be captured for header injection.
- IMAP listener never inspects `Action::UpgradeTls` returned bytes — write them, then return; if upgrade fails, the connection drops silently.

### `bin/rmail/src/main.rs`
- §7.9 graceful shutdown.
- The default env-filter is "rmail=info,rmail_server=info,rmail_smtp=info,rmail_imap=info" — drops `rmail_queue`, `rmail_mailbox`, `rmail_auth`, `rmail_tls`, `rmail_dns`. Should include them at warn at least.

### `bin/rmailctl/src/main.rs`
- §7.2, §7.4, §7.6.

---

## 9 — Risk-ranked priority list

### Critical (security / data loss)
1. Unbounded line read on every listener — OOM DoS. (§2.1)
2. No I/O timeouts — slow-loris DoS. (§2.2)
3. IMAP `FETCH BODY[]` corrupts non-UTF-8 — all attachments break. (§2.3)
4. STARTTLS leaves transaction state intact post-upgrade. (§2.4)
5. DMARC `quarantine` silently accepted. (§2.5)
6. SMTP smuggling tolerance (bare LF dot termination). (§4.5, §4.6)
7. Dead `smtpd.rs` and `cmd/*` — coherence trap, will compile-fail if wired. (§1.1, §1.2)
8. Outbound STARTTLS downgrade unprotected (no DANE / MTA-STS). (§2.13)
9. `QueueId` collision risk (24-bit entropy + no O_EXCL). (§5.1, §5.2)
10. IMAP UIDs are FNV hashes, UIDVALIDITY hardcoded, INTERNALDATE fixed — mailbox sync corruption. (§3.1–3.3)

### High (protocol compliance / functionality)
11. `Authentication-Results` / `Received-SPF` headers never written. (§2.6)
12. FCrDNS implemented but not called. (§2.7)
13. IMAP `STORE` only handles `\Deleted`; `APPEND`/`COPY`/`MOVE`/`CREATE`/`DELETE`/`RENAME` missing. (§3.4, §3.5)
14. IMAP literal syntax `{n}` not parsed. (§3.6)
15. IMAP `SEARCH` unknown criteria match all. (§3.7)
16. Outbound dot-stuffing trailer bug. (§2.14)
17. SMTP SIZE param overflow → 0. (§4.7)
18. Outbound per-MX timeout missing. (§5.5)
19. Outbound partial-accept causes duplicate delivery on retry. (§5.7)
20. `mail-auth` resolver rebuilt per message. (§6.1)
21. Timing attack on AUTH username enumeration. (§2.8)

### Medium (operational, missing features)
22. No graceful shutdown / no SIGHUP reload. (§7.9, §6.5)
23. `rmailctl user add` doesn't create the Maildir. (§7.4)
24. Config validation anemic. (§7.1)
25. Two `prepend_received` implementations; `cleanup.rs` dead. (§1.5)
26. SASL PLAIN authzid silently ignored. (§2.10)
27. IMAP `LIST` ignores pattern. (§3.8)
28. IMAP `IDLE` response malformed. (§3.5)
29. Per-IP rate limiting / failed-auth backoff missing. (§2.12)
30. Null MX not detected. (§5.8)
31. Logs contain PII without rotation policy. (§2.15)
32. IMAP `SELECT`/`EXAMINE` both writable; `\Recent` semantics wrong. (§3.10)
33. IMAP `ENVELOPE`/`BODY[]` parsing is templated and unescaped. (§3.11, §3.12)
34. CLI password prompt echoes; no `rpassword`. (§7.2)
35. Outbound `TlsConnector` rebuilt per call. (§6.6)
36. `mail-auth` 0.5 outdated → `rustls` 0.21 duplicated. (§6.3)

### Low (style, polish)
37. Docs / Postfix mapping refer to nonexistent paths. (§1.4)
38. `crates/auth/src/{spf,dkim,dmarc}.rs` stubs are dead. (§1.3)
39. `Reply::ehlo_caps` doesn't advertise ENHANCEDSTATUSCODES / PIPELINING. (§4.1, §4.2)
40. `unwrap()` in `mailbox::move_to_cur`/`mark_deleted` on `file_name`/`parent`. Practically fine, but `expect`s would be clearer.
41. `rmailctl status` shows config only, not live counts. (§7.7)

---

## 10 — Suggested fix order

If I had a week:

**Day 1 — stop the bleeding (critical security)**
- §2.1 — switch listeners to `take(MAX_LINE+1).read_until(b'\n', ...)`. Add per-protocol limits (1000 for SMTP, 8192 for IMAP per RFC 7162 §4).
- §2.2 — wrap each read in `tokio::time::timeout(5min)`; wrap each write in `tokio::time::timeout(2min)`.
- §4.5, §4.6 — reject bare LF in DATA; require CRLF for dot termination.
- §2.4 — reset session state and explicit buffer empty on STARTTLS.

**Day 2 — IMAP usability**
- §2.3 — rewrite FETCH literal response as byte-vector concat.
- §3.1 — persist a monotonic UID counter per mailbox; rename existing files to `<id>:2,…,U=<uid>` form.
- §3.2 — persist `UIDVALIDITY` per mailbox.
- §3.3 — derive INTERNALDATE from filename or mtime.
- §3.4 — implement `+FLAGS`, `-FLAGS`, `FLAGS`.

**Day 3 — coherence purge**
- Delete `crates/server/src/smtpd.rs`.
- Delete `bin/rmailctl/src/cmd/`.
- Delete `crates/auth/src/{spf,dkim,dmarc}.rs` standalone modules, or rewrite as wrappers.
- Delete `crates/server/src/cleanup.rs`, or use it.
- Rewrite `HANDOFF.md` § 4 and `docs/postfix-mapping.md` against actual paths.

**Day 4 — auth pipeline**
- §2.6 — inject `Authentication-Results:` and `Received-SPF:` headers before queue.
- §2.7 — call FCrDNS in `accept_loop`.
- §2.5 — handle DMARC `quarantine` (deliver to `.Junk`).
- §6.1 — share one `MailAuthResolver` via `Arc`.

**Day 5 — operations**
- §7.9 — graceful shutdown.
- §6.5 — SIGHUP-triggered TLS reload.
- §7.4 — `rmailctl user add` creates the Maildir.
- §7.2 — `rpassword` for prompts.
- §2.12 — per-IP failed-auth counter.

**Day 6 — IMAP completeness**
- §3.5 — implement `APPEND`, `COPY`, `MOVE`, `CREATE`, `DELETE`, `RENAME`.
- §3.6 — implement IMAP literal parser.
- §3.7 — implement at least the common SEARCH criteria (`FROM`, `TO`, `SUBJECT`, `SINCE`, `BEFORE`, `LARGER`, `SMALLER`, `BODY`).
- §3.5 — fix `IDLE` response shape.

**Day 7 — outbound robustness**
- §5.5 — per-MX timeout.
- §5.7 — persist per-recipient delivery state across retries.
- §5.8 — detect null MX.
- §2.14 — normalize CRLF on outbound body, fix trailer.
- §6.6 — Arc the `TlsConnector`.

After all this the project is a reasonable internal-use mail server. To reach Postfix/Dovecot parity for public-internet deployment the still-missing items are: MTA-STS / DANE / TLSRPT, per-mailbox quotas, virtual aliases, SIEVE/filters, full SEARCH grammar, BURL, OBJECTID, CONDSTORE, NOTIFY, milter-equivalent hook (or accept that there isn't one), and a proper FUZZ corpus on the SMTP/IMAP parsers.
