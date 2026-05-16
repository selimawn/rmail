# Postfix → rmail mapping

rmail's architecture mirrors Postfix's, but runs as a single async binary instead of multiple Unix processes.

## Process / module mapping

| Postfix process | rmail location | Job |
|-----------------|----------------|-----|
| `master` | `bin/rmail` (`main`) | Boots Tokio, spawns all tasks, supervises shutdown |
| `smtpd` | `crates/server/src/smtp_listener.rs` + `crates/smtp/src/session.rs` | Accepts SMTP connections (25, 587, 465), validates commands, prepends trace/auth headers |
| `cleanup` | folded into `crates/smtp/src/session.rs` and `crates/server/src/smtp_listener.rs` | Received header, auth header insertion, queue handoff |
| `qmgr` | `crates/server/src/queue_manager.rs` | Picks next message, schedules delivery, retries |
| `smtp` (out) | `crates/server/src/delivery.rs` + `crates/smtp/src/client.rs` | MX lookup → SMTP client → write result |
| `local` | `crates/mailbox/src/lib.rs` (`Maildir`) | Drops message into Maildir |
| `bounce` | `crates/server/src/bounce.rs` | Generates bounce messages on permanent failure |
| `pickup` | — | Not implemented (no `sendmail` compat in v1) |
| `trivial-rewrite` | `crates/core/src/lib.rs` (`Address`) | Address canonicalization |
| `tlsmgr` | `crates/tls/src/lib.rs` | rustls config and STARTTLS/implicit TLS helpers |

## Communication

In Postfix, processes talk over Unix sockets. In rmail, modules talk via:

- **Tokio channels** (`mpsc`) for control flow between tasks
- **The on-disk queue** (atomic renames between dirs) for handoff between cleanup → qmgr → delivery / local

The queue is the durable boundary. Even if rmail crashes mid-delivery, the next start picks up exactly where it left off, just like Postfix.

## Why one process and not many

Postfix's multi-process design gives:

1. **Privilege separation** — each component runs as a different uid in a chroot.
2. **Crash isolation** — a parser bug in `smtpd` doesn't take down `qmgr`.
3. **Resource limits** — kernel can cap each component independently.

rmail trades (1) and (3) for simplicity. We mitigate (2) with:

- Aggressive parser fuzzing (cargo-fuzz on SMTP/IMAP grammars).
- Catch-and-log boundaries on every connection task.
- The on-disk queue: any in-flight crash is recoverable.

If operational experience shows we need true privilege separation, splitting the binary later is mechanical — the module boundaries are already drawn.
