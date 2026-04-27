//! IMAP4rev2 command parser (RFC 9051 subset).
//!
//! Covers the commands needed for a functional read/write client:
//! CAPABILITY, NOOP, LOGOUT, LOGIN, SELECT, EXAMINE, LIST, STATUS,
//! FETCH, STORE, SEARCH, EXPUNGE, COPY, MOVE, APPEND, CREATE, DELETE, RENAME.

#[derive(Debug, Clone, PartialEq)]
pub enum ImapCommand {
    Capability,
    Noop,
    Logout,
    Login { username: String, password: String },
    Select(String),
    Examine(String),
    List { reference: String, mailbox: String },
    Status { mailbox: String, items: Vec<StatusItem> },
    Fetch { sequence: String, items: Vec<FetchItem> },
    Store { sequence: String, flags: FlagOp },
    Search(String),
    Expunge,
    Copy { sequence: String, mailbox: String },
    Create(String),
    Delete(String),
    Rename { from: String, to: String },
    Append { mailbox: String, size: u32 },
}

#[derive(Debug, Clone, PartialEq)]
pub enum StatusItem {
    Messages, Recent, UidNext, UidValidity, Unseen,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FetchItem {
    Envelope, Flags, InternalDate, Rfc822Size,
    BodyStructure, Body, Uid,
    BodySection(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum FlagOp {
    Set(Vec<String>),
    Add(Vec<String>),
    Remove(Vec<String>),
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("unrecognised command")]
    Unknown,
    #[error("missing tag")]
    MissingTag,
}

/// Parse a tagged IMAP command line.
/// Returns `(tag, command)`.
pub fn parse_command(line: &str) -> Result<(String, ImapCommand), ParseError> {
    let line = line.trim_end_matches(|c| c == '\r' || c == '\n');
    let mut parts = line.splitn(3, ' ');
    let tag = parts.next().ok_or(ParseError::MissingTag)?.to_owned();
    let verb = parts.next().ok_or(ParseError::Unknown)?.to_ascii_uppercase();
    let rest = parts.next().unwrap_or("").trim();

    let cmd = match verb.as_str() {
        "CAPABILITY" => ImapCommand::Capability,
        "NOOP"       => ImapCommand::Noop,
        "LOGOUT"     => ImapCommand::Logout,
        "LOGIN" => {
            let (user, pass) = parse_two_strings(rest)?;
            ImapCommand::Login { username: user, password: pass }
        }
        "SELECT"  => ImapCommand::Select(unquote(rest)),
        "EXAMINE" => ImapCommand::Examine(unquote(rest)),
        "LIST" => {
            let (reference, mailbox) = parse_two_strings(rest)?;
            ImapCommand::List { reference, mailbox }
        }
        "STATUS" => {
            let (mailbox, raw_items) = parse_two_strings(rest)?;
            let items = parse_status_items(&raw_items);
            ImapCommand::Status { mailbox: unquote(&mailbox), items }
        }
        "FETCH" => {
            let (seq, items_str) = split_first(rest);
            ImapCommand::Fetch {
                sequence: seq.to_owned(),
                items: parse_fetch_items(items_str),
            }
        }
        "STORE" => {
            let (seq, rest2) = split_first(rest);
            let (op_str, flags_str) = split_first(rest2);
            ImapCommand::Store {
                sequence: seq.to_owned(),
                flags: parse_flag_op(op_str, flags_str),
            }
        }
        "SEARCH"  => ImapCommand::Search(rest.to_owned()),
        "EXPUNGE" => ImapCommand::Expunge,
        "COPY" => {
            let (seq, mbox) = split_first(rest);
            ImapCommand::Copy { sequence: seq.to_owned(), mailbox: unquote(mbox) }
        }
        "CREATE" => ImapCommand::Create(unquote(rest)),
        "DELETE" => ImapCommand::Delete(unquote(rest)),
        "RENAME" => {
            let (from, to) = parse_two_strings(rest)?;
            ImapCommand::Rename { from: unquote(&from), to: unquote(&to) }
        }
        "APPEND" => {
            let (mbox, rest2) = split_first(rest);
            // Extract literal size from {N}
            let size = rest2.trim()
                .trim_start_matches('{')
                .trim_end_matches('}')
                .parse::<u32>()
                .unwrap_or(0);
            ImapCommand::Append { mailbox: unquote(mbox), size }
        }
        _ => return Err(ParseError::Unknown),
    };
    Ok((tag, cmd))
}

// ─── helpers ─────────────────────────────────────────────────────────────────

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        s[1..s.len()-1].replace("\\\"", "\"").replace("\\\\", "\\")
    } else {
        s.to_owned()
    }
}

fn split_first(s: &str) -> (&str, &str) {
    let s = s.trim_start();
    if let Some(idx) = s.find(' ') {
        (&s[..idx], s[idx+1..].trim_start())
    } else {
        (s, "")
    }
}

fn parse_two_strings(s: &str) -> Result<(String, String), ParseError> {
    let s = s.trim_start();
    let (a, rest) = if s.starts_with('"') {
        if let Some(end) = s[1..].find('"') {
            (s[1..end+1].to_owned(), s[end+2..].trim_start().to_owned())
        } else { return Err(ParseError::Unknown); }
    } else {
        let idx = s.find(' ').unwrap_or(s.len());
        (s[..idx].to_owned(), s[idx..].trim_start().to_owned())
    };
    Ok((a, rest))
}

fn parse_status_items(s: &str) -> Vec<StatusItem> {
    let inner = s.trim().trim_start_matches('(').trim_end_matches(')');
    inner.split_whitespace().filter_map(|t| match t.to_ascii_uppercase().as_str() {
        "MESSAGES"     => Some(StatusItem::Messages),
        "RECENT"       => Some(StatusItem::Recent),
        "UIDNEXT"      => Some(StatusItem::UidNext),
        "UIDVALIDITY"  => Some(StatusItem::UidValidity),
        "UNSEEN"       => Some(StatusItem::Unseen),
        _              => None,
    }).collect()
}

fn parse_fetch_items(s: &str) -> Vec<FetchItem> {
    let s = s.trim().trim_start_matches('(').trim_end_matches(')');
    s.split_whitespace().filter_map(|t| match t.to_ascii_uppercase().as_str() {
        "ENVELOPE"      => Some(FetchItem::Envelope),
        "FLAGS"         => Some(FetchItem::Flags),
        "INTERNALDATE" => Some(FetchItem::InternalDate),
        "RFC822.SIZE"   => Some(FetchItem::Rfc822Size),
        "BODYSTRUCTURE" => Some(FetchItem::BodyStructure),
        "BODY"          => Some(FetchItem::Body),
        "UID"           => Some(FetchItem::Uid),
        _               => Some(FetchItem::BodySection(t.to_owned())),
    }).collect()
}

fn parse_flag_op(op: &str, flags: &str) -> FlagOp {
    let inner = flags.trim().trim_start_matches('(').trim_end_matches(')');
    let parsed: Vec<String> = inner.split_whitespace()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_owned())
        .collect();
    match op.to_ascii_uppercase().as_str() {
        "+FLAGS" | "+FLAGS.SILENT" => FlagOp::Add(parsed),
        "-FLAGS" | "-FLAGS.SILENT" => FlagOp::Remove(parsed),
        _                          => FlagOp::Set(parsed),
    }
}
