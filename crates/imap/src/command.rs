//! IMAP4rev2 command parser (RFC 9051).

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `tag CAPABILITY`
    Capability,
    /// `tag NOOP`
    Noop,
    /// `tag LOGOUT`
    Logout,
    /// `tag LOGIN user password` (plain-text, TLS required)
    Login { username: String, password: String },
    /// `tag SELECT mailbox`
    Select(String),
    /// `tag EXAMINE mailbox` (read-only SELECT)
    Examine(String),
    /// `tag LIST ref pattern`
    List { reference: String, pattern: String },
    /// `tag STATUS mailbox (items...)`
    Status { mailbox: String, items: Vec<StatusItem> },
    /// `tag FETCH seq-set (items...)`
    Fetch { sequence: String, items: Vec<FetchItem> },
    /// `tag STORE seq-set flags`
    Store { sequence: String, flags: Vec<String>, silent: bool },
    /// `tag EXPUNGE`
    Expunge,
    /// `tag APPEND mailbox (\flags) message`
    Append { mailbox: String },
    /// `tag UID FETCH ...`
    UidFetch { sequence: String, items: Vec<FetchItem> },
    /// `tag UID STORE ...`
    UidStore { sequence: String, flags: Vec<String>, silent: bool },
    /// `tag UID EXPUNGE sequence`
    UidExpunge(String),
    /// `tag SEARCH criteria`
    Search(String),
    /// `tag CLOSE`
    Close,
    /// `tag UNSELECT`
    Unselect,
    /// `tag IDLE`
    Idle,
    /// `DONE` (terminates IDLE)
    Done,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatusItem {
    Messages,
    Recent,
    UidNext,
    UidValidity,
    Unseen,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchItem {
    /// Full RFC 5322 message
    Rfc822,
    /// Headers only
    Rfc822Header,
    /// Body size
    Rfc822Size,
    /// Full BODY[]
    Body,
    /// BODY.PEEK[section]
    BodyPeek(String),
    /// ENVELOPE (parsed header summary)
    Envelope,
    /// FLAGS
    Flags,
    /// UID
    Uid,
    /// INTERNALDATE
    InternalDate,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("unrecognised command")]
    Unknown,
    #[error("malformed command")]
    Malformed,
}

/// Parse a single IMAP command line (without CRLF).
/// Returns `(tag, Command)`.
pub fn parse(line: &str) -> Result<(String, Command), ParseError> {
    let line = line.trim_end_matches(|c| c == '\r' || c == '\n');
    let mut parts = line.splitn(3, ' ');
    let tag = parts.next().ok_or(ParseError::Malformed)?.to_owned();
    let verb = parts.next().ok_or(ParseError::Malformed)?.to_uppercase();
    let rest = parts.next().unwrap_or("");

    let cmd = match verb.as_str() {
        "CAPABILITY" => Command::Capability,
        "NOOP"       => Command::Noop,
        "LOGOUT"     => Command::Logout,
        "LOGIN"      => {
            let (user, pass) = parse_login_args(rest)?;
            Command::Login { username: user, password: pass }
        }
        "SELECT"     => Command::Select(unquote(rest)),
        "EXAMINE"    => Command::Examine(unquote(rest)),
        "LIST"       => {
            let (reference, pattern) = parse_two_strings(rest)?;
            Command::List { reference, pattern }
        }
        "STATUS"     => {
            let (mailbox, items) = parse_status_args(rest)?;
            Command::Status { mailbox, items }
        }
        "FETCH"      => {
            let (seq, items) = parse_fetch_args(rest)?;
            Command::Fetch { sequence: seq, items }
        }
        "STORE"      => {
            let (seq, flags, silent) = parse_store_args(rest)?;
            Command::Store { sequence: seq, flags, silent }
        }
        "EXPUNGE"    => Command::Expunge,
        "CLOSE"      => Command::Close,
        "UNSELECT"   => Command::Unselect,
        "IDLE"       => Command::Idle,
        "DONE"       => Command::Done,
        "UID"        => parse_uid_command(rest)?,
        "SEARCH"     => Command::Search(rest.to_owned()),
        "APPEND"     => {
            let mailbox = rest.splitn(2, ' ').next().unwrap_or("");
            Command::Append { mailbox: unquote(mailbox) }
        }
        _ => return Err(ParseError::Unknown),
    };
    Ok((tag, cmd))
}

fn parse_uid_command(rest: &str) -> Result<Command, ParseError> {
    let mut parts = rest.splitn(3, ' ');
    let subcmd = parts.next().unwrap_or("").to_uppercase();
    let seq    = parts.next().unwrap_or("").to_owned();
    let args   = parts.next().unwrap_or("");
    match subcmd.as_str() {
        "FETCH"   => Ok(Command::UidFetch { sequence: seq, items: parse_fetch_items(args) }),
        "STORE"   => {
            let (_, flags, silent) = parse_store_args(&format!("{} {}", seq, args))?;
            Ok(Command::UidStore { sequence: seq, flags, silent })
        }
        "EXPUNGE" => Ok(Command::UidExpunge(seq)),
        _ => Err(ParseError::Unknown),
    }
}

fn parse_login_args(rest: &str) -> Result<(String, String), ParseError> {
    // LOGIN "user" "password" or LOGIN user password
    let mut tokens = tokenize_imap_args(rest);
    let user = tokens.next().ok_or(ParseError::Malformed)?.to_owned();
    let pass = tokens.next().ok_or(ParseError::Malformed)?.to_owned();
    Ok((user, pass))
}

fn parse_two_strings(rest: &str) -> Result<(String, String), ParseError> {
    let mut tokens = tokenize_imap_args(rest);
    let a = tokens.next().ok_or(ParseError::Malformed)?.to_owned();
    let b = tokens.next().unwrap_or("").to_owned();
    Ok((a, b))
}

fn parse_status_args(rest: &str) -> Result<(String, Vec<StatusItem>), ParseError> {
    let paren = rest.find('(').ok_or(ParseError::Malformed)?;
    let mailbox = unquote(rest[..paren].trim());
    let items_str = &rest[paren + 1..rest.rfind(')').unwrap_or(rest.len())];
    let items = items_str.split_whitespace().filter_map(parse_status_item).collect();
    Ok((mailbox, items))
}

fn parse_status_item(s: &str) -> Option<StatusItem> {
    match s.to_uppercase().as_str() {
        "MESSAGES"    => Some(StatusItem::Messages),
        "RECENT"      => Some(StatusItem::Recent),
        "UIDNEXT"     => Some(StatusItem::UidNext),
        "UIDVALIDITY" => Some(StatusItem::UidValidity),
        "UNSEEN"      => Some(StatusItem::Unseen),
        _             => None,
    }
}

fn parse_fetch_args(rest: &str) -> Result<(String, Vec<FetchItem>), ParseError> {
    let space = rest.find(' ').ok_or(ParseError::Malformed)?;
    let seq = rest[..space].to_owned();
    let items = parse_fetch_items(&rest[space + 1..]);
    Ok((seq, items))
}

fn parse_fetch_items(s: &str) -> Vec<FetchItem> {
    let s = s.trim_matches(|c| c == '(' || c == ')');
    s.split_whitespace().filter_map(|tok| match tok.to_uppercase().as_str() {
        "RFC822"          => Some(FetchItem::Rfc822),
        "RFC822.HEADER"   => Some(FetchItem::Rfc822Header),
        "RFC822.SIZE"     => Some(FetchItem::Rfc822Size),
        "BODY[]"          => Some(FetchItem::Body),
        "ENVELOPE"        => Some(FetchItem::Envelope),
        "FLAGS"           => Some(FetchItem::Flags),
        "UID"             => Some(FetchItem::Uid),
        "INTERNALDATE"    => Some(FetchItem::InternalDate),
        _ if tok.to_uppercase().starts_with("BODY.PEEK") => Some(FetchItem::BodyPeek(tok.to_owned())),
        _                 => None,
    }).collect()
}

fn parse_store_args(rest: &str) -> Result<(String, Vec<String>, bool), ParseError> {
    let mut parts = rest.splitn(3, ' ');
    let seq    = parts.next().ok_or(ParseError::Malformed)?.to_owned();
    let action = parts.next().unwrap_or("").to_uppercase();
    let silent = action.ends_with(".SILENT");
    let flags_str = parts.next().unwrap_or("");
    let flags_str = flags_str.trim_matches(|c| c == '(' || c == ')');
    let flags = flags_str.split_whitespace().map(String::from).collect();
    Ok((seq, flags, silent))
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_owned()
    } else {
        s.to_owned()
    }
}

/// Simple tokenizer: handles quoted strings and bare atoms.
fn tokenize_imap_args(s: &str) -> impl Iterator<Item = &str> {
    // Very simplified: split on whitespace, strip quotes
    s.split_whitespace().map(|t| t.trim_matches('"'))
}
