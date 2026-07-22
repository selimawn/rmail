//! IMAP4rev2 command parser (RFC 9051).

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Capability,
    Noop,
    Logout,
    StartTls,
    Authenticate {
        mech: String,
        initial: Option<String>,
    },
    Login {
        username: String,
        password: String,
    },
    Select(String),
    Examine(String),
    List {
        reference: String,
        pattern: String,
    },
    Lsub {
        reference: String,
        pattern: String,
    },
    Status {
        mailbox: String,
        items: Vec<StatusItem>,
    },
    Fetch {
        sequence: String,
        items: Vec<FetchItem>,
    },
    Store {
        sequence: String,
        op: StoreOp,
        flags: Vec<String>,
        silent: bool,
    },
    Expunge,
    Append {
        mailbox: String,
        flags: Vec<String>,
        literal: Vec<u8>,
    },
    Copy {
        sequence: String,
        mailbox: String,
    },
    Move {
        sequence: String,
        mailbox: String,
    },
    Create(String),
    Delete(String),
    Rename {
        from: String,
        to: String,
    },
    Subscribe(String),
    Unsubscribe(String),
    UidFetch {
        sequence: String,
        items: Vec<FetchItem>,
    },
    UidStore {
        sequence: String,
        op: StoreOp,
        flags: Vec<String>,
        silent: bool,
    },
    UidCopy {
        sequence: String,
        mailbox: String,
    },
    UidMove {
        sequence: String,
        mailbox: String,
    },
    UidExpunge(String),
    Search(String),
    Close,
    Unselect,
    Idle,
    Done,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreOp {
    Add,
    Remove,
    Replace,
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
    Rfc822,
    Rfc822Header,
    Rfc822Size,
    Body,
    BodyPeek(String),
    Envelope,
    Flags,
    Uid,
    InternalDate,
    BodyStructure,
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("unrecognised command")]
    Unknown,
    #[error("malformed command")]
    Malformed,
}

pub fn parse(line: &str) -> Result<(String, Command), ParseError> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut parts = line.splitn(3, ' ');
    let tag = parts.next().ok_or(ParseError::Malformed)?.to_owned();
    let verb = parts.next().ok_or(ParseError::Malformed)?.to_uppercase();
    let rest = parts.next().unwrap_or("");

    let cmd = match verb.as_str() {
        "CAPABILITY" => Command::Capability,
        "NOOP" => Command::Noop,
        "LOGOUT" => Command::Logout,
        "STARTTLS" => Command::StartTls,
        "AUTHENTICATE" => {
            let mut tokens = rest.splitn(2, ' ');
            let mech = tokens.next().unwrap_or("").to_owned();
            let initial = tokens
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            Command::Authenticate { mech, initial }
        }
        "LOGIN" => {
            let (username, password) = parse_login_args(rest)?;
            Command::Login { username, password }
        }
        "SELECT" => Command::Select(unquote(rest)),
        "EXAMINE" => Command::Examine(unquote(rest)),
        "LIST" => {
            let (reference, pattern) = parse_two_strings(rest)?;
            Command::List { reference, pattern }
        }
        "LSUB" => {
            let (reference, pattern) = parse_two_strings(rest)?;
            Command::Lsub { reference, pattern }
        }
        "STATUS" => {
            let (mailbox, items) = parse_status_args(rest)?;
            Command::Status { mailbox, items }
        }
        "FETCH" => {
            let (sequence, items) = parse_fetch_args(rest)?;
            Command::Fetch { sequence, items }
        }
        "STORE" => {
            let (sequence, op, flags, silent) = parse_store_args(rest)?;
            Command::Store {
                sequence,
                op,
                flags,
                silent,
            }
        }
        "EXPUNGE" => Command::Expunge,
        "APPEND" => parse_append(rest)?,
        "COPY" => parse_copy_move(rest, false)?,
        "MOVE" => parse_copy_move(rest, true)?,
        "CREATE" => Command::Create(unquote(rest)),
        "DELETE" => Command::Delete(unquote(rest)),
        "RENAME" => {
            let (from, to) = parse_two_strings(rest)?;
            Command::Rename { from, to }
        }
        "SUBSCRIBE" => Command::Subscribe(unquote(rest)),
        "UNSUBSCRIBE" => Command::Unsubscribe(unquote(rest)),
        "CLOSE" => Command::Close,
        "UNSELECT" => Command::Unselect,
        "IDLE" => Command::Idle,
        "DONE" => Command::Done,
        "UID" => parse_uid_command(rest)?,
        "SEARCH" => Command::Search(rest.to_owned()),
        _ => return Err(ParseError::Unknown),
    };
    Ok((tag, cmd))
}

fn parse_uid_command(rest: &str) -> Result<Command, ParseError> {
    let mut parts = rest.splitn(3, ' ');
    let subcmd = parts.next().unwrap_or("").to_uppercase();
    let sequence = parts.next().unwrap_or("").to_owned();
    let args = parts.next().unwrap_or("");
    match subcmd.as_str() {
        "FETCH" => Ok(Command::UidFetch {
            sequence,
            items: parse_fetch_items(args),
        }),
        "STORE" => {
            let (_, op, flags, silent) = parse_store_args(&format!("{} {}", sequence, args))?;
            Ok(Command::UidStore {
                sequence,
                op,
                flags,
                silent,
            })
        }
        "COPY" => Ok(Command::UidCopy {
            sequence,
            mailbox: unquote(args),
        }),
        "MOVE" => Ok(Command::UidMove {
            sequence,
            mailbox: unquote(args),
        }),
        "EXPUNGE" => Ok(Command::UidExpunge(sequence)),
        _ => Err(ParseError::Unknown),
    }
}

fn parse_login_args(rest: &str) -> Result<(String, String), ParseError> {
    let mut tokens = tokenize_imap_args(rest).into_iter();
    let user = tokens.next().ok_or(ParseError::Malformed)?;
    let pass = tokens.next().ok_or(ParseError::Malformed)?;
    Ok((user, pass))
}

fn parse_two_strings(rest: &str) -> Result<(String, String), ParseError> {
    let mut tokens = tokenize_imap_args(rest).into_iter();
    let a = tokens.next().ok_or(ParseError::Malformed)?;
    let b = tokens.next().unwrap_or_default();
    Ok((a, b))
}

fn parse_status_args(rest: &str) -> Result<(String, Vec<StatusItem>), ParseError> {
    let paren = rest.find('(').ok_or(ParseError::Malformed)?;
    let mailbox = unquote(rest[..paren].trim());
    let items_str = &rest[paren + 1..rest.rfind(')').unwrap_or(rest.len())];
    let items = items_str
        .split_whitespace()
        .filter_map(parse_status_item)
        .collect();
    Ok((mailbox, items))
}

fn parse_status_item(s: &str) -> Option<StatusItem> {
    match s.to_uppercase().as_str() {
        "MESSAGES" => Some(StatusItem::Messages),
        "RECENT" => Some(StatusItem::Recent),
        "UIDNEXT" => Some(StatusItem::UidNext),
        "UIDVALIDITY" => Some(StatusItem::UidValidity),
        "UNSEEN" => Some(StatusItem::Unseen),
        _ => None,
    }
}

fn parse_fetch_args(rest: &str) -> Result<(String, Vec<FetchItem>), ParseError> {
    let space = rest.find(' ').ok_or(ParseError::Malformed)?;
    Ok((
        rest[..space].to_owned(),
        parse_fetch_items(&rest[space + 1..]),
    ))
}

fn parse_fetch_items(s: &str) -> Vec<FetchItem> {
    let s = s.trim_matches(|c| c == '(' || c == ')');
    let mut items = Vec::new();
    for tok in s.split_whitespace() {
        let upper = tok.to_uppercase();
        let item = match upper.as_str() {
            "RFC822" => Some(FetchItem::Rfc822),
            "RFC822.HEADER" => Some(FetchItem::Rfc822Header),
            "RFC822.SIZE" => Some(FetchItem::Rfc822Size),
            "BODY[]" => Some(FetchItem::Body),
            "BODYSTRUCTURE" => Some(FetchItem::BodyStructure),
            "ENVELOPE" => Some(FetchItem::Envelope),
            "FLAGS" => Some(FetchItem::Flags),
            "UID" => Some(FetchItem::Uid),
            "INTERNALDATE" => Some(FetchItem::InternalDate),
            _ if upper.starts_with("BODY.PEEK") || upper.starts_with("BODY[") => {
                Some(FetchItem::BodyPeek(tok.to_owned()))
            }
            _ => None,
        };
        if let Some(item) = item {
            items.push(item);
        }
    }
    if items.is_empty() {
        items.push(FetchItem::Flags);
    }
    items
}

fn parse_copy_move(rest: &str, move_cmd: bool) -> Result<Command, ParseError> {
    let mut tokens = tokenize_imap_args(rest).into_iter();
    let sequence = tokens.next().ok_or(ParseError::Malformed)?;
    let mailbox = tokens.next().ok_or(ParseError::Malformed)?;
    if move_cmd {
        Ok(Command::Move { sequence, mailbox })
    } else {
        Ok(Command::Copy { sequence, mailbox })
    }
}

fn parse_append(rest: &str) -> Result<Command, ParseError> {
    let mut tokens = tokenize_imap_args(rest).into_iter();
    let mailbox = tokens.next().ok_or(ParseError::Malformed)?;
    let mut flags = Vec::new();
    let mut literal = Vec::new();
    for token in tokens {
        if token.starts_with('\\') {
            flags.push(token);
        } else if token.starts_with('{') && token.ends_with('}') {
            continue;
        } else if !token.is_empty() {
            literal = token.into_bytes();
        }
    }
    Ok(Command::Append {
        mailbox,
        flags,
        literal,
    })
}

fn parse_store_args(rest: &str) -> Result<(String, StoreOp, Vec<String>, bool), ParseError> {
    let mut parts = rest.splitn(3, ' ');
    let sequence = parts.next().ok_or(ParseError::Malformed)?.to_owned();
    let action = parts.next().unwrap_or("").to_uppercase();
    let silent = action.ends_with(".SILENT");
    let op = if action.starts_with("+FLAGS") {
        StoreOp::Add
    } else if action.starts_with("-FLAGS") {
        StoreOp::Remove
    } else {
        StoreOp::Replace
    };
    let flags_str = parts.next().unwrap_or("");
    let flags_str = flags_str.trim_matches(|c| c == '(' || c == ')');
    let flags = flags_str.split_whitespace().map(String::from).collect();
    Ok((sequence, op, flags, silent))
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        s[1..s.len() - 1]
            .replace("\\\"", "\"")
            .replace("\\\\", "\\")
    } else {
        s.to_owned()
    }
}

fn tokenize_imap_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut escape = false;
    for ch in s.chars() {
        if escape {
            cur.push(ch);
            escape = false;
            continue;
        }
        match ch {
            '\\' if quoted => escape = true,
            '"' => quoted = !quoted,
            '(' | ')' if !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}
