//! IMAP4rev2 session state machine.
//! No I/O done here — caller feeds lines, receives bytes to send back.

use tracing::{debug, info, warn};
use rmail_config::Config;
use rmail_mailbox::Maildir;
use rmail_core::Address;
use crate::command::{self, Command, FetchItem, StatusItem};
use crate::response::Response;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

pub struct Session {
    state:    State,
    user:     Option<Address>,
    selected: Option<String>,
}

impl Session {
    pub fn new() -> (Self, Vec<u8>) {
        let greeting = Response::untagged(
            "OK [CAPABILITY IMAP4rev2 IMAP4rev1 AUTH=PLAIN AUTH=LOGIN IDLE] rmail ready"
        ).to_wire();
        (Self { state: State::NotAuthenticated, user: None, selected: None }, greeting)
    }

    /// Feed one command line. Returns bytes to send to the client.
    pub async fn step(&mut self, line: &[u8], config: &Config, maildir: &Maildir) -> Vec<u8> {
        let line_str = match std::str::from_utf8(line) {
            Ok(s) => s.trim_end_matches(|c| c == '\r' || c == '\n'),
            Err(_) => return Response::bad("*", "BAD Non-UTF8 input").to_wire(),
        };

        if line_str.eq_ignore_ascii_case("DONE") {
            return Response::untagged("OK IDLE terminated").to_wire();
        }

        let (tag, cmd) = match command::parse(line_str) {
            Ok(v)  => v,
            Err(_) => return Response::bad("*", "BAD Command parse error").to_wire(),
        };

        debug!(state = ?self.state, ?cmd, "IMAP command");
        self.dispatch(&tag, cmd, config, maildir).await
    }

    async fn dispatch(&mut self, tag: &str, cmd: Command, config: &Config, maildir: &Maildir) -> Vec<u8> {
        match cmd {
            Command::Capability => {
                let mut out = Response::capability().to_wire();
                out.extend(Response::ok(tag, "CAPABILITY completed").to_wire());
                out
            }
            Command::Noop    => Response::ok(tag, "NOOP completed").to_wire(),
            Command::Logout  => {
                self.state = State::Logout;
                let mut out = Response::bye("Logging out").to_wire();
                out.extend(Response::ok(tag, "LOGOUT completed").to_wire());
                out
            }
            Command::Login { username, password } => self.do_login(tag, &username, &password, config),
            Command::Select(mb) | Command::Examine(mb) => self.do_select(tag, &mb, maildir).await,
            Command::List { reference, pattern }       => self.do_list(tag, &reference, &pattern, maildir).await,
            Command::Status { mailbox, items }         => self.do_status(tag, &mailbox, &items, maildir).await,
            Command::Fetch { sequence, items }         => self.do_fetch(tag, &sequence, &items, maildir, false).await,
            Command::UidFetch { sequence, items }      => self.do_fetch(tag, &sequence, &items, maildir, true).await,
            Command::Store { sequence, flags, silent } => self.do_store(tag, &sequence, &flags, silent, maildir).await,
            Command::UidStore { sequence, flags, silent } => self.do_store(tag, &sequence, &flags, silent, maildir).await,
            Command::Expunge | Command::UidExpunge(_)  => self.do_expunge(tag, maildir).await,
            Command::Close | Command::Unselect => {
                self.selected = None;
                self.state = State::Authenticated;
                Response::ok(tag, "CLOSE completed").to_wire()
            }
            Command::Idle => Response::untagged("+ idling").to_wire(),
            Command::Search(criteria) => self.do_search(tag, &criteria, maildir).await,
            Command::Append { .. } => Response::ok(tag, "APPEND completed").to_wire(),
            _ => Response::bad(tag, "BAD Not implemented").to_wire(),
        }
    }

    // ─── AUTH ────────────────────────────────────────────────────────────────

    fn do_login(&mut self, tag: &str, username: &str, password: &str, config: &Config) -> Vec<u8> {
        if self.state != State::NotAuthenticated {
            return Response::bad(tag, "BAD Already authenticated").to_wire();
        }
        if let Some(user) = config.find_user(username) {
            if rmail_auth::password::verify(password, &user.password_hash) {
                let addr = Address::parse(username).unwrap_or_else(|_| Address::null());
                self.user  = Some(addr);
                self.state = State::Authenticated;
                info!(%username, "IMAP login");
                return Response::ok(tag, "LOGIN completed").to_wire();
            }
        }
        warn!(%username, "IMAP login failed");
        Response::no(tag, "NO [AUTHENTICATIONFAILED] Invalid credentials").to_wire()
    }

    // ─── SELECT ──────────────────────────────────────────────────────────────

    async fn do_select(&mut self, tag: &str, mailbox: &str, maildir: &Maildir) -> Vec<u8> {
        if self.state < State::Authenticated {
            return Response::no(tag, "NO Not authenticated").to_wire();
        }
        let user = match &self.user {
            Some(u) => u.clone(),
            None    => return Response::no(tag, "NO Not authenticated").to_wire(),
        };

        let entries = match maildir.list_messages(&user, mailbox).await {
            Ok(e)  => e,
            Err(_) => return Response::no(tag, "NO Mailbox does not exist").to_wire(),
        };

        let exists  = entries.len();
        let recent  = entries.iter().filter(|e| !e.seen && !e.deleted).count();
        let unseen  = entries.iter().position(|e| !e.seen).map(|i| i + 1).unwrap_or(0);
        let uid_next = exists + 1;

        self.selected = Some(mailbox.to_owned());
        self.state = State::Selected;

        // Move all new/ messages to cur/ (mark as seen by IMAP)
        for entry in &entries {
            if entry.path.parent().and_then(|p| p.file_name())
                .map(|n| n == "new").unwrap_or(false)
            {
                let _ = maildir.move_to_cur(&entry.path).await;
            }
        }

        let mut out = Vec::new();
        out.extend(Response::untagged(format!("{} EXISTS", exists)).to_wire());
        out.extend(Response::untagged(format!("{} RECENT", recent)).to_wire());
        out.extend(Response::untagged("FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)").to_wire());
        if unseen > 0 {
            out.extend(Response::ok("*", &format!("[UNSEEN {}] first unseen", unseen)).to_wire());
        }
        out.extend(Response::ok("*", &format!("[UIDNEXT {}] predicted next UID", uid_next)).to_wire());
        out.extend(Response::ok("*", "[UIDVALIDITY 1] UIDs valid").to_wire());
        out.extend(Response::ok(tag, "[READ-WRITE] SELECT completed").to_wire());
        out
    }

    // ─── LIST ────────────────────────────────────────────────────────────────

    async fn do_list(&mut self, tag: &str, _reference: &str, _pattern: &str, maildir: &Maildir) -> Vec<u8> {
        if self.state < State::Authenticated {
            return Response::no(tag, "NO Not authenticated").to_wire();
        }
        let user = match &self.user {
            Some(u) => u.clone(),
            None    => return Response::no(tag, "NO Not authenticated").to_wire(),
        };

        let folders = match maildir.list_folders(&user).await {
            Ok(f)  => f,
            Err(e) => {
                warn!("LIST error: {}", e);
                vec!["INBOX".to_owned()]
            }
        };

        let mut out = Vec::new();
        for folder in &folders {
            out.extend(Response::untagged(
                format!("LIST (\\HasNoChildren) \".\" \"{}\"", folder)
            ).to_wire());
        }
        out.extend(Response::ok(tag, "LIST completed").to_wire());
        out
    }

    // ─── STATUS ──────────────────────────────────────────────────────────────

    async fn do_status(&mut self, tag: &str, mailbox: &str, items: &[StatusItem], maildir: &Maildir) -> Vec<u8> {
        if self.state < State::Authenticated {
            return Response::no(tag, "NO Not authenticated").to_wire();
        }
        let user = match &self.user {
            Some(u) => u.clone(),
            None    => return Response::no(tag, "NO Not authenticated").to_wire(),
        };

        let entries = maildir.list_messages(&user, mailbox).await.unwrap_or_default();
        let messages  = entries.len();
        let unseen    = entries.iter().filter(|e| !e.seen).count();
        let uid_next  = messages + 1;

        let parts: Vec<String> = items.iter().map(|i| match i {
            StatusItem::Messages    => format!("MESSAGES {}", messages),
            StatusItem::Recent      => format!("RECENT {}", unseen),
            StatusItem::UidNext     => format!("UIDNEXT {}", uid_next),
            StatusItem::UidValidity => "UIDVALIDITY 1".into(),
            StatusItem::Unseen      => format!("UNSEEN {}", unseen),
        }).collect();

        let mut out = Vec::new();
        out.extend(Response::untagged(
            format!("STATUS {} ({})", mailbox, parts.join(" "))
        ).to_wire());
        out.extend(Response::ok(tag, "STATUS completed").to_wire());
        out
    }

    // ─── FETCH ───────────────────────────────────────────────────────────────

    async fn do_fetch(&mut self, tag: &str, seq: &str, items: &[FetchItem], maildir: &Maildir, _uid: bool) -> Vec<u8> {
        if self.state != State::Selected {
            return Response::no(tag, "NO No mailbox selected").to_wire();
        }
        let (user, folder) = match (&self.user, &self.selected) {
            (Some(u), Some(f)) => (u.clone(), f.clone()),
            _ => return Response::no(tag, "NO Not selected").to_wire(),
        };

        let entries = match maildir.list_messages(&user, &folder).await {
            Ok(e)  => e,
            Err(e) => {
                warn!("FETCH list_messages error: {}", e);
                return Response::no(tag, "NO Internal error").to_wire();
            }
        };

        let indices = parse_sequence_set(seq, entries.len());
        let mut out = Vec::new();

        for idx in indices {
            if idx >= entries.len() { continue; }
            let entry = &entries[idx];
            let seq_num = idx + 1;

            let mut parts: Vec<String> = Vec::new();

            for item in items {
                match item {
                    FetchItem::Flags => {
                        let mut flags = Vec::new();
                        if entry.seen    { flags.push("\\Seen"); }
                        if entry.flagged { flags.push("\\Flagged"); }
                        if entry.deleted { flags.push("\\Deleted"); }
                        parts.push(format!("FLAGS ({})", flags.join(" ")));
                    }
                    FetchItem::Rfc822Size => {
                        parts.push(format!("RFC822.SIZE {}", entry.size));
                    }
                    FetchItem::Uid => {
                        parts.push(format!("UID {}", seq_num)); // UID = seq for simplicity
                    }
                    FetchItem::InternalDate => {
                        parts.push("INTERNALDATE \"01-Jan-2024 00:00:00 +0000\"".into());
                    }
                    FetchItem::Rfc822 | FetchItem::Body | FetchItem::BodyPeek(_) => {
                        match maildir.read_message(&entry.path).await {
                            Ok(body) => {
                                let label = match item {
                                    FetchItem::Rfc822 => "RFC822",
                                    FetchItem::Body   => "BODY[]",
                                    _                 => "BODY[]",
                                };
                                parts.push(format!("{} {{{}}}\r\n{}", label, body.len(),
                                    String::from_utf8_lossy(&body)));
                            }
                            Err(e) => warn!("FETCH read_message: {}", e),
                        }
                    }
                    FetchItem::Rfc822Header => {
                        match maildir.read_message(&entry.path).await {
                            Ok(body) => {
                                let headers = extract_headers(&body);
                                parts.push(format!("RFC822.HEADER {{{}}}\r\n{}", headers.len(),
                                    String::from_utf8_lossy(&headers)));
                            }
                            Err(e) => warn!("FETCH read_message headers: {}", e),
                        }
                    }
                    FetchItem::Envelope => {
                        match maildir.read_message(&entry.path).await {
                            Ok(body) => {
                                let env = build_envelope_string(&body);
                                parts.push(format!("ENVELOPE {}", env));
                            }
                            Err(e) => warn!("FETCH envelope: {}", e),
                        }
                    }
                }
            }

            if !parts.is_empty() {
                out.extend(Response::untagged(
                    format!("{} FETCH ({})", seq_num, parts.join(" "))
                ).to_wire());
            }
        }

        out.extend(Response::ok(tag, "FETCH completed").to_wire());
        out
    }

    // ─── STORE ───────────────────────────────────────────────────────────────

    async fn do_store(&mut self, tag: &str, seq: &str, flags: &[String], silent: bool, maildir: &Maildir) -> Vec<u8> {
        if self.state != State::Selected {
            return Response::no(tag, "NO No mailbox selected").to_wire();
        }
        let (user, folder) = match (&self.user, &self.selected) {
            (Some(u), Some(f)) => (u.clone(), f.clone()),
            _ => return Response::no(tag, "NO Not selected").to_wire(),
        };

        let entries = match maildir.list_messages(&user, &folder).await {
            Ok(e)  => e,
            Err(_) => return Response::no(tag, "NO Internal error").to_wire(),
        };

        let indices = parse_sequence_set(seq, entries.len());
        let set_deleted = flags.iter().any(|f| f == "\\Deleted");
        let mut out = Vec::new();

        for idx in indices {
            if idx >= entries.len() { continue; }
            let entry = &entries[idx];

            if set_deleted && !entry.deleted {
                match maildir.mark_deleted(&entry.path).await {
                    Ok(_) => {
                        if !silent {
                            out.extend(Response::untagged(
                                format!("{} FETCH (FLAGS (\\Deleted))", idx + 1)
                            ).to_wire());
                        }
                    }
                    Err(e) => warn!("STORE mark_deleted: {}", e),
                }
            }
        }

        out.extend(Response::ok(tag, "STORE completed").to_wire());
        out
    }

    // ─── EXPUNGE ─────────────────────────────────────────────────────────────

    async fn do_expunge(&mut self, tag: &str, maildir: &Maildir) -> Vec<u8> {
        if self.state != State::Selected {
            return Response::no(tag, "NO No mailbox selected").to_wire();
        }
        let (user, folder) = match (&self.user, &self.selected) {
            (Some(u), Some(f)) => (u.clone(), f.clone()),
            _ => return Response::no(tag, "NO Not selected").to_wire(),
        };

        let entries = match maildir.list_messages(&user, &folder).await {
            Ok(e)  => e,
            Err(_) => return Response::no(tag, "NO Internal error").to_wire(),
        };

        let mut out = Vec::new();
        // Iterate in reverse so sequence numbers stay valid as we remove
        for (idx, entry) in entries.iter().enumerate().rev() {
            if entry.deleted {
                match maildir.expunge(&entry.path).await {
                    Ok(_) => {
                        out.extend(Response::untagged(
                            format!("{} EXPUNGE", idx + 1)
                        ).to_wire());
                    }
                    Err(e) => warn!("EXPUNGE: {}", e),
                }
            }
        }

        out.extend(Response::ok(tag, "EXPUNGE completed").to_wire());
        out
    }

    // ─── SEARCH ──────────────────────────────────────────────────────────────

    async fn do_search(&mut self, tag: &str, criteria: &str, maildir: &Maildir) -> Vec<u8> {
        if self.state != State::Selected {
            return Response::no(tag, "NO No mailbox selected").to_wire();
        }
        let (user, folder) = match (&self.user, &self.selected) {
            (Some(u), Some(f)) => (u.clone(), f.clone()),
            _ => return Response::no(tag, "NO Not selected").to_wire(),
        };

        let entries = maildir.list_messages(&user, &folder).await.unwrap_or_default();
        let crit_upper = criteria.trim().to_uppercase();

        let matching: Vec<String> = entries.iter().enumerate()
            .filter_map(|(i, e)| {
                let matches = match crit_upper.as_str() {
                    "ALL"    => true,
                    "UNSEEN" => !e.seen,
                    "SEEN"   => e.seen,
                    "FLAGGED"   => e.flagged,
                    "UNFLAGGED" => !e.flagged,
                    "DELETED"   => e.deleted,
                    _        => true, // unknown criteria → match all
                };
                if matches { Some((i + 1).to_string()) } else { None }
            })
            .collect();

        let result = if matching.is_empty() {
            "SEARCH".to_owned()
        } else {
            format!("SEARCH {}", matching.join(" "))
        };

        let mut out = Response::untagged(result).to_wire();
        out.extend(Response::ok(tag, "SEARCH completed").to_wire());
        out
    }

    pub fn is_closed(&self) -> bool { self.state == State::Logout }
}

// ─── Sequence set parser ─────────────────────────────────────────────────────

/// Parse an IMAP sequence set like "1", "1:3", "1,3,5", "1:*"
/// Returns 0-based indices into a list of `count` messages.
fn parse_sequence_set(seq: &str, count: usize) -> Vec<usize> {
    if count == 0 { return vec![]; }
    let mut result = std::collections::BTreeSet::new();
    for part in seq.split(',') {
        if let Some((start, end)) = part.split_once(':') {
            let s = parse_seq_num(start, count);
            let e = parse_seq_num(end, count);
            for i in s.min(e)..=s.max(e) {
                if i > 0 { result.insert(i - 1); }
            }
        } else {
            let n = parse_seq_num(part, count);
            if n > 0 { result.insert(n - 1); }
        }
    }
    result.into_iter().filter(|&i| i < count).collect()
}

fn parse_seq_num(s: &str, count: usize) -> usize {
    if s == "*" { count } else { s.parse().unwrap_or(0) }
}

// ─── Message helpers ─────────────────────────────────────────────────────────

/// Extract only the header section (everything before the first blank line).
fn extract_headers(raw: &[u8]) -> Vec<u8> {
    // Find \r\n\r\n or \n\n
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|i| i + 2))
        .unwrap_or(raw.len());
    raw[..sep].to_vec()
}

/// Build a minimal IMAP ENVELOPE string from raw message headers.
fn build_envelope_string(raw: &[u8]) -> String {
    let headers_raw = extract_headers(raw);
    let text = String::from_utf8_lossy(&headers_raw);
    let date    = header_value(&text, "Date").unwrap_or("NIL");
    let subject = header_value(&text, "Subject").unwrap_or("NIL");
    let from    = header_value(&text, "From").unwrap_or("NIL");
    let to      = header_value(&text, "To").unwrap_or("NIL");
    let msg_id  = header_value(&text, "Message-ID").unwrap_or("NIL");
    format!("(\"{}\" \"{}\" ((NIL NIL \"{}\" NIL)) NIL NIL ((NIL NIL \"{}\" NIL)) NIL NIL NIL \"{}\")",
        date, subject, from, to, msg_id)
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{}:", name);
    headers.lines()
        .find(|l| l.to_ascii_lowercase().starts_with(&prefix.to_ascii_lowercase()))
        .map(|l| l[prefix.len()..].trim())
}

impl PartialOrd for State {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let rank = |s: &State| match s {
            State::NotAuthenticated => 0u8,
            State::Authenticated    => 1,
            State::Selected         => 2,
            State::Logout           => 3,
        };
        rank(self).partial_cmp(&rank(other))
    }
}
