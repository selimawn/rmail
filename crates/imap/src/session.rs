//! IMAP4rev2 session state machine.
//!
//! The caller reads lines from the client, calls `step()`, and writes the
//! returned bytes to the socket. No I/O is done inside this module.

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
    state:      State,
    user:       Option<Address>,
    selected:   Option<String>,     // currently selected mailbox
}

impl Session {
    pub fn new() -> (Self, Vec<u8>) {
        let greeting = Response::untagged(
            "OK [CAPABILITY IMAP4rev2 IMAP4rev1 AUTH=PLAIN AUTH=LOGIN IDLE] rmail ready"
        ).to_wire();
        (Self { state: State::NotAuthenticated, user: None, selected: None }, greeting)
    }

    /// Feed one command line. Returns bytes to send to the client.
    pub fn step(&mut self, line: &[u8], config: &Config, maildir: &Maildir) -> Vec<u8> {
        let line_str = match std::str::from_utf8(line) {
            Ok(s) => s.trim_end_matches(|c| c == '\r' || c == '\n'),
            Err(_) => return Response::bad("*", "BAD Non-UTF8 input").to_wire(),
        };

        // DONE terminates IDLE (no tag)
        if line_str.eq_ignore_ascii_case("DONE") {
            return Response::untagged("OK IDLE terminated").to_wire();
        }

        let (tag, cmd) = match command::parse(line_str) {
            Ok(v)  => v,
            Err(_) => return Response::bad("*", "BAD Command parse error").to_wire(),
        };

        debug!(state = ?self.state, ?cmd, "IMAP command");
        self.dispatch(&tag, cmd, config, maildir)
    }

    fn dispatch(&mut self, tag: &str, cmd: Command, config: &Config, maildir: &Maildir) -> Vec<u8> {
        match cmd {
            Command::Capability => {
                let mut out = Response::capability().to_wire();
                out.extend(Response::ok(tag, "CAPABILITY completed").to_wire());
                out
            }
            Command::Noop => Response::ok(tag, "NOOP completed").to_wire(),
            Command::Logout => {
                self.state = State::Logout;
                let mut out = Response::bye("Logging out").to_wire();
                out.extend(Response::ok(tag, "LOGOUT completed").to_wire());
                out
            }
            Command::Login { username, password } => self.do_login(tag, &username, &password, config),
            Command::Select(mb) | Command::Examine(mb) => self.do_select(tag, &mb),
            Command::List { reference, pattern } => self.do_list(tag, &reference, &pattern),
            Command::Status { mailbox, items } => self.do_status(tag, &mailbox, &items),
            Command::Fetch { sequence, items } => self.do_fetch(tag, &sequence, &items, maildir),
            Command::Store { sequence, flags, silent } => self.do_store(tag, &sequence, &flags, silent, maildir),
            Command::Expunge => self.do_expunge(tag, maildir),
            Command::Close | Command::Unselect => {
                self.selected = None;
                self.state = State::Authenticated;
                Response::ok(tag, "CLOSE completed").to_wire()
            }
            Command::Idle => Response::untagged("+ idling").to_wire(),
            Command::Search(_criteria) => {
                // Stub: return all sequence numbers
                let mut out = Response::untagged("SEARCH").to_wire();
                out.extend(Response::ok(tag, "SEARCH completed").to_wire());
                out
            }
            _ => Response::bad(tag, "BAD Not implemented").to_wire(),
        }
    }

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

    fn do_select(&mut self, tag: &str, mailbox: &str) -> Vec<u8> {
        if self.state < State::Authenticated {
            return Response::no(tag, "NO Not authenticated").to_wire();
        }
        self.selected = Some(mailbox.to_owned());
        self.state = State::Selected;
        let mut out = Vec::new();
        // Minimal required untagged responses
        out.extend(Response::untagged("0 EXISTS").to_wire());
        out.extend(Response::untagged("0 RECENT").to_wire());
        out.extend(Response::untagged(format!("FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)")).to_wire());
        out.extend(Response::ok(tag, "[READ-WRITE] SELECT completed").to_wire());
        out
    }

    fn do_list(&mut self, tag: &str, _reference: &str, _pattern: &str) -> Vec<u8> {
        if self.state < State::Authenticated {
            return Response::no(tag, "NO Not authenticated").to_wire();
        }
        // Minimal static response; full implementation reads from Maildir
        let mut out = Vec::new();
        out.extend(Response::untagged("LIST (\\HasNoChildren) \".\" INBOX").to_wire());
        out.extend(Response::untagged("LIST (\\HasNoChildren) \".\" Sent").to_wire());
        out.extend(Response::untagged("LIST (\\HasNoChildren) \".\" Drafts").to_wire());
        out.extend(Response::untagged("LIST (\\HasNoChildren) \".\" Trash").to_wire());
        out.extend(Response::untagged("LIST (\\HasNoChildren) \".\" Junk").to_wire());
        out.extend(Response::ok(tag, "LIST completed").to_wire());
        out
    }

    fn do_status(&mut self, tag: &str, mailbox: &str, items: &[StatusItem]) -> Vec<u8> {
        if self.state < State::Authenticated {
            return Response::no(tag, "NO Not authenticated").to_wire();
        }
        // Stub: return zeroes for all requested items
        let parts: Vec<String> = items.iter().map(|i| match i {
            StatusItem::Messages    => "MESSAGES 0".into(),
            StatusItem::Recent      => "RECENT 0".into(),
            StatusItem::UidNext     => "UIDNEXT 1".into(),
            StatusItem::UidValidity => "UIDVALIDITY 1".into(),
            StatusItem::Unseen      => "UNSEEN 0".into(),
        }).collect();
        let mut out = Vec::new();
        out.extend(Response::untagged(format!("STATUS {} ({})", mailbox, parts.join(" "))).to_wire());
        out.extend(Response::ok(tag, "STATUS completed").to_wire());
        out
    }

    fn do_fetch(&mut self, tag: &str, _seq: &str, _items: &[FetchItem], _maildir: &Maildir) -> Vec<u8> {
        if self.state != State::Selected {
            return Response::no(tag, "NO No mailbox selected").to_wire();
        }
        // Stub: no messages
        Response::ok(tag, "FETCH completed").to_wire()
    }

    fn do_store(&mut self, tag: &str, _seq: &str, _flags: &[String], _silent: bool, _maildir: &Maildir) -> Vec<u8> {
        if self.state != State::Selected {
            return Response::no(tag, "NO No mailbox selected").to_wire();
        }
        Response::ok(tag, "STORE completed").to_wire()
    }

    fn do_expunge(&mut self, tag: &str, _maildir: &Maildir) -> Vec<u8> {
        if self.state != State::Selected {
            return Response::no(tag, "NO No mailbox selected").to_wire();
        }
        Response::ok(tag, "EXPUNGE completed").to_wire()
    }

    pub fn is_closed(&self) -> bool {
        self.state == State::Logout
    }
}

impl PartialOrd for State {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let rank = |s: &State| match s {
            State::NotAuthenticated => 0,
            State::Authenticated    => 1,
            State::Selected         => 2,
            State::Logout           => 3,
        };
        rank(self).partial_cmp(&rank(other))
    }
}
