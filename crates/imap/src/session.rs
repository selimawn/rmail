//! IMAP4rev2 session state machine.
//! No I/O done here — caller feeds lines, receives bytes to send back.

use crate::command::{self, Command, FetchItem, StatusItem, StoreOp};
use crate::response::Response;
use rmail_config::Config;
use rmail_core::Address;
use rmail_mailbox::{FlagOp, Maildir};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    NotAuthenticated,
    Authenticated,
    Selected,
    Logout,
}

pub struct Session {
    state: State,
    user: Option<Address>,
    selected: Option<String>,
    read_only: bool,
    tls_active: bool,
}

pub enum Action {
    Reply(Vec<u8>),
    UpgradeTls(Vec<u8>),
    Close(Vec<u8>),
}

struct StoreRequest<'a> {
    sequence: &'a str,
    uid: bool,
    op: StoreOp,
    flags: &'a [String],
    silent: bool,
}

impl Session {
    pub fn new(tls_active: bool) -> (Self, Vec<u8>) {
        let greeting = Response::untagged(format!(
            "OK [CAPABILITY {}] rmail ready",
            Response::capability_tokens(tls_active)
        ))
        .to_wire();
        (
            Self {
                state: State::NotAuthenticated,
                user: None,
                selected: None,
                read_only: false,
                tls_active,
            },
            greeting,
        )
    }

    /// Feed one command line. Returns bytes to send to the client.
    pub async fn step(&mut self, line: &[u8], config: &Config, maildir: &Maildir) -> Action {
        let (command_line, literal) = split_literal_command(line);
        let line_str = match std::str::from_utf8(command_line) {
            Ok(s) => s.trim_end_matches(['\r', '\n']),
            Err(_) => return Action::Reply(Response::bad("*", "BAD Non-UTF8 input").to_wire()),
        };

        if line_str.eq_ignore_ascii_case("DONE") {
            return Action::Reply(Response::untagged("OK IDLE terminated").to_wire());
        }

        let (tag, mut cmd) = match command::parse(line_str) {
            Ok(v) => v,
            Err(_) => {
                return Action::Reply(Response::bad("*", "BAD Command parse error").to_wire())
            }
        };
        if let (Command::Append { literal: dst, .. }, Some(src)) = (&mut cmd, literal) {
            *dst = src.to_vec();
        }

        debug!(state = ?self.state, ?cmd, "IMAP command");
        self.dispatch(&tag, cmd, config, maildir).await
    }

    async fn dispatch(
        &mut self,
        tag: &str,
        cmd: Command,
        config: &Config,
        maildir: &Maildir,
    ) -> Action {
        match cmd {
            Command::Capability => {
                let mut out = Response::capability(self.tls_active).to_wire();
                out.extend(Response::ok(tag, "CAPABILITY completed").to_wire());
                Action::Reply(out)
            }
            Command::Noop => Action::Reply(Response::ok(tag, "NOOP completed").to_wire()),
            Command::Logout => {
                self.state = State::Logout;
                let mut out = Response::bye("Logging out").to_wire();
                out.extend(Response::ok(tag, "LOGOUT completed").to_wire());
                Action::Close(out)
            }
            Command::StartTls => {
                if self.tls_active {
                    Action::Reply(Response::bad(tag, "BAD Already using TLS").to_wire())
                } else if self.state != State::NotAuthenticated {
                    Action::Reply(
                        Response::bad(tag, "BAD STARTTLS only valid before authentication")
                            .to_wire(),
                    )
                } else {
                    Action::UpgradeTls(Response::ok(tag, "Begin TLS negotiation now").to_wire())
                }
            }
            Command::Authenticate(mech) => Action::Reply(self.do_authenticate(tag, &mech)),
            Command::Login { username, password } => {
                Action::Reply(self.do_login(tag, &username, &password, config))
            }
            Command::Select(mb) => Action::Reply(self.do_select(tag, &mb, false, maildir).await),
            Command::Examine(mb) => Action::Reply(self.do_select(tag, &mb, true, maildir).await),
            Command::List { reference, pattern } => {
                Action::Reply(self.do_list(tag, &reference, &pattern, maildir).await)
            }
            Command::Lsub { reference, pattern } => {
                Action::Reply(self.do_list(tag, &reference, &pattern, maildir).await)
            }
            Command::Status { mailbox, items } => {
                Action::Reply(self.do_status(tag, &mailbox, &items, maildir).await)
            }
            Command::Fetch { sequence, items } => {
                Action::Reply(self.do_fetch(tag, &sequence, &items, maildir, false).await)
            }
            Command::UidFetch { sequence, items } => {
                Action::Reply(self.do_fetch(tag, &sequence, &items, maildir, true).await)
            }
            Command::Store {
                sequence,
                op,
                flags,
                silent,
            } => Action::Reply(
                self.do_store(
                    tag,
                    StoreRequest {
                        sequence: &sequence,
                        uid: false,
                        op,
                        flags: &flags,
                        silent,
                    },
                    maildir,
                )
                .await,
            ),
            Command::UidStore {
                sequence,
                op,
                flags,
                silent,
            } => Action::Reply(
                self.do_store(
                    tag,
                    StoreRequest {
                        sequence: &sequence,
                        uid: true,
                        op,
                        flags: &flags,
                        silent,
                    },
                    maildir,
                )
                .await,
            ),
            Command::Expunge | Command::UidExpunge(_) => {
                Action::Reply(self.do_expunge(tag, maildir).await)
            }
            Command::Close | Command::Unselect => {
                self.selected = None;
                self.read_only = false;
                self.state = State::Authenticated;
                Action::Reply(Response::ok(tag, "CLOSE completed").to_wire())
            }
            Command::Idle => Action::Reply(b"+ idling\r\n".to_vec()),
            Command::Search(criteria) => {
                Action::Reply(self.do_search(tag, &criteria, maildir).await)
            }
            Command::Append {
                mailbox,
                flags,
                literal,
            } => Action::Reply(
                self.do_append(tag, &mailbox, &flags, &literal, maildir)
                    .await,
            ),
            Command::Copy { sequence, mailbox } => Action::Reply(
                self.do_copy_move(tag, &sequence, false, &mailbox, false, maildir)
                    .await,
            ),
            Command::Move { sequence, mailbox } => Action::Reply(
                self.do_copy_move(tag, &sequence, false, &mailbox, true, maildir)
                    .await,
            ),
            Command::UidCopy { sequence, mailbox } => Action::Reply(
                self.do_copy_move(tag, &sequence, true, &mailbox, false, maildir)
                    .await,
            ),
            Command::UidMove { sequence, mailbox } => Action::Reply(
                self.do_copy_move(tag, &sequence, true, &mailbox, true, maildir)
                    .await,
            ),
            Command::Create(mailbox) => Action::Reply(self.do_create(tag, &mailbox, maildir).await),
            Command::Delete(mailbox) => Action::Reply(self.do_delete(tag, &mailbox, maildir).await),
            Command::Rename { from, to } => {
                Action::Reply(self.do_rename(tag, &from, &to, maildir).await)
            }
            Command::Subscribe(_) | Command::Unsubscribe(_) => {
                Action::Reply(Response::ok(tag, "subscription updated").to_wire())
            }
            _ => Action::Reply(Response::bad(tag, "BAD Not implemented").to_wire()),
        }
    }

    // ─── AUTH ────────────────────────────────────────────────────────────────

    fn do_login(&mut self, tag: &str, username: &str, password: &str, config: &Config) -> Vec<u8> {
        if self.state != State::NotAuthenticated {
            return Response::bad(tag, "BAD Already authenticated").to_wire();
        }
        if !self.tls_active {
            return Response::no(tag, "NO [PRIVACYREQUIRED] STARTTLS required").to_wire();
        }
        if let Some(user) = config.find_user(username) {
            if rmail_auth::password::verify(password, &user.password_hash) {
                let addr = Address::parse(username).unwrap_or_else(|_| Address::null());
                self.user = Some(addr);
                self.state = State::Authenticated;
                info!(%username, "IMAP login");
                return Response::ok(tag, "LOGIN completed").to_wire();
            }
        }
        warn!(%username, "IMAP login failed");
        Response::no(tag, "NO [AUTHENTICATIONFAILED] Invalid credentials").to_wire()
    }

    fn do_authenticate(&self, tag: &str, mech: &str) -> Vec<u8> {
        match mech.to_ascii_uppercase().as_str() {
            "PLAIN" | "LOGIN" => Response::no(
                tag,
                "NO Use LOGIN; SASL challenge flow is not enabled in this listener",
            )
            .to_wire(),
            _ => Response::no(tag, "NO Unsupported authentication mechanism").to_wire(),
        }
    }

    // ─── SELECT ──────────────────────────────────────────────────────────────

    async fn do_select(
        &mut self,
        tag: &str,
        mailbox: &str,
        read_only: bool,
        maildir: &Maildir,
    ) -> Vec<u8> {
        if self.state < State::Authenticated {
            return Response::no(tag, "NO Not authenticated").to_wire();
        }
        let user = match &self.user {
            Some(u) => u.clone(),
            None => return Response::no(tag, "NO Not authenticated").to_wire(),
        };

        let entries = match maildir.list_messages(&user, mailbox).await {
            Ok(e) => e,
            Err(_) => return Response::no(tag, "NO Mailbox does not exist").to_wire(),
        };

        let exists = entries.len();
        let recent = entries.iter().filter(|e| !e.seen && !e.deleted).count();
        let unseen = entries
            .iter()
            .position(|e| !e.seen)
            .map(|i| i + 1)
            .unwrap_or(0);
        let uid_next = next_uid(&entries);

        self.selected = Some(mailbox.to_owned());
        self.read_only = read_only;
        self.state = State::Selected;

        let mut out = Vec::new();
        out.extend(Response::untagged(format!("{} EXISTS", exists)).to_wire());
        out.extend(Response::untagged(format!("{} RECENT", recent)).to_wire());
        out.extend(
            Response::untagged("FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)").to_wire(),
        );
        if unseen > 0 {
            out.extend(Response::ok("*", format!("[UNSEEN {}] first unseen", unseen)).to_wire());
        }
        out.extend(
            Response::ok("*", format!("[UIDNEXT {}] predicted next UID", uid_next)).to_wire(),
        );
        out.extend(
            Response::ok(
                "*",
                format!("[UIDVALIDITY {}] UIDs valid", uid_validity(&user, mailbox)),
            )
            .to_wire(),
        );
        let mode = if read_only { "READ-ONLY" } else { "READ-WRITE" };
        out.extend(Response::ok(tag, format!("[{}] SELECT completed", mode)).to_wire());
        out
    }

    // ─── LIST ────────────────────────────────────────────────────────────────

    async fn do_list(
        &mut self,
        tag: &str,
        reference: &str,
        pattern: &str,
        maildir: &Maildir,
    ) -> Vec<u8> {
        if self.state < State::Authenticated {
            return Response::no(tag, "NO Not authenticated").to_wire();
        }
        let user = match &self.user {
            Some(u) => u.clone(),
            None => return Response::no(tag, "NO Not authenticated").to_wire(),
        };

        let folders = match maildir.list_folders(&user).await {
            Ok(f) => f,
            Err(e) => {
                warn!("LIST error: {}", e);
                vec!["INBOX".to_owned()]
            }
        };

        let mut out = Vec::new();
        for folder in &folders {
            if list_matches(reference, pattern, folder) {
                out.extend(
                    Response::untagged(format!("LIST (\\HasNoChildren) \".\" \"{}\"", folder))
                        .to_wire(),
                );
            }
        }
        out.extend(Response::ok(tag, "LIST completed").to_wire());
        out
    }

    // ─── STATUS ──────────────────────────────────────────────────────────────

    async fn do_status(
        &mut self,
        tag: &str,
        mailbox: &str,
        items: &[StatusItem],
        maildir: &Maildir,
    ) -> Vec<u8> {
        if self.state < State::Authenticated {
            return Response::no(tag, "NO Not authenticated").to_wire();
        }
        let user = match &self.user {
            Some(u) => u.clone(),
            None => return Response::no(tag, "NO Not authenticated").to_wire(),
        };

        let entries = maildir
            .list_messages(&user, mailbox)
            .await
            .unwrap_or_default();
        let messages = entries.len();
        let unseen = entries.iter().filter(|e| !e.seen).count();
        let recent = entries.iter().filter(|e| !e.seen && !e.deleted).count();
        let uid_next = next_uid(&entries);
        let uid_validity = uid_validity(&user, mailbox);

        let parts: Vec<String> = items
            .iter()
            .map(|i| match i {
                StatusItem::Messages => format!("MESSAGES {}", messages),
                StatusItem::Recent => format!("RECENT {}", recent),
                StatusItem::UidNext => format!("UIDNEXT {}", uid_next),
                StatusItem::UidValidity => format!("UIDVALIDITY {}", uid_validity),
                StatusItem::Unseen => format!("UNSEEN {}", unseen),
            })
            .collect();

        let mut out = Vec::new();
        out.extend(
            Response::untagged(format!("STATUS {} ({})", mailbox, parts.join(" "))).to_wire(),
        );
        out.extend(Response::ok(tag, "STATUS completed").to_wire());
        out
    }

    // ─── FETCH ───────────────────────────────────────────────────────────────

    async fn do_fetch(
        &mut self,
        tag: &str,
        seq: &str,
        items: &[FetchItem],
        maildir: &Maildir,
        _uid: bool,
    ) -> Vec<u8> {
        if self.state != State::Selected {
            return Response::no(tag, "NO No mailbox selected").to_wire();
        }
        let (user, folder) = match (&self.user, &self.selected) {
            (Some(u), Some(f)) => (u.clone(), f.clone()),
            _ => return Response::no(tag, "NO Not selected").to_wire(),
        };

        let entries = match maildir.list_messages(&user, &folder).await {
            Ok(e) => e,
            Err(e) => {
                warn!("FETCH list_messages error: {}", e);
                return Response::no(tag, "NO Internal error").to_wire();
            }
        };

        let indices = if _uid {
            parse_uid_set(seq, &entries)
        } else {
            parse_sequence_set(seq, entries.len())
        };
        let mut out = Vec::new();

        for idx in indices {
            if idx >= entries.len() {
                continue;
            }
            let entry = &entries[idx];
            let seq_num = idx + 1;

            let mut parts: Vec<Vec<u8>> = Vec::new();

            for item in items {
                match item {
                    FetchItem::Flags => {
                        let mut flags = Vec::new();
                        if entry.seen {
                            flags.push("\\Seen");
                        }
                        if entry.flagged {
                            flags.push("\\Flagged");
                        }
                        if entry.deleted {
                            flags.push("\\Deleted");
                        }
                        if entry.answered {
                            flags.push("\\Answered");
                        }
                        if entry.draft {
                            flags.push("\\Draft");
                        }
                        parts.push(format!("FLAGS ({})", flags.join(" ")).into_bytes());
                    }
                    FetchItem::Rfc822Size => {
                        parts.push(format!("RFC822.SIZE {}", entry.size).into_bytes());
                    }
                    FetchItem::Uid => {
                        parts.push(
                            format!("UID {}", uid_for_filename(&entry.filename)).into_bytes(),
                        );
                    }
                    FetchItem::InternalDate => {
                        let date = internal_date(entry).await;
                        parts.push(format!("INTERNALDATE \"{}\"", date).into_bytes());
                    }
                    FetchItem::Rfc822 | FetchItem::Body | FetchItem::BodyPeek(_) => {
                        match maildir.read_message(&entry.path).await {
                            Ok(body) => {
                                let (label, payload) = match item {
                                    FetchItem::Rfc822 => ("RFC822".to_owned(), body),
                                    FetchItem::Body => ("BODY[]".to_owned(), body),
                                    FetchItem::BodyPeek(section) => body_section(section, &body),
                                    _ => unreachable!(),
                                };
                                let mut part =
                                    format!("{} {{{}}}\r\n", label, payload.len()).into_bytes();
                                part.extend_from_slice(&payload);
                                parts.push(part);
                            }
                            Err(e) => warn!("FETCH read_message: {}", e),
                        }
                    }
                    FetchItem::Rfc822Header => match maildir.read_message(&entry.path).await {
                        Ok(body) => {
                            let headers = extract_headers(&body);
                            let mut part =
                                format!("RFC822.HEADER {{{}}}\r\n", headers.len()).into_bytes();
                            part.extend_from_slice(&headers);
                            parts.push(part);
                        }
                        Err(e) => warn!("FETCH read_message headers: {}", e),
                    },
                    FetchItem::Envelope => match maildir.read_message(&entry.path).await {
                        Ok(body) => {
                            let env = build_envelope_string(&body);
                            parts.push(format!("ENVELOPE {}", env).into_bytes());
                        }
                        Err(e) => warn!("FETCH envelope: {}", e),
                    },
                    FetchItem::BodyStructure => {
                        parts.push(
                            b"BODYSTRUCTURE (\"TEXT\" \"PLAIN\" NIL NIL NIL \"7BIT\" 0 0)".to_vec(),
                        );
                    }
                }
            }

            if !parts.is_empty() {
                out.extend_from_slice(format!("* {} FETCH (", seq_num).as_bytes());
                for (i, part) in parts.iter().enumerate() {
                    if i > 0 {
                        out.push(b' ');
                    }
                    out.extend_from_slice(part);
                }
                out.extend_from_slice(b")\r\n");
            }
        }

        out.extend(Response::ok(tag, "FETCH completed").to_wire());
        out
    }

    // ─── STORE ───────────────────────────────────────────────────────────────

    async fn do_store(
        &mut self,
        tag: &str,
        request: StoreRequest<'_>,
        maildir: &Maildir,
    ) -> Vec<u8> {
        if self.state != State::Selected {
            return Response::no(tag, "NO No mailbox selected").to_wire();
        }
        let (user, folder) = match (&self.user, &self.selected) {
            (Some(u), Some(f)) => (u.clone(), f.clone()),
            _ => return Response::no(tag, "NO Not selected").to_wire(),
        };

        let entries = match maildir.list_messages(&user, &folder).await {
            Ok(e) => e,
            Err(_) => return Response::no(tag, "NO Internal error").to_wire(),
        };

        if self.read_only {
            return Response::no(tag, "NO Mailbox is read-only").to_wire();
        }

        let indices = if request.uid {
            parse_uid_set(request.sequence, &entries)
        } else {
            parse_sequence_set(request.sequence, entries.len())
        };
        let maildir_flags = flags_to_maildir(request.flags);
        let op = match request.op {
            StoreOp::Add => FlagOp::Add,
            StoreOp::Remove => FlagOp::Remove,
            StoreOp::Replace => FlagOp::Replace,
        };
        let mut out = Vec::new();

        for idx in indices {
            if idx >= entries.len() {
                continue;
            }
            let entry = &entries[idx];

            match maildir.set_flags(&entry.path, &maildir_flags, op).await {
                Ok(new_path) => {
                    if !request.silent {
                        let mut updated = entry.clone();
                        updated.path = new_path;
                        updated.seen =
                            apply_flag_bool(entry.seen, maildir_flags.contains(&'S'), op);
                        updated.flagged =
                            apply_flag_bool(entry.flagged, maildir_flags.contains(&'F'), op);
                        updated.deleted =
                            apply_flag_bool(entry.deleted, maildir_flags.contains(&'T'), op);
                        out.extend(
                            Response::untagged(format!(
                                "{} FETCH (FLAGS ({}))",
                                idx + 1,
                                imap_flags(&updated).join(" ")
                            ))
                            .to_wire(),
                        );
                    }
                }
                Err(e) => warn!("STORE set_flags: {}", e),
            }
        }

        out.extend(Response::ok(tag, "STORE completed").to_wire());
        out
    }

    async fn do_append(
        &mut self,
        tag: &str,
        mailbox: &str,
        flags: &[String],
        literal: &[u8],
        maildir: &Maildir,
    ) -> Vec<u8> {
        if self.state < State::Authenticated {
            return Response::no(tag, "NO Not authenticated").to_wire();
        }
        let Some(user) = &self.user else {
            return Response::no(tag, "NO Not authenticated").to_wire();
        };
        let maildir_flags = flags_to_maildir(flags).iter().collect::<String>();
        match maildir
            .append_to_folder(user, mailbox, literal, &maildir_flags)
            .await
        {
            Ok(_) => Response::ok(tag, "APPEND completed").to_wire(),
            Err(e) => Response::no(tag, format!("NO APPEND failed: {}", e)).to_wire(),
        }
    }

    async fn do_copy_move(
        &mut self,
        tag: &str,
        seq: &str,
        uid: bool,
        mailbox: &str,
        move_after_copy: bool,
        maildir: &Maildir,
    ) -> Vec<u8> {
        if self.state != State::Selected {
            return Response::no(tag, "NO No mailbox selected").to_wire();
        }
        if move_after_copy && self.read_only {
            return Response::no(tag, "NO Mailbox is read-only").to_wire();
        }
        let (user, folder) = match (&self.user, &self.selected) {
            (Some(u), Some(f)) => (u.clone(), f.clone()),
            _ => return Response::no(tag, "NO Not selected").to_wire(),
        };
        let entries = match maildir.list_messages(&user, &folder).await {
            Ok(e) => e,
            Err(_) => return Response::no(tag, "NO Internal error").to_wire(),
        };
        let indices = if uid {
            parse_uid_set(seq, &entries)
        } else {
            parse_sequence_set(seq, entries.len())
        };
        for idx in indices {
            if let Some(entry) = entries.get(idx) {
                if let Err(e) = maildir.copy_message(&user, mailbox, entry).await {
                    return Response::no(tag, format!("NO COPY failed: {}", e)).to_wire();
                }
                if move_after_copy {
                    let _ = maildir.set_flags(&entry.path, &['T'], FlagOp::Add).await;
                }
            }
        }
        if move_after_copy {
            self.do_expunge(tag, maildir).await
        } else {
            Response::ok(tag, "COPY completed").to_wire()
        }
    }

    async fn do_create(&self, tag: &str, mailbox: &str, maildir: &Maildir) -> Vec<u8> {
        let Some(user) = &self.user else {
            return Response::no(tag, "NO Not authenticated").to_wire();
        };
        match maildir.create_folder(user, mailbox).await {
            Ok(_) => Response::ok(tag, "CREATE completed").to_wire(),
            Err(e) => Response::no(tag, format!("NO CREATE failed: {}", e)).to_wire(),
        }
    }

    async fn do_delete(&self, tag: &str, mailbox: &str, maildir: &Maildir) -> Vec<u8> {
        let Some(user) = &self.user else {
            return Response::no(tag, "NO Not authenticated").to_wire();
        };
        match maildir.delete_folder(user, mailbox).await {
            Ok(_) => Response::ok(tag, "DELETE completed").to_wire(),
            Err(e) => Response::no(tag, format!("NO DELETE failed: {}", e)).to_wire(),
        }
    }

    async fn do_rename(&self, tag: &str, from: &str, to: &str, maildir: &Maildir) -> Vec<u8> {
        let Some(user) = &self.user else {
            return Response::no(tag, "NO Not authenticated").to_wire();
        };
        match maildir.rename_folder(user, from, to).await {
            Ok(_) => Response::ok(tag, "RENAME completed").to_wire(),
            Err(e) => Response::no(tag, format!("NO RENAME failed: {}", e)).to_wire(),
        }
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
            Ok(e) => e,
            Err(_) => return Response::no(tag, "NO Internal error").to_wire(),
        };

        let mut out = Vec::new();
        // Iterate in reverse so sequence numbers stay valid as we remove
        for (idx, entry) in entries.iter().enumerate().rev() {
            if entry.deleted {
                match maildir.expunge(&entry.path).await {
                    Ok(_) => {
                        out.extend(Response::untagged(format!("{} EXPUNGE", idx + 1)).to_wire());
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

        let entries = maildir
            .list_messages(&user, &folder)
            .await
            .unwrap_or_default();
        let criteria = tokenize_search(criteria);

        let matching: Vec<String> = entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| {
                let body = std::fs::read(&e.path).unwrap_or_default();
                let matches = search_matches(&criteria, e, &body);
                if matches {
                    Some((i + 1).to_string())
                } else {
                    None
                }
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

    pub fn is_closed(&self) -> bool {
        self.state == State::Logout
    }

    pub fn mark_tls_active(&mut self) {
        self.tls_active = true;
        self.state = State::NotAuthenticated;
        self.user = None;
        self.selected = None;
    }
}

fn split_literal_command(line: &[u8]) -> (&[u8], Option<&[u8]>) {
    if let Some(pos) = line.windows(2).position(|w| w == b"\r\n") {
        let (cmd, rest) = line.split_at(pos + 2);
        if std::str::from_utf8(cmd)
            .ok()
            .and_then(|s| s.trim_end_matches(['\r', '\n']).rfind('{').map(|_| ()))
            .is_some()
        {
            let rest = rest.strip_suffix(b"\r\n").unwrap_or(rest);
            return (cmd, Some(rest));
        }
    }
    (line, None)
}

// ─── Sequence set parser ─────────────────────────────────────────────────────

/// Parse an IMAP sequence set like "1", "1:3", "1,3,5", "1:*"
/// Returns 0-based indices into a list of `count` messages.
fn parse_sequence_set(seq: &str, count: usize) -> Vec<usize> {
    if count == 0 {
        return vec![];
    }
    let mut result = std::collections::BTreeSet::new();
    for part in seq.split(',') {
        if let Some((start, end)) = part.split_once(':') {
            let s = parse_seq_num(start, count);
            let e = parse_seq_num(end, count);
            for i in s.min(e)..=s.max(e) {
                if i > 0 {
                    result.insert(i - 1);
                }
            }
        } else {
            let n = parse_seq_num(part, count);
            if n > 0 {
                result.insert(n - 1);
            }
        }
    }
    result.into_iter().filter(|&i| i < count).collect()
}

fn parse_seq_num(s: &str, count: usize) -> usize {
    if s == "*" {
        count
    } else {
        s.parse().unwrap_or(0)
    }
}

fn parse_uid_set(seq: &str, entries: &[rmail_mailbox::MaildirEntry]) -> Vec<usize> {
    if entries.is_empty() {
        return vec![];
    }
    let max_uid = entries
        .iter()
        .map(|e| uid_for_filename(&e.filename))
        .max()
        .unwrap_or(1);
    let mut result = std::collections::BTreeSet::new();
    for part in seq.split(',') {
        if let Some((start, end)) = part.split_once(':') {
            let s = parse_uid_num(start, max_uid);
            let e = parse_uid_num(end, max_uid);
            let lo = s.min(e);
            let hi = s.max(e);
            for (idx, entry) in entries.iter().enumerate() {
                let uid = uid_for_filename(&entry.filename);
                if uid >= lo && uid <= hi {
                    result.insert(idx);
                }
            }
        } else {
            let wanted = parse_uid_num(part, max_uid);
            for (idx, entry) in entries.iter().enumerate() {
                if uid_for_filename(&entry.filename) == wanted {
                    result.insert(idx);
                }
            }
        }
    }
    result.into_iter().collect()
}

fn parse_uid_num(s: &str, max_uid: u32) -> u32 {
    if s == "*" {
        max_uid
    } else {
        s.parse().unwrap_or(0)
    }
}

fn list_matches(reference: &str, pattern: &str, folder: &str) -> bool {
    let pat = if reference.is_empty() {
        pattern.to_owned()
    } else if pattern.is_empty() {
        reference.to_owned()
    } else {
        format!("{}.{}", reference.trim_end_matches('.'), pattern)
    };
    if pat.is_empty() {
        return folder == "INBOX";
    }
    wildcard_match(&pat, folder)
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut p, mut v) = (0, 0);
    let mut star = None;
    let mut star_match = 0;
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == value[v] || pattern[p] == b'%' && value[v] != b'.') {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            star_match = v;
            p += 1;
        } else if let Some(star_pos) = star {
            p = star_pos + 1;
            star_match += 1;
            v = star_match;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

fn next_uid(entries: &[rmail_mailbox::MaildirEntry]) -> u32 {
    entries
        .iter()
        .map(|e| uid_for_filename(&e.filename))
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

fn uid_for_filename(filename: &str) -> u32 {
    let base = filename.split_once('.').and_then(|(ts, rest)| {
        let ts = ts.parse::<u32>().ok()?;
        let counter = rest
            .split_once('_')
            .and_then(|(_, suffix)| suffix.split('.').next())
            .and_then(|n| n.parse::<u32>().ok())
            .unwrap_or(0);
        let epoch = ts.saturating_sub(1_600_000_000);
        Some(epoch.saturating_mul(1024).saturating_add(counter.min(1023)))
    });
    if let Some(uid) = base {
        return uid.max(1);
    }
    let mut hash: u32 = 2_166_136_261;
    for b in filename.as_bytes() {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(16_777_619);
    }
    hash.max(1)
}

// ─── Message helpers ─────────────────────────────────────────────────────────

fn uid_validity(user: &Address, mailbox: &str) -> i64 {
    let key = format!("{}:{}:{}", user.local, user.domain, mailbox);
    let mut hash: i64 = 1_704_067_200; // 2024-01-01; stable non-zero base.
    for b in key.as_bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(*b as i64);
    }
    hash.unsigned_abs().min(i64::MAX as u64) as i64
}

fn flags_to_maildir(flags: &[String]) -> Vec<char> {
    let mut out = Vec::new();
    for flag in flags {
        match flag.to_ascii_uppercase().as_str() {
            "\\SEEN" => out.push('S'),
            "\\FLAGGED" => out.push('F'),
            "\\DELETED" => out.push('T'),
            "\\ANSWERED" => out.push('R'),
            "\\DRAFT" => out.push('D'),
            _ => {}
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn imap_flags(entry: &rmail_mailbox::MaildirEntry) -> Vec<&'static str> {
    let mut flags = Vec::new();
    if entry.seen {
        flags.push("\\Seen");
    }
    if entry.flagged {
        flags.push("\\Flagged");
    }
    if entry.deleted {
        flags.push("\\Deleted");
    }
    if entry.answered {
        flags.push("\\Answered");
    }
    if entry.draft {
        flags.push("\\Draft");
    }
    flags
}

fn apply_flag_bool(current: bool, mentioned: bool, op: FlagOp) -> bool {
    match op {
        FlagOp::Add => current || mentioned,
        FlagOp::Remove => current && !mentioned,
        FlagOp::Replace => mentioned,
    }
}

async fn internal_date(entry: &rmail_mailbox::MaildirEntry) -> String {
    let dt = match tokio::fs::metadata(&entry.path)
        .await
        .and_then(|m| m.modified())
    {
        Ok(modified) => time::OffsetDateTime::from(modified),
        Err(_) => time::OffsetDateTime::now_utc(),
    };
    dt.format(time::macros::format_description!(
        "[day padding:zero]-[month repr:short]-[year] [hour]:[minute]:[second] [offset_hour sign:mandatory][offset_minute]"
    ))
    .unwrap_or_else(|_| "01-Jan-1970 00:00:00 +0000".to_owned())
}

/// Extract only the header section (everything before the first blank line).
fn extract_headers(raw: &[u8]) -> Vec<u8> {
    // Find \r\n\r\n or \n\n
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .or_else(|| raw.windows(2).position(|w| w == b"\n\n").map(|i| i + 2))
        .unwrap_or(raw.len());
    raw[..sep].to_vec()
}

fn body_section(section: &str, raw: &[u8]) -> (String, Vec<u8>) {
    let upper = section.to_ascii_uppercase();
    if upper.contains("HEADER.FIELDS") {
        let headers = extract_headers(raw);
        let wanted = section
            .split_once('(')
            .and_then(|(_, rest)| rest.split_once(')').map(|(fields, _)| fields))
            .map(|fields| {
                fields
                    .split_whitespace()
                    .map(|f| f.trim().to_ascii_lowercase())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if wanted.is_empty() {
            return (section.to_owned(), headers);
        }
        let text = String::from_utf8_lossy(&headers);
        let mut out = Vec::new();
        for line in text.lines() {
            if let Some((name, _)) = line.split_once(':') {
                if wanted.iter().any(|w| w == &name.to_ascii_lowercase()) {
                    out.extend_from_slice(line.as_bytes());
                    out.extend_from_slice(b"\r\n");
                }
            }
        }
        out.extend_from_slice(b"\r\n");
        return (section.to_owned(), out);
    }
    if upper.contains("HEADER") {
        return (section.to_owned(), extract_headers(raw));
    }
    if upper.contains("TEXT") {
        return (section.to_owned(), extract_body(raw));
    }
    (section.to_owned(), raw.to_vec())
}

fn tokenize_search(criteria: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for ch in criteria.chars() {
        match ch {
            '"' => quoted = !quoted,
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

fn search_matches(criteria: &[String], entry: &rmail_mailbox::MaildirEntry, raw: &[u8]) -> bool {
    if criteria.is_empty() {
        return true;
    }
    let headers = String::from_utf8_lossy(&extract_headers(raw)).to_string();
    let body = String::from_utf8_lossy(raw).to_ascii_lowercase();
    let mut i = 0;
    while i < criteria.len() {
        let key = criteria[i].to_ascii_uppercase();
        let matched = match key.as_str() {
            "ALL" => true,
            "UNSEEN" => !entry.seen,
            "SEEN" => entry.seen,
            "FLAGGED" => entry.flagged,
            "UNFLAGGED" => !entry.flagged,
            "DELETED" => entry.deleted,
            "UNDELETED" => !entry.deleted,
            "ANSWERED" => entry.answered,
            "UNANSWERED" => !entry.answered,
            "DRAFT" => entry.draft,
            "UNDRAFT" => !entry.draft,
            "LARGER" => {
                i += 1;
                criteria
                    .get(i)
                    .and_then(|n| n.parse::<u64>().ok())
                    .map(|n| entry.size > n)
                    .unwrap_or(false)
            }
            "SMALLER" => {
                i += 1;
                criteria
                    .get(i)
                    .and_then(|n| n.parse::<u64>().ok())
                    .map(|n| entry.size < n)
                    .unwrap_or(false)
            }
            "FROM" | "TO" | "CC" | "BCC" | "SUBJECT" => {
                i += 1;
                let needle = criteria
                    .get(i)
                    .map(|s| s.to_ascii_lowercase())
                    .unwrap_or_default();
                header_value(&headers, &key)
                    .map(|v| v.to_ascii_lowercase().contains(&needle))
                    .unwrap_or(false)
            }
            "BODY" | "TEXT" => {
                i += 1;
                let needle = criteria
                    .get(i)
                    .map(|s| s.to_ascii_lowercase())
                    .unwrap_or_default();
                body.contains(&needle)
            }
            _ => false,
        };
        if !matched {
            return false;
        }
        i += 1;
    }
    true
}

fn extract_body(raw: &[u8]) -> Vec<u8> {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| raw[i + 4..].to_vec())
        .or_else(|| {
            raw.windows(2)
                .position(|w| w == b"\n\n")
                .map(|i| raw[i + 2..].to_vec())
        })
        .unwrap_or_else(|| raw.to_vec())
}

/// Build a minimal IMAP ENVELOPE string from raw message headers.
fn build_envelope_string(raw: &[u8]) -> String {
    let headers_raw = extract_headers(raw);
    let text = String::from_utf8_lossy(&headers_raw);
    let date = header_value(&text, "Date").unwrap_or("NIL");
    let subject = header_value(&text, "Subject").unwrap_or("NIL");
    let from = header_value(&text, "From").unwrap_or("NIL");
    let to = header_value(&text, "To").unwrap_or("NIL");
    let msg_id = header_value(&text, "Message-ID").unwrap_or("NIL");
    format!(
        "(\"{}\" \"{}\" ((NIL NIL \"{}\" NIL)) NIL NIL ((NIL NIL \"{}\" NIL)) NIL NIL NIL \"{}\")",
        date, subject, from, to, msg_id
    )
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{}:", name);
    headers
        .lines()
        .find(|l| {
            l.to_ascii_lowercase()
                .starts_with(&prefix.to_ascii_lowercase())
        })
        .map(|l| l[prefix.len()..].trim())
}

impl PartialOrd for State {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let rank = |s: &State| match s {
            State::NotAuthenticated => 0u8,
            State::Authenticated => 1,
            State::Selected => 2,
            State::Logout => 3,
        };
        rank(self).partial_cmp(&rank(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmail_config::{Config, DeliveryConfig, DnsConfig, ServerConfig, StorageConfig, TlsConfig};
    use std::path::PathBuf;

    fn test_config() -> Config {
        Config {
            server: ServerConfig {
                hostname: "mail.example.com".into(),
                listen_smtp: vec!["127.0.0.1:0".parse().unwrap()],
                listen_imap: vec!["127.0.0.1:0".parse().unwrap()],
                max_message_mb: 25,
            },
            storage: StorageConfig {
                queue_dir: PathBuf::from("/tmp/rmail-test-queue"),
                mailbox_dir: PathBuf::from("/tmp/rmail-test-mail"),
            },
            tls: TlsConfig {
                cert: PathBuf::from("/tmp/cert.pem"),
                key: PathBuf::from("/tmp/key.pem"),
            },
            dns: DnsConfig::default(),
            delivery: DeliveryConfig::default(),
            domains: vec![],
            users: vec![],
        }
    }

    #[test]
    fn pre_tls_greeting_disables_login() {
        let (_session, greeting) = Session::new(false);
        let greeting = String::from_utf8(greeting).unwrap();
        assert!(greeting.contains("STARTTLS"));
        assert!(greeting.contains("LOGINDISABLED"));
        assert!(!greeting.contains("AUTH=PLAIN"));
    }

    #[test]
    fn tls_greeting_advertises_auth() {
        let (_session, greeting) = Session::new(true);
        let greeting = String::from_utf8(greeting).unwrap();
        assert!(greeting.contains("LITERAL+"));
        assert!(greeting.contains("MOVE"));
        assert!(!greeting.contains("AUTH=PLAIN"));
        assert!(!greeting.contains("LOGINDISABLED"));
    }

    #[tokio::test]
    async fn login_requires_tls() {
        let config = test_config();
        let maildir = Maildir::new(config.storage.mailbox_dir.clone());
        let (mut session, _) = Session::new(false);
        let action = session
            .step(b"a1 LOGIN alice@example.com secret\r\n", &config, &maildir)
            .await;
        let Action::Reply(reply) = action else {
            panic!("expected reply");
        };
        let reply = String::from_utf8(reply).unwrap();
        assert!(reply.contains("PRIVACYREQUIRED"));
    }
}
