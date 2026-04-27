//! IMAP4rev2 session state machine.

use crate::command::ImapCommand;
use crate::response::ImapResponse;

#[derive(Debug, Clone, PartialEq)]
pub enum ImapState {
    NotAuthenticated,
    Authenticated { user: String },
    Selected     { user: String, mailbox: String, readonly: bool },
    Logout,
}

pub struct ImapSession {
    pub state: ImapState,
}

impl ImapSession {
    pub fn new() -> Self {
        Self { state: ImapState::NotAuthenticated }
    }

    /// Returns the responses to send for this command.
    pub fn step(
        &mut self,
        tag: &str,
        cmd: ImapCommand,
        verify_auth: &dyn Fn(&str, &str) -> Option<String>,
        // Returns (messages, unseen, uid_validity, uid_next) for a mailbox
        mailbox_info: &dyn Fn(&str, &str) -> Option<(u32, u32, u32, u32)>,
    ) -> Vec<ImapResponse> {
        use ImapCommand::*;
        use ImapState::*;

        match (&self.state.clone(), cmd) {
            (_, Capability) => {
                let mut r = ImapResponse::capability();
                r.push(ImapResponse::tagged_ok(tag, "CAPABILITY completed"));
                r
            }
            (_, Noop) => vec![ImapResponse::tagged_ok(tag, "NOOP completed")],
            (_, Logout) => {
                self.state = Logout;
                vec![
                    ImapResponse::untagged("BYE Logging out"),
                    ImapResponse::tagged_ok(tag, "LOGOUT completed"),
                ]
            }

            (NotAuthenticated, Login { username, password }) => {
                match verify_auth(&username, &password) {
                    Some(user) => {
                        self.state = Authenticated { user };
                        vec![ImapResponse::tagged_ok(tag, "LOGIN completed")]
                    }
                    None => vec![ImapResponse::tagged_no(tag, "[AUTHENTICATIONFAILED] Invalid credentials")],
                }
            }

            (Authenticated { user } | Selected { user, .. }, Select(mbox)) => {
                let user = user.clone();
                match mailbox_info(&user, &mbox) {
                    None => vec![ImapResponse::tagged_no(tag, "No such mailbox")],
                    Some((messages, unseen, uid_validity, uid_next)) => {
                        let mut r = vec![
                            ImapResponse::untagged(format!("{} EXISTS", messages)),
                            ImapResponse::untagged("0 RECENT"),
                            ImapResponse::untagged(format!("OK [UIDVALIDITY {}] UIDs valid", uid_validity)),
                            ImapResponse::untagged(format!("OK [UIDNEXT {}] Predicted next UID", uid_next)),
                            ImapResponse::untagged("OK [UNSEEN 1] Message 1 is first unseen"),
                            ImapResponse::untagged("FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)"),
                        ];
                        self.state = Selected { user, mailbox: mbox, readonly: false };
                        r.push(ImapResponse::tagged_ok(tag, "[READ-WRITE] SELECT completed"));
                        r
                    }
                }
            }

            (Authenticated { user } | Selected { user, .. }, Examine(mbox)) => {
                let user = user.clone();
                match mailbox_info(&user, &mbox) {
                    None => vec![ImapResponse::tagged_no(tag, "No such mailbox")],
                    Some((messages, _, uid_validity, uid_next)) => {
                        self.state = Selected { user, mailbox: mbox, readonly: true };
                        vec![
                            ImapResponse::untagged(format!("{} EXISTS", messages)),
                            ImapResponse::tagged_ok(tag, "[READ-ONLY] EXAMINE completed"),
                        ]
                    }
                }
            }

            (Authenticated { user } | Selected { user, .. }, List { reference, mailbox }) => {
                // Placeholder: real impl scans Maildir folders
                let user = user.clone();
                vec![
                    ImapResponse::untagged(r#"LIST (\HasNoChildren) "/" INBOX"#),
                    ImapResponse::tagged_ok(tag, "LIST completed"),
                ]
            }

            (_, _) => vec![
                ImapResponse::tagged_bad(tag, "Command not allowed in this state")
            ],
        }
    }
}
