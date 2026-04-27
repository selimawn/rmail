//! IMAP response builders.

use std::fmt;

#[derive(Debug)]
pub struct ImapResponse {
    pub tag:  String,   // "*" for untagged, "+" for continuation, or the client tag
    pub text: String,
}

impl ImapResponse {
    pub fn untagged(text: impl Into<String>) -> Self {
        Self { tag: "*".into(), text: text.into() }
    }
    pub fn tagged_ok(tag: &str, msg: impl Into<String>) -> Self {
        Self { tag: tag.to_owned(), text: format!("OK {}", msg.into()) }
    }
    pub fn tagged_no(tag: &str, msg: impl Into<String>) -> Self {
        Self { tag: tag.to_owned(), text: format!("NO {}", msg.into()) }
    }
    pub fn tagged_bad(tag: &str, msg: impl Into<String>) -> Self {
        Self { tag: tag.to_owned(), text: format!("BAD {}", msg.into()) }
    }
    pub fn continuation(msg: impl Into<String>) -> Self {
        Self { tag: "+".into(), text: msg.into() }
    }
    pub fn capability() -> Vec<Self> {
        vec![
            Self::untagged("CAPABILITY IMAP4rev2 AUTH=PLAIN AUTH=LOGIN"),
        ]
    }
}

impl fmt::Display for ImapResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} {}", self.tag, self.text)
    }
}
