//! IMAP response formatting.

#[derive(Debug, Clone)]
pub struct Response {
    pub tag: String, // "*" for untagged, tag for tagged
    pub kind: ResponseKind,
    pub text: String,
}

#[derive(Debug, Clone)]
pub enum ResponseKind {
    Ok,
    No,
    Bad,
    Preauth,
    Bye,
    // Untagged data responses
    Untagged,
}

impl Response {
    pub fn ok(tag: &str, text: impl Into<String>) -> Self {
        Self {
            tag: tag.to_owned(),
            kind: ResponseKind::Ok,
            text: text.into(),
        }
    }

    pub fn no(tag: &str, text: impl Into<String>) -> Self {
        Self {
            tag: tag.to_owned(),
            kind: ResponseKind::No,
            text: text.into(),
        }
    }

    pub fn bad(tag: &str, text: impl Into<String>) -> Self {
        Self {
            tag: tag.to_owned(),
            kind: ResponseKind::Bad,
            text: text.into(),
        }
    }

    pub fn untagged(text: impl Into<String>) -> Self {
        Self {
            tag: "*".to_owned(),
            kind: ResponseKind::Untagged,
            text: text.into(),
        }
    }

    pub fn bye(text: impl Into<String>) -> Self {
        Self {
            tag: "*".to_owned(),
            kind: ResponseKind::Bye,
            text: text.into(),
        }
    }

    pub fn to_wire(&self) -> Vec<u8> {
        let kind_str = match self.kind {
            ResponseKind::Ok => "OK",
            ResponseKind::No => "NO",
            ResponseKind::Bad => "BAD",
            ResponseKind::Preauth => "PREAUTH",
            ResponseKind::Bye => "BYE",
            ResponseKind::Untagged => "",
        };
        let line = if matches!(self.kind, ResponseKind::Untagged) {
            format!("* {}\r\n", self.text)
        } else {
            format!("{} {} {}\r\n", self.tag, kind_str, self.text)
        };
        line.into_bytes()
    }

    pub fn capability_tokens(tls_active: bool) -> &'static str {
        if tls_active {
            "IMAP4rev2 IMAP4rev1 LITERAL+ IDLE UIDPLUS MOVE AUTH=PLAIN"
        } else {
            "IMAP4rev2 IMAP4rev1 LITERAL+ IDLE UIDPLUS MOVE STARTTLS LOGINDISABLED"
        }
    }

    pub fn capability(tls_active: bool) -> Self {
        Self::untagged(format!(
            "CAPABILITY {}",
            Self::capability_tokens(tls_active)
        ))
    }
}
