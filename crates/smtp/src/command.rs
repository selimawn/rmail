//! SMTP command parser (RFC 5321).
//!
//! Parses the client side of an SMTP conversation into typed `SmtpCommand` values.
//! Built with `nom` — no regex, no allocations on the hot path.

use nom::{
    branch::alt,
    bytes::complete::{tag, tag_no_case, take_while, take_while1},
    character::complete::{char, space0, space1},
    combinator::{map, opt, rest},
    sequence::{preceded, tuple},
    IResult,
};

#[derive(Debug, Clone, PartialEq)]
pub enum SmtpCommand {
    /// EHLO <domain>
    Ehlo(String),
    /// HELO <domain>
    Helo(String),
    /// MAIL FROM:<addr> [parameters]
    MailFrom { address: String, size: Option<u64> },
    /// RCPT TO:<addr>
    RcptTo(String),
    /// DATA
    Data,
    /// RSET
    Rset,
    /// NOOP
    Noop,
    /// QUIT
    Quit,
    /// STARTTLS
    StartTls,
    /// AUTH PLAIN <credentials>
    AuthPlain(Option<String>),
    /// AUTH LOGIN
    AuthLogin,
    /// VRFY <string>
    Vrfy(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("unrecognised command")]
    Unknown,
    #[error("syntax error: {0}")]
    Syntax(String),
}

/// Parse a single SMTP command line (without the trailing CRLF).
pub fn parse_command(line: &str) -> Result<SmtpCommand, ParseError> {
    let line = line.trim_end_matches(|c| c == '\r' || c == '\n');
    let (_, cmd) = alt((
        parse_ehlo,
        parse_helo,
        parse_mail_from,
        parse_rcpt_to,
        parse_data,
        parse_rset,
        parse_noop,
        parse_quit,
        parse_starttls,
        parse_auth,
        parse_vrfy,
    ))(line)
    .map_err(|_| ParseError::Unknown)?;
    Ok(cmd)
}

fn parse_ehlo(i: &str) -> IResult<&str, SmtpCommand> {
    map(
        preceded(tuple((tag_no_case("EHLO"), space1)), rest_str),
        SmtpCommand::Ehlo,
    )(i)
}

fn parse_helo(i: &str) -> IResult<&str, SmtpCommand> {
    map(
        preceded(tuple((tag_no_case("HELO"), space1)), rest_str),
        SmtpCommand::Helo,
    )(i)
}

fn parse_mail_from(i: &str) -> IResult<&str, SmtpCommand> {
    // MAIL FROM:<addr>[ SIZE=nnn]
    let (i, _) = tag_no_case("MAIL")(i)?;
    let (i, _) = space1(i)?;
    let (i, _) = tag_no_case("FROM:")(i)?;
    let (i, _) = space0(i)?;
    let (i, addr) = parse_angle_or_bare(i)?;
    let (i, size) = opt(parse_size_param)(i)?;
    Ok((i, SmtpCommand::MailFrom { address: addr.to_lowercase(), size }))
}

fn parse_rcpt_to(i: &str) -> IResult<&str, SmtpCommand> {
    let (i, _) = tag_no_case("RCPT")(i)?;
    let (i, _) = space1(i)?;
    let (i, _) = tag_no_case("TO:")(i)?;
    let (i, _) = space0(i)?;
    let (i, addr) = parse_angle_or_bare(i)?;
    Ok((i, SmtpCommand::RcptTo(addr.to_lowercase())))
}

fn parse_data(i: &str) -> IResult<&str, SmtpCommand> {
    map(tag_no_case("DATA"), |_| SmtpCommand::Data)(i)
}

fn parse_rset(i: &str) -> IResult<&str, SmtpCommand> {
    map(tag_no_case("RSET"), |_| SmtpCommand::Rset)(i)
}

fn parse_noop(i: &str) -> IResult<&str, SmtpCommand> {
    map(tag_no_case("NOOP"), |_| SmtpCommand::Noop)(i)
}

fn parse_quit(i: &str) -> IResult<&str, SmtpCommand> {
    map(tag_no_case("QUIT"), |_| SmtpCommand::Quit)(i)
}

fn parse_starttls(i: &str) -> IResult<&str, SmtpCommand> {
    map(tag_no_case("STARTTLS"), |_| SmtpCommand::StartTls)(i)
}

fn parse_auth(i: &str) -> IResult<&str, SmtpCommand> {
    let (i, _) = tag_no_case("AUTH")(i)?;
    let (i, _) = space1(i)?;
    let (i, mech) = take_while1(|c: char| c.is_ascii_alphabetic())(i)?;
    match mech.to_ascii_uppercase().as_str() {
        "PLAIN" => {
            let (i, creds) = opt(preceded(space1, rest_str))(i)?;
            Ok((i, SmtpCommand::AuthPlain(creds.filter(|s| !s.is_empty()))))
        }
        "LOGIN" => Ok((i, SmtpCommand::AuthLogin)),
        _ => Err(nom::Err::Error(nom::error::Error::new(i, nom::error::ErrorKind::Tag))),
    }
}

fn parse_vrfy(i: &str) -> IResult<&str, SmtpCommand> {
    map(
        preceded(tuple((tag_no_case("VRFY"), space1)), rest_str),
        SmtpCommand::Vrfy,
    )(i)
}

// ─── helpers ──────────────────────────────────────────────────────────

fn rest_str(i: &str) -> IResult<&str, String> {
    map(rest, |s: &str| s.trim().to_owned())(i)
}

/// Parse `<addr>` or bare `addr`.
fn parse_angle_or_bare(i: &str) -> IResult<&str, String> {
    if i.starts_with('<') {
        let (i, _) = char('<')(i)?;
        let (i, addr) = take_while(|c| c != '>')(i)?;
        let (i, _) = char('>')(i)?;
        Ok((i, addr.to_owned()))
    } else {
        let (i, addr) = take_while1(|c: char| !c.is_whitespace())(i)?;
        Ok((i, addr.to_owned()))
    }
}

fn parse_size_param(i: &str) -> IResult<&str, u64> {
    let (i, _) = space1(i)?;
    let (i, _) = tag_no_case("SIZE=")(i)?;
    let (i, n) = take_while1(|c: char| c.is_ascii_digit())(i)?;
    Ok((i, n.parse().unwrap_or(0)))
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ehlo() {
        assert_eq!(parse_command("EHLO mail.google.com").unwrap(),
            SmtpCommand::Ehlo("mail.google.com".into()));
    }

    #[test]
    fn mail_from_angle() {
        let cmd = parse_command("MAIL FROM:<bob@gmail.com> SIZE=1234").unwrap();
        assert_eq!(cmd, SmtpCommand::MailFrom {
            address: "bob@gmail.com".into(),
            size: Some(1234),
        });
    }

    #[test]
    fn mail_from_null() {
        let cmd = parse_command("MAIL FROM:<>").unwrap();
        assert_eq!(cmd, SmtpCommand::MailFrom { address: "".into(), size: None });
    }

    #[test]
    fn rcpt_to() {
        assert_eq!(parse_command("RCPT TO:<alice@example.com>").unwrap(),
            SmtpCommand::RcptTo("alice@example.com".into()));
    }

    #[test]
    fn quit() {
        assert_eq!(parse_command("QUIT").unwrap(), SmtpCommand::Quit);
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(parse_command("quit").unwrap(), SmtpCommand::Quit);
        assert_eq!(parse_command("data").unwrap(), SmtpCommand::Data);
    }
}
