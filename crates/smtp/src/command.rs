//! SMTP command parser (RFC 5321).
//!
//! Parses the text line sent by the client into a typed `Command`.
//! Uses `nom` for zero-copy parsing.

use nom::{
    branch::alt,
    bytes::complete::{tag_no_case, take_while, take_while1},
    character::complete::{space0, space1},
    combinator::{map, opt, rest},
    sequence::{preceded, tuple},
    IResult,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// EHLO <domain>
    Ehlo(String),
    /// HELO <domain>
    Helo(String),
    /// MAIL FROM:<addr> [SIZE=n]
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
    /// AUTH PLAIN <base64>
    AuthPlain(Option<String>),
    /// AUTH LOGIN
    AuthLogin,
    /// VRFY <string>
    Vrfy(String),
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("unrecognised command: {0}")]
    Unknown(String),
    #[error("malformed command syntax")]
    Malformed,
}

/// Parse a single SMTP command line (without the trailing CRLF).
pub fn parse(line: &str) -> Result<Command, ParseError> {
    let line = line.trim_end_matches(['\r', '\n']);
    let res: IResult<&str, Command> = alt((
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
    ))(line);

    match res {
        Ok((_, cmd)) => Ok(cmd),
        Err(_) => Err(ParseError::Unknown(line.to_owned())),
    }
}

// ─── individual parsers ──────────────────────────────────────────────────────

fn word(i: &str) -> IResult<&str, &str> {
    take_while1(|c: char| !c.is_whitespace())(i)
}

fn parse_ehlo(i: &str) -> IResult<&str, Command> {
    map(
        preceded(tuple((tag_no_case("EHLO"), space1)), word),
        |d: &str| Command::Ehlo(d.to_owned()),
    )(i)
}

fn parse_helo(i: &str) -> IResult<&str, Command> {
    map(
        preceded(tuple((tag_no_case("HELO"), space1)), word),
        |d: &str| Command::Helo(d.to_owned()),
    )(i)
}

fn parse_mail_from(i: &str) -> IResult<&str, Command> {
    // MAIL FROM:<addr> [SIZE=nnn]
    let (i, _) = tag_no_case("MAIL")(i)?;
    let (i, _) = space1(i)?;
    let (i, _) = tag_no_case("FROM:")(i)?;
    let (i, addr) = take_while(|c: char| c != ' ' && c != '\r' && c != '\n')(i)?;
    let (i, _) = space0(i)?;
    let (i, size) = opt(parse_size_param)(i)?;
    Ok((
        i,
        Command::MailFrom {
            address: addr.to_owned(),
            size,
        },
    ))
}

fn parse_size_param(i: &str) -> IResult<&str, u64> {
    let (i, _) = tag_no_case("SIZE=")(i)?;
    let (i, n) = take_while1(|c: char| c.is_ascii_digit())(i)?;
    Ok((i, n.parse().unwrap_or(0)))
}

fn parse_rcpt_to(i: &str) -> IResult<&str, Command> {
    let (i, _) = tag_no_case("RCPT")(i)?;
    let (i, _) = space1(i)?;
    let (i, _) = tag_no_case("TO:")(i)?;
    let (i, addr) = take_while(|c: char| c != ' ' && c != '\r' && c != '\n')(i)?;
    Ok((i, Command::RcptTo(addr.to_owned())))
}

fn parse_data(i: &str) -> IResult<&str, Command> {
    map(tag_no_case("DATA"), |_| Command::Data)(i)
}

fn parse_rset(i: &str) -> IResult<&str, Command> {
    map(tag_no_case("RSET"), |_| Command::Rset)(i)
}

fn parse_noop(i: &str) -> IResult<&str, Command> {
    map(tag_no_case("NOOP"), |_| Command::Noop)(i)
}

fn parse_quit(i: &str) -> IResult<&str, Command> {
    map(tag_no_case("QUIT"), |_| Command::Quit)(i)
}

fn parse_starttls(i: &str) -> IResult<&str, Command> {
    map(tag_no_case("STARTTLS"), |_| Command::StartTls)(i)
}

fn parse_auth(i: &str) -> IResult<&str, Command> {
    let (i, _) = tag_no_case("AUTH")(i)?;
    let (i, _) = space1(i)?;
    let (i, mech) = word(i)?;
    let (i, _) = space0(i)?;
    let (i, initial) = opt(map(rest, |s: &str| s.to_owned()))(i)?;
    let initial = initial.filter(|s| !s.is_empty());
    match mech.to_uppercase().as_str() {
        "PLAIN" => Ok((i, Command::AuthPlain(initial))),
        "LOGIN" => Ok((i, Command::AuthLogin)),
        _ => Err(nom::Err::Error(nom::error::Error::new(
            i,
            nom::error::ErrorKind::Tag,
        ))),
    }
}

fn parse_vrfy(i: &str) -> IResult<&str, Command> {
    map(
        preceded(tuple((tag_no_case("VRFY"), space1)), rest),
        |s: &str| Command::Vrfy(s.to_owned()),
    )(i)
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ehlo() {
        assert_eq!(
            parse("EHLO mail.google.com").unwrap(),
            Command::Ehlo("mail.google.com".into())
        );
    }

    #[test]
    fn mail_from_with_size() {
        let cmd = parse("MAIL FROM:<bob@gmail.com> SIZE=4521").unwrap();
        assert_eq!(
            cmd,
            Command::MailFrom {
                address: "<bob@gmail.com>".into(),
                size: Some(4521)
            }
        );
    }

    #[test]
    fn mail_from_null() {
        let cmd = parse("MAIL FROM:<>").unwrap();
        assert_eq!(
            cmd,
            Command::MailFrom {
                address: "<>".into(),
                size: None
            }
        );
    }

    #[test]
    fn rcpt_to() {
        let cmd = parse("RCPT TO:<alice@example.com>").unwrap();
        assert_eq!(cmd, Command::RcptTo("<alice@example.com>".into()));
    }

    #[test]
    fn quit() {
        assert_eq!(parse("QUIT").unwrap(), Command::Quit);
    }

    #[test]
    fn case_insensitive() {
        assert_eq!(parse("quit").unwrap(), Command::Quit);
        assert_eq!(
            parse("Ehlo mx.example.org").unwrap(),
            Command::Ehlo("mx.example.org".into())
        );
    }
}
