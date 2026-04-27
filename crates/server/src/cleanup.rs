//! Cleanup: moves a message from `incoming` to `active` after adding
//! the `Received:` header and validating the RFC 5322 structure.
//!
//! In Postfix this is `cleanup(8)`. In rmail it's called from queue_manager
//! before the message is dispatched for delivery.

use rmail_core::Envelope;

/// Prepend a `Received:` header to raw message bytes.
/// This is the trace record required by RFC 5321 §3.7.2.
pub fn add_received_header(body: &[u8], envelope: &Envelope, our_hostname: &str) -> Vec<u8> {
    let ts = envelope.received_at
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_else(|_| "unknown".to_owned());

    let header = format!(
        "Received: from {} ({} [{}])\r\n\tby {} (rmail) with ESMTP id {}\r\n\tfor {}; {}\r\n",
        envelope.client_helo,
        envelope.client_helo,
        envelope.client_ip,
        our_hostname,
        envelope.id,
        envelope.recipients.first()
            .map(|r| r.address.to_string())
            .unwrap_or_else(|| "unknown".into()),
        ts,
    );

    let mut out = Vec::with_capacity(header.len() + body.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(body);
    out
}
