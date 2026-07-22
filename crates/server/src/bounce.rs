//! Bounce message generator.
//! Sends a DSN (Delivery Status Notification) back to the original sender.

use rmail_core::{Address, Envelope};
use rmail_queue::Queue;
use tracing::{info, warn};

pub async fn generate(original: &Envelope, reason: &str, queue: &Queue, server_hostname: &str) {
    if original.from.is_null() {
        // RFC 5321: do NOT generate a bounce for a bounce
        return;
    }

    let date = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc2822)
        .unwrap_or_else(|_| "unknown".to_owned());
    let dsn_body = format!(
        "From: MAILER-DAEMON <mailer-daemon@{host}>\r\n\
         To: {sender}\r\n\
         Date: {date}\r\n\
         Message-ID: <{msg_id}@{host}>\r\n\
         Subject: Delivery Status Notification (Failure)\r\n\
         Auto-Submitted: auto-replied\r\n\
         \r\n\
         This is the mail system at {host}.\r\n\
         \r\n\
         Your message could not be delivered to one or more recipients.\r\n\
         \r\n\
         Reason: {reason}\r\n\
         Original message ID: {id}\r\n",
        host = server_hostname,
        sender = original.from.as_str(),
        date = date,
        msg_id = rmail_core::QueueId::generate(),
        reason = reason,
        id = original.id,
    );

    let bounce_envelope = rmail_core::Envelope::new(
        Address::null(),
        vec![original.from.clone()],
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        server_hostname,
        None,
    );

    match queue.enqueue(bounce_envelope, dsn_body.as_bytes()).await {
        Ok(id) => info!(bounce_id = %id, "bounce generated for {}", original.id),
        Err(e) => warn!("bounce enqueue failed: {}", e),
    }
}
