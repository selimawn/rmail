//! On-disk message queue (Postfix-inspired).
//!
//! ## Layout
//! ```text
//! queue_dir/
//! ├── incoming/   newly accepted, awaiting cleanup
//! ├── active/     being delivered right now
//! ├── deferred/   delivery failed, retry scheduled
//! ├── hold/       admin hold
//! ├── bounce/     bounce notice in progress
//! └── corrupt/    malformed; needs manual inspection
//! ```
//!
//! Each message is two files:
//! - `<id>.env` — bincode-encoded `Envelope`
//! - `<id>.eml` — raw RFC 5322 bytes (dot-stuffing decoded)
//!
//! State transitions are atomic `rename(2)` calls.
//! If rmail crashes mid-delivery, the message stays in its last stable dir.

use std::path::PathBuf;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, warn};
use thiserror::Error;
use rmail_core::{Envelope, Message, QueueState};

#[derive(Debug, Error)]
pub enum QueueError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Bincode(#[from] bincode::Error),
}

pub struct Queue {
    root: PathBuf,
}

impl Queue {
    /// Create a Queue handle and ensure all subdirectories exist.
    pub async fn new(root: PathBuf) -> Result<Self, QueueError> {
        for state in [
            QueueState::Incoming,
            QueueState::Active,
            QueueState::Deferred,
            QueueState::Hold,
            QueueState::Bounce,
            QueueState::Corrupt,
        ] {
            fs::create_dir_all(root.join(state.dir_name())).await?;
        }
        Ok(Self { root })
    }

    fn dir(&self, state: QueueState) -> PathBuf {
        self.root.join(state.dir_name())
    }

    fn env_path(&self, state: QueueState, id: &str) -> PathBuf {
        self.dir(state).join(format!("{}.env", id))
    }

    fn eml_path(&self, state: QueueState, id: &str) -> PathBuf {
        self.dir(state).join(format!("{}.eml", id))
    }

    // ─── Enqueue ─────────────────────────────────────────────────────────────

    /// Accept a message into `incoming/`.
    /// Writes body first, then envelope. Both are fsynced before returning.
    /// Returns the message ID (= `envelope.id`).
    pub async fn enqueue(
        &self,
        envelope: Envelope,
        body: &[u8],
    ) -> Result<String, QueueError> {
        let id = envelope.id.to_string();
        debug!(%id, bytes = body.len(), "enqueue");

        // 1. Write body
        let eml = self.eml_path(QueueState::Incoming, &id);
        let mut f = fs::File::create(&eml).await?;
        f.write_all(body).await?;
        f.sync_data().await?;
        drop(f);

        // 2. Write envelope
        let env_bytes = bincode::serialize(&envelope)?;
        let env = self.env_path(QueueState::Incoming, &id);
        let mut f = fs::File::create(&env).await?;
        f.write_all(&env_bytes).await?;
        f.sync_data().await?;
        drop(f);

        Ok(id)
    }

    // ─── State transitions ───────────────────────────────────────────────────

    /// Atomically move a message from one state directory to another.
    /// Envelope is renamed first; if only that succeeds on a crash,
    /// a scan of `from/` will not find a dangling `.eml`.
    pub async fn transition(
        &self,
        id: &str,
        from: QueueState,
        to: QueueState,
    ) -> Result<(), QueueError> {
        debug!(%id, from = from.dir_name(), to = to.dir_name(), "queue transition");
        fs::rename(self.env_path(from, id), self.env_path(to, id)).await?;
        fs::rename(self.eml_path(from, id), self.eml_path(to, id)).await?;
        Ok(())
    }

    // ─── Load ────────────────────────────────────────────────────────────────

    /// Load a message from a queue directory.
    pub async fn load(&self, state: QueueState, id: &str) -> Result<Message, QueueError> {
        let env_path = self.env_path(state, id);
        let eml_path = self.eml_path(state, id);
        let env_bytes = fs::read(&env_path).await?;
        let envelope: Envelope = bincode::deserialize(&env_bytes)?;
        let size = fs::metadata(&eml_path).await?.len();
        Ok(Message { envelope, body_path: eml_path, size })
    }

    // ─── Update envelope ─────────────────────────────────────────────────────

    /// Rewrite the envelope in-place after updating delivery status.
    /// Uses a tmp file + rename for atomicity.
    pub async fn update_envelope(
        &self,
        state: QueueState,
        envelope: &Envelope,
    ) -> Result<(), QueueError> {
        let id = envelope.id.to_string();
        let path = self.env_path(state, &id);
        let tmp  = path.with_extension("tmp");
        let bytes = bincode::serialize(envelope)?;
        let mut f = fs::File::create(&tmp).await?;
        f.write_all(&bytes).await?;
        f.sync_data().await?;
        drop(f);
        fs::rename(&tmp, &path).await?;
        Ok(())
    }

    // ─── List ────────────────────────────────────────────────────────────────

    /// List all message IDs present in a queue state directory.
    pub async fn list(&self, state: QueueState) -> Result<Vec<String>, QueueError> {
        let mut ids = Vec::new();
        let mut rd = match fs::read_dir(self.dir(state)).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ids),
            Err(e) => return Err(e.into()),
        };
        while let Some(entry) = rd.next_entry().await? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some(id) = name.strip_suffix(".env") {
                ids.push(id.to_owned());
            }
        }
        Ok(ids)
    }

    // ─── Remove ──────────────────────────────────────────────────────────────

    /// Delete both files for a message (called after successful delivery).
    pub async fn remove(&self, state: QueueState, id: &str) -> Result<(), QueueError> {
        if let Err(e) = fs::remove_file(self.env_path(state, id)).await {
            warn!(%id, "could not remove .env: {}", e);
        }
        if let Err(e) = fs::remove_file(self.eml_path(state, id)).await {
            warn!(%id, "could not remove .eml: {}", e);
        }
        Ok(())
    }
}
