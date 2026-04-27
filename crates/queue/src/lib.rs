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
//! State transitions are atomic `rename(2)` calls per file. The two-file
//! design means a transition is *not* atomic across both files: a crash
//! between the two renames leaves split halves in different directories.
//! [`Queue::new`] runs an orphan reconciliation pass at startup that moves
//! any unmatched halves into `corrupt/` for manual inspection.

use std::path::{Path, PathBuf};
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
    /// Create a Queue handle, ensure all subdirectories exist, and reconcile
    /// any orphan files left behind by a previous crash mid-transition.
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
        let queue = Self { root };
        queue.reconcile_orphans().await?;
        Ok(queue)
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

    // ─── Enqueue ───────────────────────────────────────────────────────────────────

    /// Accept a message into `incoming/`.
    /// Writes body, then envelope, then fsyncs the directory so the names
    /// are durable on POSIX. An accepted message survives a crash.
    /// Returns the message ID (= `envelope.id`).
    pub async fn enqueue(
        &self,
        envelope: Envelope,
        body: &[u8],
    ) -> Result<String, QueueError> {
        let id = envelope.id.to_string();
        debug!(%id, bytes = body.len(), "enqueue");

        // 1. Body
        let eml = self.eml_path(QueueState::Incoming, &id);
        let mut f = fs::File::create(&eml).await?;
        f.write_all(body).await?;
        f.sync_data().await?;
        drop(f);

        // 2. Envelope
        let env_bytes = bincode::serialize(&envelope)?;
        let env = self.env_path(QueueState::Incoming, &id);
        let mut f = fs::File::create(&env).await?;
        f.write_all(&env_bytes).await?;
        f.sync_data().await?;
        drop(f);

        // 3. fsync the directory so the entries are durable.
        if let Err(e) = fsync_dir(&self.dir(QueueState::Incoming)).await {
            warn!(%id, "fsync of incoming/ failed (message accepted but not durable): {}", e);
        }

        Ok(id)
    }

    // ─── State transitions ───────────────────────────────────────────────────────────────────

    /// Move a message from one state directory to another.
    ///
    /// Renames `.env` then `.eml`. A crash between the two renames leaves
    /// the two halves split across directories; these split halves are
    /// caught and quarantined by [`Queue::new`]'s orphan reconciliation
    /// pass at the next startup.
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

    // ─── Load ────────────────────────────────────────────────────────────────────────────

    /// Load a message from a queue directory.
    pub async fn load(&self, state: QueueState, id: &str) -> Result<Message, QueueError> {
        let env_path = self.env_path(state, id);
        let eml_path = self.eml_path(state, id);
        let env_bytes = fs::read(&env_path).await?;
        let envelope: Envelope = bincode::deserialize(&env_bytes)?;
        let size = fs::metadata(&eml_path).await?.len();
        Ok(Message { envelope, body_path: eml_path, size })
    }

    // ─── Update envelope ────────────────────────────────────────────────────────────────────

    /// Rewrite the envelope in-place after updating delivery status.
    /// Uses tmp file + rename for atomicity.
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

    // ─── List ────────────────────────────────────────────────────────────────────────────

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

    // ─── Remove ───────────────────────────────────────────────────────────────────────

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

    // ─── Orphan reconciliation ────────────────────────────────────────────────────────────────────

    /// Scan every working state dir for files without their counterpart and
    /// move them to `corrupt/`. Recovers from a crash mid-transition.
    /// `corrupt/` itself is intentionally not scanned.
    async fn reconcile_orphans(&self) -> Result<(), QueueError> {
        use std::collections::HashSet;
        for state in [
            QueueState::Incoming,
            QueueState::Active,
            QueueState::Deferred,
            QueueState::Hold,
            QueueState::Bounce,
        ] {
            let dir = self.dir(state);
            let mut envs: HashSet<String> = HashSet::new();
            let mut emls: HashSet<String> = HashSet::new();
            let mut rd = match fs::read_dir(&dir).await {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            while let Some(entry) = rd.next_entry().await? {
                let name = entry.file_name();
                let s = name.to_string_lossy();
                if let Some(id) = s.strip_suffix(".env") {
                    envs.insert(id.to_owned());
                } else if let Some(id) = s.strip_suffix(".eml") {
                    emls.insert(id.to_owned());
                }
            }
            for id in envs.difference(&emls) {
                warn!(
                    %id, dir = state.dir_name(),
                    "orphan .env (no matching .eml); moving to corrupt/"
                );
                if let Err(e) = fs::rename(
                    self.env_path(state, id),
                    self.env_path(QueueState::Corrupt, id),
                ).await {
                    warn!(%id, "failed to move orphan .env to corrupt/: {}", e);
                }
            }
            for id in emls.difference(&envs) {
                warn!(
                    %id, dir = state.dir_name(),
                    "orphan .eml (no matching .env); moving to corrupt/"
                );
                if let Err(e) = fs::rename(
                    self.eml_path(state, id),
                    self.eml_path(QueueState::Corrupt, id),
                ).await {
                    warn!(%id, "failed to move orphan .eml to corrupt/: {}", e);
                }
            }
        }
        Ok(())
    }
}

// ─── helpers ────────────────────────────────────────────────────────────────────────

/// fsync a directory (POSIX). On non-Unix targets this is a no-op.
///
/// Uses `spawn_blocking` + `std::fs::File` because tokio's async file API
/// is documented for files only. `sync_all` on a directory fd flushes the
/// directory's metadata (the names of contained files) on Linux/BSD.
async fn fsync_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let path = path.to_path_buf();
        match tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let f = std::fs::File::open(&path)?;
            f.sync_all()?;
            Ok(())
        })
        .await
        {
            Ok(r) => r,
            Err(e) => Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}
