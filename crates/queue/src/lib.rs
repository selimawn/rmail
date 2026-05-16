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
//! ## Crash semantics
//!
//! State transitions are atomic `rename(2)` calls. Within a transition the
//! body is renamed first and the envelope second — the **envelope is the
//! commit marker**. After every mutation the parent directory is fsynced so
//! the rename is durable across kernel crashes.
//!
//! On startup, [`Queue::recover`] sweeps every directory: orphan `.eml`
//! files (a partial transition) are deleted, envelopes without a body are
//! quarantined into `corrupt/`.

use rmail_core::{Envelope, Message, QueueId, QueueState};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, warn};

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
    /// Body first, envelope second, then directory fsync. After this returns
    /// Ok the message is durable: a kernel crash cannot lose it.
    pub async fn enqueue(&self, mut envelope: Envelope, body: &[u8]) -> Result<String, QueueError> {
        let incoming = self.dir(QueueState::Incoming);
        loop {
            let id = envelope.id.to_string();
            let eml = self.eml_path(QueueState::Incoming, &id);
            let env = self.env_path(QueueState::Incoming, &id);
            if fs::try_exists(&eml).await? || fs::try_exists(&env).await? {
                envelope.id = QueueId::generate();
                continue;
            }
            debug!(%id, bytes = body.len(), "enqueue");

            // 1. Write body, fsync data
            let mut f = match create_new(&eml).await {
                Ok(f) => f,
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    envelope.id = QueueId::generate();
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            f.write_all(body).await?;
            f.sync_data().await?;
            drop(f);

            // 2. Write envelope (commit marker), fsync data
            let env_bytes = bincode::serialize(&envelope)?;
            let mut f = match create_new(&env).await {
                Ok(f) => f,
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    let _ = fs::remove_file(&eml).await;
                    envelope.id = QueueId::generate();
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            f.write_all(&env_bytes).await?;
            f.sync_data().await?;
            drop(f);

            // 3. Fsync directory so both new entries are durable
            fsync_dir(&incoming).await?;

            return Ok(id);
        }
    }

    // ─── State transitions ───────────────────────────────────────────────────────

    /// Atomically move a message from one state directory to another.
    ///
    /// Order: `.eml` first, `.env` second. The envelope is the commit
    /// marker — if its presence in a directory implies the body is also
    /// there. If we crash between the two renames:
    ///   - body is in the destination dir (orphan, picked up by `recover`)
    ///   - envelope is still in the source dir (message remains in old state)
    ///
    /// Both directories are fsynced before returning.
    pub async fn transition(
        &self,
        id: &str,
        from: QueueState,
        to: QueueState,
    ) -> Result<(), QueueError> {
        debug!(%id, from = from.dir_name(), to = to.dir_name(), "queue transition");
        // Body first
        fs::rename(self.eml_path(from, id), self.eml_path(to, id)).await?;
        // Envelope second (= commit marker)
        fs::rename(self.env_path(from, id), self.env_path(to, id)).await?;
        // Make both dir entries durable
        fsync_dir(&self.dir(from)).await?;
        fsync_dir(&self.dir(to)).await?;
        Ok(())
    }

    // ─── Load ────────────────────────────────────────────────────────────────────

    /// Load a message from a queue directory.
    pub async fn load(&self, state: QueueState, id: &str) -> Result<Message, QueueError> {
        let env_path = self.env_path(state, id);
        let eml_path = self.eml_path(state, id);
        let env_bytes = fs::read(&env_path).await?;
        let envelope: Envelope = bincode::deserialize(&env_bytes)?;
        let size = fs::metadata(&eml_path).await?.len();
        Ok(Message {
            envelope,
            body_path: eml_path,
            size,
        })
    }

    // ─── Update envelope ─────────────────────────────────────────────────────────

    /// Rewrite the envelope in-place after updating delivery status.
    /// Tmp file + rename for atomicity, then dir fsync.
    pub async fn update_envelope(
        &self,
        state: QueueState,
        envelope: &Envelope,
    ) -> Result<(), QueueError> {
        let id = envelope.id.to_string();
        let path = self.env_path(state, &id);
        let tmp = path.with_extension("tmp");
        let bytes = bincode::serialize(envelope)?;
        let mut f = fs::File::create(&tmp).await?;
        f.write_all(&bytes).await?;
        f.sync_data().await?;
        drop(f);
        fs::rename(&tmp, &path).await?;
        fsync_dir(&self.dir(state)).await?;
        Ok(())
    }

    // ─── List ────────────────────────────────────────────────────────────────────

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

    // ─── Remove ──────────────────────────────────────────────────────────────────

    /// Delete both files for a message (called after successful delivery).
    pub async fn remove(&self, state: QueueState, id: &str) -> Result<(), QueueError> {
        if let Err(e) = fs::remove_file(self.env_path(state, id)).await {
            warn!(%id, "could not remove .env: {}", e);
        }
        if let Err(e) = fs::remove_file(self.eml_path(state, id)).await {
            warn!(%id, "could not remove .eml: {}", e);
        }
        let _ = fsync_dir(&self.dir(state)).await;
        Ok(())
    }

    // ─── Recovery ─────────────────────────────────────────────────────────────────

    /// Walk every queue directory and reconcile inconsistent state left by a
    /// crash. Call **once** at startup before any other queue activity.
    ///
    /// Two cases handled:
    ///
    /// - `.eml` without matching `.env`: orphan body left by a partial
    ///   `transition`. The envelope is still in the source dir and will be
    ///   picked up on the next pass. The orphan body is deleted.
    /// - `.env` without matching `.eml`: envelope claims a message we cannot
    ///   find. Quarantine it into `corrupt/` for human inspection.
    pub async fn recover(&self) -> Result<RecoveryReport, QueueError> {
        let mut report = RecoveryReport::default();

        for state in [
            QueueState::Incoming,
            QueueState::Active,
            QueueState::Deferred,
            QueueState::Hold,
            QueueState::Bounce,
        ] {
            let dir = self.dir(state);
            let mut envs = Vec::new();
            let mut emls = Vec::new();

            let mut rd = match fs::read_dir(&dir).await {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            while let Some(entry) = rd.next_entry().await? {
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some(id) = name.strip_suffix(".env") {
                    envs.push(id.to_owned());
                } else if let Some(id) = name.strip_suffix(".eml") {
                    emls.push(id.to_owned());
                }
            }

            // Case 1: orphan bodies
            for id in &emls {
                if !envs.contains(id) {
                    warn!(%id, dir = state.dir_name(), "orphan body removed during recovery");
                    let _ = fs::remove_file(self.eml_path(state, id)).await;
                    report.orphan_bodies_removed += 1;
                }
            }

            // Case 2: envelopes without bodies
            for id in &envs {
                if !emls.contains(id) {
                    warn!(%id, dir = state.dir_name(), "envelope without body, quarantining");
                    let _ = fs::rename(
                        self.env_path(state, id),
                        self.env_path(QueueState::Corrupt, id),
                    )
                    .await;
                    report.corrupt_envelopes += 1;
                }
            }

            let _ = fsync_dir(&dir).await;
        }
        let _ = fsync_dir(&self.dir(QueueState::Corrupt)).await;

        info!(
            orphan_bodies = report.orphan_bodies_removed,
            corrupt = report.corrupt_envelopes,
            "queue recovery complete"
        );
        Ok(report)
    }
}

/// Result of a [`Queue::recover`] sweep.
#[derive(Debug, Default, Clone, Copy)]
pub struct RecoveryReport {
    pub orphan_bodies_removed: usize,
    pub corrupt_envelopes: usize,
}

// ─── helpers ──────────────────────────────────────────────────────────────────────

/// fsync(2) the directory file descriptor so that recent rename/create/unlink
/// operations are durable. On most Unix filesystems, fsyncing a file is not
/// sufficient — the parent directory entry must be fsynced too.
async fn fsync_dir(path: &Path) -> std::io::Result<()> {
    let f = fs::File::open(path).await?;
    f.sync_all().await?;
    Ok(())
}

async fn create_new(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await
}
