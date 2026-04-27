//! Maildir++ mailbox storage.
//!
//! ## Layout
//! ```text
//! mailbox_dir/<domain>/<local>/
//! ├── cur/          messages seen by IMAP
//! ├── new/          messages not yet seen
//! ├── tmp/          delivery staging (atomic rename to new/)
//! ├── .Sent/{cur,new,tmp}
//! ├── .Drafts/{cur,new,tmp}
//! ├── .Trash/{cur,new,tmp}
//! └── .Junk/{cur,new,tmp}
//! ```
//!
//! One file = one message. Lock-free thanks to atomic `rename(2)` from `tmp/` to `new/`.
//! Directories are fsynced after each rename so deliveries survive a kernel crash.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tracing::{debug, info};
use thiserror::Error;
use rmail_core::Address;

#[derive(Debug, Error)]
pub enum MailboxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("user not found: {0}")]
    UserNotFound(String),
    #[error("folder not found: {0}")]
    FolderNotFound(String),
}

pub struct Maildir {
    root: PathBuf,
}

impl Maildir {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn user_dir(&self, address: &Address) -> PathBuf {
        self.root.join(&address.domain).join(&address.local)
    }

    fn folder_dir(&self, user: &Address, folder: &str) -> PathBuf {
        let base = self.user_dir(user);
        if folder == "INBOX" {
            base
        } else {
            // Maildir++ convention: subfolder = .FolderName
            base.join(format!(".{}", folder))
        }
    }

    // ─── Provisioning ────────────────────────────────────────────────────────

    /// Create the full Maildir++ structure for a new user.
    pub async fn create_user(&self, address: &Address) -> Result<(), MailboxError> {
        let base = self.user_dir(address);
        for sub in ["cur", "new", "tmp"] {
            fs::create_dir_all(base.join(sub)).await?;
        }
        for folder in [".Sent", ".Drafts", ".Trash", ".Junk"] {
            for sub in ["cur", "new", "tmp"] {
                fs::create_dir_all(base.join(folder).join(sub)).await?;
            }
        }
        info!(address = %address, "maildir created");
        Ok(())
    }

    pub async fn user_exists(&self, address: &Address) -> bool {
        self.user_dir(address).join("cur").exists()
    }

    // ─── Delivery ────────────────────────────────────────────────────────────

    /// Deliver a raw RFC 5322 message to the user's INBOX.
    ///
    /// Steps:
    /// 1. Write to `tmp/<unique>` and fsync.
    /// 2. `rename(tmp/<unique>, new/<unique>)` — atomic.
    /// 3. fsync the `new/` directory so the rename is durable.
    ///
    /// Returns the Maildir filename.
    pub async fn deliver(
        &self,
        address: &Address,
        body: &[u8],
    ) -> Result<String, MailboxError> {
        let base = self.user_dir(address);
        if !base.join("cur").exists() {
            return Err(MailboxError::UserNotFound(address.as_str()));
        }

        let filename = unique_filename();
        let tmp_path = base.join("tmp").join(&filename);
        let new_path = base.join("new").join(&filename);

        // Write + fsync the body file
        tokio::fs::write(&tmp_path, body).await?;
        {
            let f = tokio::fs::File::open(&tmp_path).await?;
            f.sync_data().await?;
        }
        // Atomic move into new/
        tokio::fs::rename(&tmp_path, &new_path).await?;
        // Fsync new/ so the rename survives a kernel crash
        sync_dir(&base.join("new")).await?;

        debug!(address = %address, file = %filename, bytes = body.len(), "delivered");
        Ok(filename)
    }

    // ─── List ────────────────────────────────────────────────────────────────

    /// List all messages in a folder (both `cur/` and `new/`).
    pub async fn list_messages(
        &self,
        address: &Address,
        folder: &str,
    ) -> Result<Vec<MaildirEntry>, MailboxError> {
        let folder_dir = self.folder_dir(address, folder);
        if !folder_dir.exists() {
            return Err(MailboxError::FolderNotFound(folder.to_owned()));
        }

        let mut entries = Vec::new();
        for (subdir, in_new) in [("new", true), ("cur", false)] {
            let dir = folder_dir.join(subdir);
            if !dir.exists() { continue; }
            let mut rd = fs::read_dir(&dir).await?;
            while let Some(entry) = rd.next_entry().await? {
                let meta = entry.metadata().await?;
                if !meta.is_file() { continue; }
                let filename = entry.file_name().to_string_lossy().into_owned();
                let flags = parse_maildir_flags(&filename);
                entries.push(MaildirEntry {
                    path:     entry.path(),
                    filename: filename.clone(),
                    size:     meta.len(),
                    seen:     !in_new && flags.contains('S'),
                    flagged:  flags.contains('F'),
                    deleted:  flags.contains('T'),
                });
            }
        }
        Ok(entries)
    }

    /// List all folders for a user (INBOX + Maildir++ subdirs).
    pub async fn list_folders(
        &self,
        address: &Address,
    ) -> Result<Vec<String>, MailboxError> {
        let base = self.user_dir(address);
        if !base.exists() {
            return Err(MailboxError::UserNotFound(address.as_str()));
        }
        let mut folders = vec!["INBOX".to_owned()];
        let mut rd = fs::read_dir(&base).await?;
        while let Some(entry) = rd.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') && entry.metadata().await?.is_dir() {
                // Strip leading dot for display (`.Sent` → `Sent`)
                folders.push(name[1..].to_owned());
            }
        }
        Ok(folders)
    }

    // ─── Read ────────────────────────────────────────────────────────────────

    pub async fn read_message(&self, path: &PathBuf) -> Result<Vec<u8>, MailboxError> {
        Ok(tokio::fs::read(path).await?)
    }

    // ─── Move to cur (IMAP "seen") ───────────────────────────────────────────

    /// Move a message from `new/` to `cur/` when IMAP selects the mailbox.
    /// Appends `:2,S` flags to the filename.
    pub async fn move_to_cur(&self, path: &PathBuf) -> Result<PathBuf, MailboxError> {
        let filename = path.file_name().unwrap().to_string_lossy();
        let new_name = if filename.contains(":2,") {
            // Already in Maildir flags format — ensure S is present
            add_flag(&filename, 'S')
        } else {
            format!("{}:2,S", filename)
        };
        let cur_dir = path.parent().unwrap().parent().unwrap().join("cur");
        let new_path = cur_dir.join(&new_name);
        tokio::fs::rename(path, &new_path).await?;
        sync_dir(&cur_dir).await?;
        Ok(new_path)
    }

    // ─── Expunge / delete ────────────────────────────────────────────────────

    /// Mark a message as deleted by adding the T flag.
    pub async fn mark_deleted(&self, path: &PathBuf) -> Result<PathBuf, MailboxError> {
        let filename = path.file_name().unwrap().to_string_lossy();
        let new_name = add_flag(&filename, 'T');
        let parent = path.parent().unwrap();
        let new_path = parent.join(&new_name);
        tokio::fs::rename(path, &new_path).await?;
        sync_dir(parent).await?;
        Ok(new_path)
    }

    /// Permanently remove a message file (called on EXPUNGE).
    pub async fn expunge(&self, path: &PathBuf) -> Result<(), MailboxError> {
        tokio::fs::remove_file(path).await?;
        Ok(())
    }
}

// ─── Types ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MaildirEntry {
    pub path:     PathBuf,
    pub filename: String,
    pub size:     u64,
    pub seen:     bool,
    pub flagged:  bool,
    pub deleted:  bool,
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Cached host identifier for Maildir filenames. Read from /proc/sys/kernel/hostname
/// (Linux) or /etc/hostname, with a sane fallback. `:` and `/` (forbidden by
/// Maildir spec) are replaced with `_`.
fn host_id() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "rmail".into())
            .replace('/', "_")
            .replace(':', "_")
    })
}

/// Generate a unique Maildir filename per the DJB convention:
///   `<timestamp>.M<usec>P<pid>Q<counter>.<host>`
/// `M` = microseconds, `P` = pid, `Q` = local sequence counter.
fn unique_filename() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let ts = now.as_secs();
    let usec = now.subsec_micros();
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}.M{}P{}Q{}.{}", ts, usec, pid, n, host_id())
}

/// Extract Maildir flags from filename.
/// Filename may end in `:2,FLAGS` (e.g. `:2,FS` = Flagged + Seen).
fn parse_maildir_flags(filename: &str) -> &str {
    if let Some(idx) = filename.rfind(":2,") {
        &filename[idx + 3..]
    } else {
        ""
    }
}

/// Add a Maildir flag character to a filename (flags are sorted alphabetically).
fn add_flag(filename: &str, flag: char) -> String {
    if let Some(idx) = filename.rfind(":2,") {
        let flags = &filename[idx + 3..];
        if flags.contains(flag) {
            return filename.to_owned();
        }
        let mut chars: Vec<char> = flags.chars().chain(std::iter::once(flag)).collect();
        chars.sort_unstable();
        format!("{}:2,{}", &filename[..idx], chars.iter().collect::<String>())
    } else {
        format!("{}:2,{}", filename, flag)
    }
}

/// Open a directory and fsync it so prior renames/creates within it are durable.
/// No-op on non-Unix targets (Windows has no equivalent fsync-on-directory).
async fn sync_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let f = fs::File::open(path).await?;
        f.sync_all().await?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
