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
//! One file = one message. Lock-free thanks to atomic `rename(2)` from
//! `tmp/` to `new/`. Every state-changing rename is followed by a parent-
//! directory fsync so the change is durable across kernel crashes.

use rmail_core::Address;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::fs;
use tracing::{debug, info};

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

    // ─── Provisioning ─────────────────────────────────────────────────────────────

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

    // ─── Delivery ──────────────────────────────────────────────────────────────────

    /// Deliver a raw RFC 5322 message to the user's INBOX.
    ///
    /// 1. Write to `tmp/<unique>` and fsync.
    /// 2. `rename(tmp/<unique>, new/<unique>)` — atomic.
    /// 3. Fsync `new/` so the rename is durable.
    pub async fn deliver(&self, address: &Address, body: &[u8]) -> Result<String, MailboxError> {
        self.append_to_folder(address, "INBOX", body, "").await
    }

    pub async fn append_to_folder(
        &self,
        address: &Address,
        folder: &str,
        body: &[u8],
        flags: &str,
    ) -> Result<String, MailboxError> {
        let base = self.user_dir(address);
        if !base.join("cur").exists() {
            return Err(MailboxError::UserNotFound(address.as_str()));
        }
        let folder_dir = self.folder_dir(address, folder);
        if !folder_dir.exists() {
            return Err(MailboxError::FolderNotFound(folder.to_owned()));
        }

        let filename = unique_filename();
        let tmp_path = folder_dir.join("tmp").join(&filename);
        let target_name = if flags.is_empty() {
            filename
        } else {
            format!("{}:2,{}", filename, normalize_flags(flags))
        };
        let target_subdir = if flags.contains('S') { "cur" } else { "new" };
        let target_path = folder_dir.join(target_subdir).join(&target_name);

        tokio::fs::write(&tmp_path, body).await?;
        {
            let f = tokio::fs::File::open(&tmp_path).await?;
            f.sync_data().await?;
        }
        tokio::fs::rename(&tmp_path, &target_path).await?;
        let _ = fsync_dir(&folder_dir.join(target_subdir)).await;

        debug!(address = %address, folder, file = %target_name, bytes = body.len(), "delivered");
        Ok(target_name)
    }

    // ─── List ─────────────────────────────────────────────────────────────────────────

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
            if !dir.exists() {
                continue;
            }
            let mut rd = fs::read_dir(&dir).await?;
            while let Some(entry) = rd.next_entry().await? {
                let meta = entry.metadata().await?;
                if !meta.is_file() {
                    continue;
                }
                let filename = entry.file_name().to_string_lossy().into_owned();
                let flags = parse_maildir_flags(&filename);
                entries.push(MaildirEntry {
                    path: entry.path(),
                    filename: filename.clone(),
                    size: meta.len(),
                    seen: !in_new && flags.contains('S'),
                    flagged: flags.contains('F'),
                    deleted: flags.contains('T'),
                    answered: flags.contains('R'),
                    draft: flags.contains('D'),
                });
            }
        }
        Ok(entries)
    }

    /// List all folders for a user (INBOX + Maildir++ subdirs).
    pub async fn list_folders(&self, address: &Address) -> Result<Vec<String>, MailboxError> {
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

    pub async fn create_folder(&self, address: &Address, folder: &str) -> Result<(), MailboxError> {
        if folder == "INBOX" {
            return Ok(());
        }
        let dir = self.folder_dir(address, folder);
        for sub in ["cur", "new", "tmp"] {
            fs::create_dir_all(dir.join(sub)).await?;
        }
        fsync_dir(&self.user_dir(address)).await?;
        Ok(())
    }

    pub async fn delete_folder(&self, address: &Address, folder: &str) -> Result<(), MailboxError> {
        if folder == "INBOX" {
            return Err(MailboxError::FolderNotFound(folder.to_owned()));
        }
        let dir = self.folder_dir(address, folder);
        fs::remove_dir_all(&dir).await?;
        fsync_dir(&self.user_dir(address)).await?;
        Ok(())
    }

    pub async fn rename_folder(
        &self,
        address: &Address,
        from: &str,
        to: &str,
    ) -> Result<(), MailboxError> {
        if from == "INBOX" || to == "INBOX" {
            return Err(MailboxError::FolderNotFound(from.to_owned()));
        }
        fs::rename(self.folder_dir(address, from), self.folder_dir(address, to)).await?;
        fsync_dir(&self.user_dir(address)).await?;
        Ok(())
    }

    // ─── Read ────────────────────────────────────────────────────────────────────

    pub async fn read_message(&self, path: &PathBuf) -> Result<Vec<u8>, MailboxError> {
        Ok(tokio::fs::read(path).await?)
    }

    pub async fn copy_message(
        &self,
        address: &Address,
        dest_folder: &str,
        entry: &MaildirEntry,
    ) -> Result<String, MailboxError> {
        let body = self.read_message(&entry.path).await?;
        self.append_to_folder(address, dest_folder, &body, &entry.flags_string())
            .await
    }

    // ─── Move to cur (IMAP "seen") ─────────────────────────────────────────────────────

    /// Move a message from `new/` to `cur/` when IMAP selects the mailbox.
    /// Appends `:2,S` flags to the filename. The `cur/` directory is fsynced
    /// so the rename survives a crash.
    pub async fn move_to_cur(&self, path: &PathBuf) -> Result<PathBuf, MailboxError> {
        let filename = path.file_name().unwrap().to_string_lossy();
        let new_name = if filename.contains(":2,") {
            add_flag(&filename, 'S')
        } else {
            format!("{}:2,S", filename)
        };
        let cur_dir = path.parent().unwrap().parent().unwrap().join("cur");
        let new_path = cur_dir.join(&new_name);
        tokio::fs::rename(path, &new_path).await?;
        let _ = fsync_dir(&cur_dir).await;
        Ok(new_path)
    }

    // ─── Expunge / delete ────────────────────────────────────────────────────────────

    /// Mark a message as deleted by adding the T flag.
    pub async fn mark_deleted(&self, path: &PathBuf) -> Result<PathBuf, MailboxError> {
        self.set_flags(path, &['T'], FlagOp::Add).await
    }

    pub async fn set_flags(
        &self,
        path: &PathBuf,
        flags: &[char],
        op: FlagOp,
    ) -> Result<PathBuf, MailboxError> {
        let filename = path.file_name().unwrap().to_string_lossy();
        let current = parse_maildir_flags(&filename);
        let mut set: std::collections::BTreeSet<char> = current.chars().collect();
        match op {
            FlagOp::Add => {
                set.extend(flags.iter().copied());
            }
            FlagOp::Remove => {
                for flag in flags {
                    set.remove(flag);
                }
            }
            FlagOp::Replace => {
                set = flags.iter().copied().collect();
            }
        }
        let new_name = replace_flags(&filename, &set.iter().collect::<String>());
        let mut parent = path.parent().unwrap().to_owned();
        let target_subdir = if set.contains(&'S') { "cur" } else { "new" };
        if parent
            .file_name()
            .map(|n| n != target_subdir)
            .unwrap_or(false)
        {
            parent = parent.parent().unwrap().join(target_subdir);
        }
        let new_path = parent.join(&new_name);
        tokio::fs::rename(path, &new_path).await?;
        let _ = fsync_dir(&parent).await;
        Ok(new_path)
    }

    /// Permanently remove a message file (called on EXPUNGE).
    pub async fn expunge(&self, path: &PathBuf) -> Result<(), MailboxError> {
        let parent = path.parent().map(|p| p.to_owned());
        tokio::fs::remove_file(path).await?;
        if let Some(p) = parent {
            let _ = fsync_dir(&p).await;
        }
        Ok(())
    }
}

// ─── Types ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MaildirEntry {
    pub path: PathBuf,
    pub filename: String,
    pub size: u64,
    pub seen: bool,
    pub flagged: bool,
    pub deleted: bool,
    pub answered: bool,
    pub draft: bool,
}

impl MaildirEntry {
    pub fn flags_string(&self) -> String {
        let mut flags = String::new();
        if self.seen {
            flags.push('S');
        }
        if self.flagged {
            flags.push('F');
        }
        if self.deleted {
            flags.push('T');
        }
        if self.answered {
            flags.push('R');
        }
        if self.draft {
            flags.push('D');
        }
        normalize_flags(&flags)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FlagOp {
    Add,
    Remove,
    Replace,
}

// ─── Helpers ────────────────────────────────────────────────────────────────────

/// Generate a unique Maildir filename.
/// Format: `<timestamp>.<pid>_<counter>.rmail`
fn unique_filename() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}.{}_{}.rmail", ts, pid, n)
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
        format!(
            "{}:2,{}",
            &filename[..idx],
            chars.iter().collect::<String>()
        )
    } else {
        format!("{}:2,{}", filename, flag)
    }
}

fn replace_flags(filename: &str, flags: &str) -> String {
    let flags = normalize_flags(flags);
    if let Some(idx) = filename.rfind(":2,") {
        format!("{}:2,{}", &filename[..idx], flags)
    } else {
        format!("{}:2,{}", filename, flags)
    }
}

fn normalize_flags(flags: &str) -> String {
    let mut chars: Vec<char> = flags.chars().collect();
    chars.sort_unstable();
    chars.dedup();
    chars.iter().collect()
}

/// fsync(2) a directory so that recent rename/create/unlink operations are
/// durable. On Unix filesystems, file fsync alone is not sufficient for
/// directory entry persistence.
async fn fsync_dir(path: &Path) -> std::io::Result<()> {
    let f = fs::File::open(path).await?;
    f.sync_all().await?;
    Ok(())
}
