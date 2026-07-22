//! Maildir++ mailbox storage.
//!
//! ## Layout
//! ```text
//! mailbox_dir/<domain>/<local>/
//! ├── cur/          messages seen by IMAP
//! ├── new/          messages not yet seen
//! ├── tmp/          delivery staging (atomic rename to new/)
//! ├── rmail-uidmap  persistent IMAP UID ↔ filename mapping
//! ├── .Sent/{cur,new,tmp}
//! ├── .Drafts/{cur,new,tmp}
//! ├── .Trash/{cur,new,tmp}
//! └── .Junk/{cur,new,tmp}
//! ```
//!
//! One file = one message. Lock-free thanks to atomic `rename(2)` from
//! `tmp/` to `new/`. Every state-changing rename is followed by a parent-
//! directory fsync so the change is durable across kernel crashes.
//!
//! IMAP UIDs are persistent: each folder owns a `rmail-uidmap` file mapping
//! UIDs to message basenames, plus a stable UIDVALIDITY. UIDs never shrink
//! and never repeat.

use rmail_config::{StorageBackend, StorageConfig};
use rmail_core::Address;
use rmail_storage::{S3Store, StorageError};
use std::collections::BTreeSet;
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
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("storage.backend = \"s3\" requires [storage.s3]")]
    MissingS3Config,
}

pub struct Maildir {
    root: PathBuf,
    s3: Option<S3Store>,
}

/// Reject address components that could escape the mailbox root.
fn validate_address(address: &Address) -> Result<(), MailboxError> {
    let bad = |p: &str| {
        p.is_empty()
            || p.contains("..")
            || p.contains('/')
            || p.contains('\\')
            || p.chars().any(|c| c.is_control() || c.is_whitespace())
    };
    if bad(&address.local) || bad(&address.domain) {
        return Err(MailboxError::InvalidAddress(address.as_str()));
    }
    Ok(())
}

impl Maildir {
    pub fn new(root: PathBuf) -> Self {
        Self { root, s3: None }
    }

    pub fn from_storage_config(config: &StorageConfig) -> Result<Self, MailboxError> {
        match config.backend {
            StorageBackend::Local => Ok(Self::new(config.mailbox_dir.clone())),
            StorageBackend::S3 => {
                let s3 = config.s3.as_ref().ok_or(MailboxError::MissingS3Config)?;
                Ok(Self {
                    root: config.mailbox_dir.clone(),
                    s3: Some(S3Store::new(s3)),
                })
            }
        }
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

    fn user_prefix(&self, address: &Address) -> String {
        format!("mail/{}/{}/", address.domain, address.local)
    }

    fn folder_prefix(&self, address: &Address, folder: &str) -> String {
        if folder == "INBOX" {
            self.user_prefix(address)
        } else {
            format!("{}.{}/", self.user_prefix(address), folder)
        }
    }

    fn resolve_path(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_owned()
        } else {
            self.root.join(path)
        }
    }

    async fn s3_user_exists(
        &self,
        store: &S3Store,
        address: &Address,
    ) -> Result<bool, MailboxError> {
        Ok(!store
            .list(&format!("{}cur/", self.user_prefix(address)))
            .await?
            .is_empty())
    }

    // ─── Provisioning ─────────────────────────────────────────────────────────────

    /// Create the full Maildir++ structure for a new user.
    pub async fn create_user(&self, address: &Address) -> Result<(), MailboxError> {
        validate_address(address)?;
        if let Some(store) = &self.s3 {
            for folder in ["INBOX", "Sent", "Drafts", "Trash", "Junk"] {
                for sub in ["cur", "new", "tmp"] {
                    store
                        .put(
                            &format!("{}{}/.keep", self.folder_prefix(address, folder), sub),
                            Vec::new(),
                        )
                        .await?;
                }
            }
            info!(address = %address, "s3 maildir created");
            return Ok(());
        }
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
        if validate_address(address).is_err() {
            return false;
        }
        if let Some(store) = &self.s3 {
            return self.s3_user_exists(store, address).await.unwrap_or(false);
        }
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
        validate_address(address)?;
        if let Some(store) = &self.s3 {
            if !self.s3_user_exists(store, address).await? {
                return Err(MailboxError::UserNotFound(address.as_str()));
            }
            let prefix = self.folder_prefix(address, folder);
            if folder != "INBOX" && store.list(&prefix).await?.is_empty() {
                return Err(MailboxError::FolderNotFound(folder.to_owned()));
            }
            let filename = unique_filename();
            let target_name = if flags.is_empty() {
                filename
            } else {
                format!("{}:2,{}", filename, normalize_flags(flags))
            };
            let target_subdir = if flags.contains('S') { "cur" } else { "new" };
            let key = format!("{}{}/{}", prefix, target_subdir, target_name);
            store.put(&key, body.to_vec()).await?;
            debug!(address = %address, folder, file = %target_name, bytes = body.len(), "s3 delivered");
            return Ok(target_name);
        }
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

    /// List all messages in a folder (both `cur/` and `new/`), with stable
    /// IMAP UIDs. Reconciles the folder's `rmail-uidmap` file on every call.
    pub async fn list_messages(
        &self,
        address: &Address,
        folder: &str,
    ) -> Result<FolderListing, MailboxError> {
        validate_address(address)?;
        if let Some(store) = &self.s3 {
            return self.list_messages_s3(store, address, folder).await;
        }
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
                let mtime = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or_else(|| filename_timestamp(&filename));
                entries.push(MaildirEntry {
                    path: entry.path(),
                    filename: filename.clone(),
                    size: meta.len(),
                    seen: !in_new && flags.contains('S'),
                    flagged: flags.contains('F'),
                    deleted: flags.contains('T'),
                    answered: flags.contains('R'),
                    draft: flags.contains('D'),
                    uid: 0,
                    recent: in_new,
                    mtime,
                });
            }
        }

        let db_path = folder_dir.join(UIDMAP_FILE);
        let raw = fs::read(&db_path).await.ok();
        let mut map = raw
            .as_deref()
            .and_then(UidMap::parse)
            .unwrap_or_default();
        // Persist even when unchanged if the file did not exist yet, so an
        // empty folder keeps a stable UIDVALIDITY across sessions.
        if map.reconcile(&mut entries) || raw.is_none() {
            let tmp = folder_dir.join(".rmail-uidmap.tmp");
            if fs::write(&tmp, map.serialize()).await.is_ok() {
                let _ = fs::rename(&tmp, &db_path).await;
                let _ = fsync_dir(&folder_dir).await;
            }
        }
        Ok(FolderListing {
            entries,
            uid_validity: map.validity,
            uid_next: map.next,
        })
    }

    async fn list_messages_s3(
        &self,
        store: &S3Store,
        address: &Address,
        folder: &str,
    ) -> Result<FolderListing, MailboxError> {
        let folder_prefix = self.folder_prefix(address, folder);
        if folder != "INBOX" && store.list(&folder_prefix).await?.is_empty() {
            return Err(MailboxError::FolderNotFound(folder.to_owned()));
        }
        let mut entries = Vec::new();
        for (subdir, in_new) in [("new", true), ("cur", false)] {
            let prefix = format!("{}{}/", folder_prefix, subdir);
            for item in store.list_detailed(&prefix).await? {
                let Some(filename) = item.key.strip_prefix(&prefix) else {
                    continue;
                };
                if filename == ".keep" || filename.contains('/') {
                    continue;
                }
                let filename = filename.to_owned();
                let flags = parse_maildir_flags(&filename);
                entries.push(MaildirEntry {
                    path: PathBuf::from(&item.key),
                    filename: filename.clone(),
                    size: item.size,
                    seen: !in_new && flags.contains('S'),
                    flagged: flags.contains('F'),
                    deleted: flags.contains('T'),
                    answered: flags.contains('R'),
                    draft: flags.contains('D'),
                    uid: 0,
                    recent: in_new,
                    mtime: filename_timestamp(&filename),
                });
            }
        }

        let db_key = format!("{}{}", folder_prefix, UIDMAP_FILE);
        let raw = store.get(&db_key).await.ok();
        let mut map = raw
            .as_deref()
            .and_then(UidMap::parse)
            .unwrap_or_default();
        if map.reconcile(&mut entries) || raw.is_none() {
            let _ = store.put(&db_key, map.serialize()).await;
        }
        Ok(FolderListing {
            entries,
            uid_validity: map.validity,
            uid_next: map.next,
        })
    }

    /// List all folders for a user (INBOX + Maildir++ subdirs).
    pub async fn list_folders(&self, address: &Address) -> Result<Vec<String>, MailboxError> {
        validate_address(address)?;
        if let Some(store) = &self.s3 {
            if !self.s3_user_exists(store, address).await? {
                return Err(MailboxError::UserNotFound(address.as_str()));
            }
            let base = self.user_prefix(address);
            let mut folders = BTreeSet::from(["INBOX".to_owned()]);
            for key in store.list(&base).await? {
                let Some(rest) = key.strip_prefix(&base) else {
                    continue;
                };
                if let Some(stripped) = rest.strip_prefix('.') {
                    if let Some((folder, _)) = stripped.split_once('/') {
                        folders.insert(folder.to_owned());
                    }
                }
            }
            return Ok(folders.into_iter().collect());
        }
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
        validate_address(address)?;
        if folder == "INBOX" {
            return Ok(());
        }
        if let Some(store) = &self.s3 {
            for sub in ["cur", "new", "tmp"] {
                store
                    .put(
                        &format!("{}{}/.keep", self.folder_prefix(address, folder), sub),
                        Vec::new(),
                    )
                    .await?;
            }
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
        validate_address(address)?;
        if folder == "INBOX" {
            return Err(MailboxError::FolderNotFound(folder.to_owned()));
        }
        if let Some(store) = &self.s3 {
            let prefix = self.folder_prefix(address, folder);
            for key in store.list(&prefix).await? {
                store.delete(&key).await?;
            }
            return Ok(());
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
        validate_address(address)?;
        if from == "INBOX" || to == "INBOX" {
            return Err(MailboxError::FolderNotFound(from.to_owned()));
        }
        if let Some(store) = &self.s3 {
            let from_prefix = self.folder_prefix(address, from);
            let to_prefix = self.folder_prefix(address, to);
            let keys = store.list(&from_prefix).await?;
            if keys.is_empty() {
                return Err(MailboxError::FolderNotFound(from.to_owned()));
            }
            for key in keys {
                let body = store.get(&key).await?;
                let new_key = key.replacen(&from_prefix, &to_prefix, 1);
                store.put(&new_key, body).await?;
                store.delete(&key).await?;
            }
            return Ok(());
        }
        fs::rename(self.folder_dir(address, from), self.folder_dir(address, to)).await?;
        fsync_dir(&self.user_dir(address)).await?;
        Ok(())
    }

    // ─── Read ────────────────────────────────────────────────────────────────────

    pub async fn read_message(&self, path: &Path) -> Result<Vec<u8>, MailboxError> {
        if let Some(store) = &self.s3 {
            return Ok(store.get(&path.to_string_lossy()).await?.to_vec());
        }
        Ok(tokio::fs::read(self.resolve_path(path)).await?)
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

    // ─── Move to cur (IMAP "seen by a client") ─────────────────────────────────────

    /// Move a message from `new/` to `cur/` when a client selects the mailbox.
    /// The filename (and therefore its flags and UID) is preserved — the
    /// message becomes "no longer recent" but is NOT marked `\Seen`.
    pub async fn move_to_cur(&self, path: &Path) -> Result<PathBuf, MailboxError> {
        if let Some(store) = &self.s3 {
            let key = path.to_string_lossy();
            let filename = s3_filename(&key)?;
            let new_key = s3_replace_subdir_and_name(&key, "cur", filename)?;
            if new_key == key {
                return Ok(path.to_owned());
            }
            let body = store.get(&key).await?;
            store.put(&new_key, body).await?;
            store.delete(&key).await?;
            return Ok(PathBuf::from(new_key));
        }
        let filename = path.file_name().unwrap().to_string_lossy();
        let cur_dir = path.parent().unwrap().parent().unwrap().join("cur");
        let new_path = cur_dir.join(filename.as_ref());
        tokio::fs::rename(path, &new_path).await?;
        let _ = fsync_dir(&cur_dir).await;
        Ok(new_path)
    }

    // ─── Expunge / delete ────────────────────────────────────────────────────────────

    /// Mark a message as deleted by adding the T flag.
    pub async fn mark_deleted(&self, path: &Path) -> Result<PathBuf, MailboxError> {
        self.set_flags(path, &['T'], FlagOp::Add).await
    }

    pub async fn set_flags(
        &self,
        path: &Path,
        flags: &[char],
        op: FlagOp,
    ) -> Result<PathBuf, MailboxError> {
        if let Some(store) = &self.s3 {
            let key = path.to_string_lossy();
            let filename = s3_filename(&key)?;
            let current = parse_maildir_flags(filename);
            let mut set: BTreeSet<char> = current.chars().collect();
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
            let new_name = replace_flags(filename, &set.iter().collect::<String>());
            let target_subdir = if set.contains(&'S') { "cur" } else { "new" };
            let new_key = s3_replace_subdir_and_name(&key, target_subdir, &new_name)?;
            if new_key == key {
                // Flags unchanged — rewriting then deleting the same key
                // would destroy the message.
                return Ok(path.to_owned());
            }
            let body = store.get(&key).await?;
            store.put(&new_key, body).await?;
            store.delete(&key).await?;
            return Ok(PathBuf::from(new_key));
        }
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
        tokio::fs::rename(self.resolve_path(path), &new_path).await?;
        let _ = fsync_dir(&parent).await;
        Ok(new_path)
    }

    /// Permanently remove a message file (called on EXPUNGE).
    pub async fn expunge(&self, path: &Path) -> Result<(), MailboxError> {
        if let Some(store) = &self.s3 {
            store.delete(&path.to_string_lossy()).await?;
            return Ok(());
        }
        let parent = path.parent().map(|p| p.to_owned());
        tokio::fs::remove_file(self.resolve_path(path)).await?;
        if let Some(p) = parent {
            let _ = fsync_dir(&p).await;
        }
        Ok(())
    }
}

// ─── Types ──────────────────────────────────────────────────────────────────────

/// Result of listing a folder: messages plus IMAP UID metadata.
#[derive(Debug, Clone)]
pub struct FolderListing {
    pub entries: Vec<MaildirEntry>,
    pub uid_validity: u32,
    pub uid_next: u32,
}

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
    /// Persistent IMAP UID (assigned from the folder's uidmap).
    pub uid: u32,
    /// True while the message sits in `new/` (never seen by any client).
    pub recent: bool,
    /// Modification / delivery time as unix seconds.
    pub mtime: i64,
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

// ─── Persistent UID map ─────────────────────────────────────────────────────────

const UIDMAP_FILE: &str = "rmail-uidmap";

/// On-disk UID database for one folder. First line: `V <uidvalidity> <next>`.
/// Following lines: `<uid> <basename>` (basename = filename without `:2,`
/// flags, so flag changes and `new/`→`cur/` moves keep the UID).
struct UidMap {
    validity: u32,
    next: u32,
    map: Vec<(u32, String)>,
}

impl Default for UidMap {
    fn default() -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            validity: (secs % u32::MAX as u64) as u32,
            next: 1,
            map: Vec::new(),
        }
    }
}

impl UidMap {
    fn parse(raw: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(raw).ok()?;
        let mut lines = text.lines();
        let header = lines.next()?;
        let mut parts = header.split_whitespace();
        if parts.next()? != "V" {
            return None;
        }
        let validity = parts.next()?.parse().ok()?;
        let next = parts.next()?.parse().ok()?;
        let mut map = Vec::new();
        for line in lines {
            let (uid, name) = line.split_once(' ')?;
            map.push((uid.parse().ok()?, name.to_owned()));
        }
        Some(Self {
            validity,
            next,
            map,
        })
    }

    fn serialize(&self) -> Vec<u8> {
        let mut out = format!("V {} {}\n", self.validity, self.next);
        for (uid, name) in &self.map {
            out.push_str(&format!("{} {}\n", uid, name));
        }
        out.into_bytes()
    }

    /// Assign UIDs to every entry. Removes mappings for vanished files,
    /// allocates fresh UIDs for new files. Returns true when the map changed.
    fn reconcile(&mut self, entries: &mut [MaildirEntry]) -> bool {
        let mut changed = false;
        let present: BTreeSet<&str> = entries
            .iter()
            .map(|e| basename(&e.filename))
            .collect();
        let before = self.map.len();
        self.map.retain(|(_, name)| present.contains(name.as_str()));
        if self.map.len() != before {
            changed = true;
        }
        for entry in entries.iter_mut() {
            let base = basename(&entry.filename);
            if let Some((uid, _)) = self.map.iter().find(|(_, n)| n == base) {
                entry.uid = *uid;
            } else {
                let uid = self.next;
                self.next = self.next.saturating_add(1);
                self.map.push((uid, base.to_owned()));
                entry.uid = uid;
                changed = true;
            }
        }
        changed
    }
}

/// Filename without the `:2,FLAGS` Maildir suffix.
fn basename(filename: &str) -> &str {
    filename.split_once(":2,").map(|(base, _)| base).unwrap_or(filename)
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

/// Delivery time encoded in the unique filename (epoch seconds prefix).
fn filename_timestamp(filename: &str) -> i64 {
    filename
        .split_once('.')
        .and_then(|(ts, _)| ts.parse::<i64>().ok())
        .unwrap_or(0)
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

fn s3_filename(key: &str) -> Result<&str, MailboxError> {
    key.rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| MailboxError::FolderNotFound(key.to_owned()))
}

fn s3_replace_subdir_and_name(
    key: &str,
    target_subdir: &str,
    new_name: &str,
) -> Result<String, MailboxError> {
    let mut parts = key.rsplitn(3, '/');
    let _name = parts
        .next()
        .ok_or_else(|| MailboxError::FolderNotFound(key.to_owned()))?;
    let _subdir = parts
        .next()
        .ok_or_else(|| MailboxError::FolderNotFound(key.to_owned()))?;
    let base = parts
        .next()
        .ok_or_else(|| MailboxError::FolderNotFound(key.to_owned()))?;
    Ok(format!("{}/{}/{}", base, target_subdir, new_name))
}

/// fsync(2) a directory so that recent rename/create/unlink operations are
/// durable. On Unix filesystems, file fsync alone is not sufficient for
/// directory entry persistence.
async fn fsync_dir(path: &Path) -> std::io::Result<()> {
    let f = fs::File::open(path).await?;
    f.sync_all().await?;
    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uidmap_roundtrip() {
        let mut map = UidMap {
            validity: 42,
            ..UidMap::default()
        };
        let mut entries = vec![
            MaildirEntry {
                path: PathBuf::from("/x/new/1.2_3.rmail"),
                filename: "1.2_3.rmail".into(),
                size: 10,
                seen: false,
                flagged: false,
                deleted: false,
                answered: false,
                draft: false,
                uid: 0,
                recent: true,
                mtime: 1,
            },
            MaildirEntry {
                path: PathBuf::from("/x/cur/4.5_6.rmail:2,S"),
                filename: "4.5_6.rmail:2,S".into(),
                size: 20,
                seen: true,
                flagged: false,
                deleted: false,
                answered: false,
                draft: false,
                uid: 0,
                recent: false,
                mtime: 2,
            },
        ];
        assert!(map.reconcile(&mut entries));
        assert_eq!(entries[0].uid, 1);
        assert_eq!(entries[1].uid, 2);
        assert_eq!(map.next, 3);

        // Flags change → same basename → same UID, no map change.
        entries[1].filename = "4.5_6.rmail:2,FS".into();
        assert!(!map.reconcile(&mut entries));
        assert_eq!(entries[1].uid, 2);

        // Survives a serialize/parse cycle.
        let bytes = map.serialize();
        let mut map2 = UidMap::parse(&bytes).unwrap();
        assert_eq!(map2.validity, 42);
        assert!(!map2.reconcile(&mut entries));
        assert_eq!(entries[0].uid, 1);

        // New message gets the next UID; vanished message is dropped.
        entries.remove(0);
        entries.push(MaildirEntry {
            path: PathBuf::from("/x/new/7.8_9.rmail"),
            filename: "7.8_9.rmail".into(),
            size: 5,
            seen: false,
            flagged: false,
            deleted: false,
            answered: false,
            draft: false,
            uid: 0,
            recent: true,
            mtime: 3,
        });
        assert!(map2.reconcile(&mut entries));
        assert_eq!(entries[1].uid, 3);
        assert_eq!(map2.map.len(), 2);
    }

    #[test]
    fn validate_address_rejects_traversal() {
        let mut a = Address {
            local: "..".into(),
            domain: "example.com".into(),
        };
        assert!(validate_address(&a).is_err());
        a.local = "alice".into();
        assert!(validate_address(&a).is_ok());
        a.domain = "exa/mple.com".into();
        assert!(validate_address(&a).is_err());
    }
}
