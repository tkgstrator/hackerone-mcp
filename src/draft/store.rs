//! Hardened on-disk draft store. See module docs in `lock.rs` and `frontmatter.rs`.
//!
//! Ownership checks in safe Rust: `libc::geteuid()` is unsafe, so the effective
//! uid is learned by creating a probe file (`create_new`, `O_NOFOLLOW`, 0600)
//! inside the verified drafts directory and reading its owner via `MetadataExt`.
//! A file we create is always owned by our euid. The directory and the lock
//! file must then be owned by that uid with no group/other permission bits.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde::Serialize;

use super::frontmatter;
use super::lock;
use super::model::{Draft, MAX_FILE_BYTES, Severity, Stored, now_secs, random_token, validate_id};
use crate::error::{Error, Result};

const STALE_TEMP: Duration = Duration::from_secs(600);
pub const DEFAULT_LIST_LIMIT: usize = 50;
pub const MAX_LIST_LIMIT: usize = 200;

/// Summary row returned by `list` (no body).
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub id: String,
    pub title: String,
    pub revision: u64,
    pub updated_at: u64,
    pub severity_rating: Option<Severity>,
    pub team_handle: Option<String>,
    /// False when the file exists but cannot be parsed/validated.
    pub valid: bool,
}

struct Inner {
    dir: PathBuf,
    uid: u32,
    lock_timeout: Duration,
}

#[derive(Clone)]
pub struct DraftStore {
    inner: Arc<Inner>,
}

pub(super) fn io_err(what: &str, e: std::io::Error) -> Error {
    Error::Draft(format!("{what}: {e}"))
}

fn not_found(id: &str) -> Error {
    Error::Draft(format!("draft '{id}' not found"))
}

fn check_dir(dir: &Path, uid: u32) -> Result<()> {
    let m = fs::symlink_metadata(dir).map_err(|e| io_err("cannot stat drafts directory", e))?;
    if m.file_type().is_symlink() {
        return Err(Error::Draft("drafts directory is a symlink".into()));
    }
    if !m.is_dir() {
        return Err(Error::Draft("drafts path is not a directory".into()));
    }
    if m.uid() != uid {
        return Err(Error::Draft("drafts directory has the wrong owner".into()));
    }
    if m.mode() & 0o077 != 0 {
        return Err(Error::Draft(
            "drafts directory is accessible by group/other (expected mode 0700)".into(),
        ));
    }
    Ok(())
}

pub(super) fn open_new(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

fn read_file(path: &Path) -> Result<Option<String>> {
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err("cannot open draft", e)),
    };
    let m = f.metadata().map_err(|e| io_err("cannot stat draft", e))?;
    if !m.is_file() {
        return Err(Error::Draft("draft is not a regular file".into()));
    }
    if m.len() > MAX_FILE_BYTES as u64 {
        return Err(Error::Draft("draft file exceeds size limit".into()));
    }
    let mut buf = Vec::new();
    f.take(MAX_FILE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .map_err(|e| io_err("cannot read draft", e))?;
    if buf.len() > MAX_FILE_BYTES {
        return Err(Error::Draft("draft file exceeds size limit".into()));
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| Error::Draft("draft file is not valid UTF-8".into()))
}

impl Inner {
    fn path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.md"))
    }

    fn read(&self, id: &str) -> Result<Stored> {
        validate_id(id)?;
        let text = read_file(&self.path(id))?.ok_or_else(|| not_found(id))?;
        let s = frontmatter::parse(&text)?;
        if s.draft.id != id {
            return Err(Error::Draft(format!(
                "draft file '{id}.md' contains mismatching id"
            )));
        }
        Ok(s)
    }

    fn with_lock<T>(&self, f: impl FnOnce() -> Result<T>) -> Result<T> {
        check_dir(&self.dir, self.uid)?;
        let _guard = lock::acquire(&self.dir, self.uid, self.lock_timeout)?;
        self.sweep_stale();
        f()
    }

    fn sweep_stale(&self) {
        let Ok(rd) = fs::read_dir(&self.dir) else {
            return;
        };
        for e in rd.flatten() {
            let name = e.file_name();
            let Some(name) = name.to_str() else { continue };
            if !(name.starts_with(".tmp-") && name.ends_with(".md.part")) {
                continue;
            }
            let Ok(m) = fs::symlink_metadata(e.path()) else {
                continue;
            };
            let old = m
                .modified()
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .is_some_and(|age| age > STALE_TEMP);
            if m.is_file() && old {
                let _ = fs::remove_file(e.path());
            }
        }
    }

    /// Write a new temp file with the full content; returns its path.
    fn write_temp(&self, content: &str) -> Result<PathBuf> {
        let tmp = self.dir.join(format!(".tmp-{}.md.part", random_token(16)));
        let res = open_new(&tmp).and_then(|mut f| {
            f.write_all(content.as_bytes())?;
            f.sync_all()
        });
        match res {
            Ok(()) => Ok(tmp),
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                Err(io_err("cannot write draft", e))
            }
        }
    }

    fn sync_dir(&self) {
        if let Ok(d) = File::open(&self.dir) {
            let _ = d.sync_all();
        }
    }

    fn create(&self, mut draft: Draft, body: &str) -> Result<Stored> {
        validate_id(&draft.id)?;
        let now = now_secs();
        draft.revision = 1;
        draft.created_at = now;
        draft.updated_at = now;
        draft.status = "draft".into();
        let content = frontmatter::render(&draft, body)?;
        self.with_lock(|| {
            let tmp = self.write_temp(&content)?;
            let linked = fs::hard_link(&tmp, self.path(&draft.id));
            let _ = fs::remove_file(&tmp);
            match linked {
                Ok(()) => {
                    self.sync_dir();
                    Ok(Stored {
                        draft: draft.clone(),
                        body: body.to_string(),
                    })
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    Err(Error::Draft(format!("draft '{}' already exists", draft.id)))
                }
                Err(e) => Err(Error::Draft(format!(
                    "cannot create draft (hard links unsupported by this filesystem?): {e}"
                ))),
            }
        })
    }

    fn update(
        &self,
        id: &str,
        expected: Option<u64>,
        f: impl FnOnce(&mut Draft, &mut String) -> Result<()>,
    ) -> Result<Stored> {
        validate_id(id)?;
        self.with_lock(|| {
            let mut s = self.read(id)?;
            check_revision(id, expected, s.draft.revision)?;
            f(&mut s.draft, &mut s.body)?;
            if s.draft.id != id {
                return Err(Error::Validation("draft id cannot be changed".into()));
            }
            s.draft.revision += 1;
            s.draft.updated_at = now_secs();
            let content = frontmatter::render(&s.draft, &s.body)?;
            let tmp = self.write_temp(&content)?;
            if let Err(e) = fs::rename(&tmp, self.path(id)) {
                let _ = fs::remove_file(&tmp);
                return Err(io_err("cannot replace draft", e));
            }
            self.sync_dir();
            Ok(s)
        })
    }

    fn delete(&self, id: &str, expected: Option<u64>) -> Result<()> {
        validate_id(id)?;
        self.with_lock(|| {
            let path = self.path(id);
            let m = fs::symlink_metadata(&path).map_err(|_| not_found(id))?;
            if !m.is_file() {
                return Err(Error::Draft("draft is not a regular file".into()));
            }
            if expected.is_some() {
                let s = self.read(id)?;
                check_revision(id, expected, s.draft.revision)?;
            }
            fs::remove_file(&path).map_err(|e| io_err("cannot delete draft", e))?;
            self.sync_dir();
            Ok(())
        })
    }

    fn list(&self, limit: usize) -> Result<Vec<Summary>> {
        check_dir(&self.dir, self.uid)?;
        let rd = fs::read_dir(&self.dir).map_err(|e| io_err("cannot list drafts", e))?;
        let mut rows = Vec::new();
        for e in rd.flatten() {
            let name = e.file_name();
            let Some(id) = name.to_str().and_then(|n| n.strip_suffix(".md")) else {
                continue;
            };
            if validate_id(id).is_err() {
                continue;
            }
            match fs::symlink_metadata(e.path()) {
                Ok(m) if m.is_file() => {}
                _ => continue,
            }
            rows.push(match self.read(id) {
                Ok(s) => Summary {
                    id: id.to_string(),
                    title: s.draft.title,
                    revision: s.draft.revision,
                    updated_at: s.draft.updated_at,
                    severity_rating: s.draft.severity_rating,
                    team_handle: s.draft.team_handle,
                    valid: true,
                },
                Err(_) => Summary {
                    id: id.to_string(),
                    title: String::new(),
                    revision: 0,
                    updated_at: 0,
                    severity_rating: None,
                    team_handle: None,
                    valid: false,
                },
            });
        }
        rows.sort_by(|a, b| b.updated_at.cmp(&a.updated_at).then(a.id.cmp(&b.id)));
        rows.truncate(limit);
        Ok(rows)
    }
}

fn check_revision(id: &str, expected: Option<u64>, current: u64) -> Result<()> {
    match expected {
        Some(x) if x != current => Err(Error::Draft(format!(
            "revision conflict for '{id}': expected {x}, current revision is {current}"
        ))),
        _ => Ok(()),
    }
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| Error::Draft(format!("storage task failed: {e}")))?
}

impl DraftStore {
    /// Open (creating with mode 0700 if absent) and verify the drafts directory.
    pub fn open(dir: PathBuf) -> Result<Self> {
        Self::open_with_timeout(dir, lock::DEFAULT_TIMEOUT)
    }

    pub(crate) fn open_with_timeout(dir: PathBuf, lock_timeout: Duration) -> Result<Self> {
        let created = match fs::symlink_metadata(&dir) {
            Ok(_) => false,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
                    fs::create_dir_all(parent).map_err(|e| io_err("cannot create parent", e))?;
                }
                DirBuilder::new()
                    .mode(0o700)
                    .create(&dir)
                    .map_err(|e| io_err("cannot create drafts directory", e))?;
                true
            }
            Err(e) => return Err(io_err("cannot stat drafts directory", e)),
        };
        let m = fs::symlink_metadata(&dir).map_err(|e| io_err("cannot stat drafts dir", e))?;
        if m.file_type().is_symlink() || !m.is_dir() {
            return Err(Error::Draft(
                "drafts path must be a real directory, not a symlink or file".into(),
            ));
        }
        if created && m.mode() & 0o077 != 0 {
            // umask cannot widen a 0700 request, but be explicit anyway.
            fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                .map_err(|e| io_err("cannot tighten drafts directory", e))?;
        }
        let uid = lock::probe_uid(&dir)?;
        check_dir(&dir, uid)?;
        Ok(Self {
            inner: Arc::new(Inner {
                dir,
                uid,
                lock_timeout,
            }),
        })
    }

    pub async fn create(&self, draft: Draft, body: String) -> Result<Stored> {
        let i = self.inner.clone();
        blocking(move || i.create(draft, &body)).await
    }

    pub async fn get(&self, id: &str) -> Result<Stored> {
        let (i, id) = (self.inner.clone(), id.to_string());
        blocking(move || i.read(&id)).await
    }

    /// Apply `f` under the lock. `expected_revision` guards against lost updates.
    pub async fn update<F>(&self, id: &str, expected_revision: Option<u64>, f: F) -> Result<Stored>
    where
        F: FnOnce(&mut Draft, &mut String) -> Result<()> + Send + 'static,
    {
        let (i, id) = (self.inner.clone(), id.to_string());
        blocking(move || i.update(&id, expected_revision, f)).await
    }

    pub async fn delete(&self, id: &str, expected_revision: Option<u64>) -> Result<()> {
        let (i, id) = (self.inner.clone(), id.to_string());
        blocking(move || i.delete(&id, expected_revision)).await
    }

    pub async fn list(&self, limit: Option<usize>) -> Result<Vec<Summary>> {
        let limit = limit.unwrap_or(DEFAULT_LIST_LIMIT).clamp(1, MAX_LIST_LIMIT);
        let i = self.inner.clone();
        blocking(move || i.list(limit)).await
    }
}

#[cfg(test)]
mod tests;
