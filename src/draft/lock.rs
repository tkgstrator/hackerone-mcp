//! Directory-level advisory lock (`.drafts.lock`), never deleted.

use std::fs::{File, OpenOptions, TryLockError};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

use super::model::random_token;
use crate::error::{Error, Result};

pub const LOCK_NAME: &str = ".drafts.lock";
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Open (creating if needed) and validate the lock file, then take the lock
/// with a bounded retry. The lock is released when the returned file drops.
pub fn acquire(dir: &Path, uid: u32, timeout: Duration) -> Result<File> {
    let path = dir.join(LOCK_NAME);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|e| Error::Draft(format!("cannot open lock file: {e}")))?;
    let meta = file
        .metadata()
        .map_err(|e| Error::Draft(format!("cannot stat lock file: {e}")))?;
    if !meta.is_file() {
        return Err(Error::Draft("lock file is not a regular file".into()));
    }
    if meta.uid() != uid {
        return Err(Error::Draft("lock file has the wrong owner".into()));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(Error::Draft(
            "lock file is accessible by group/other".into(),
        ));
    }
    let deadline = Instant::now() + timeout;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(Error::Busy);
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(TryLockError::Error(e)) => {
                return Err(Error::Draft(format!("cannot lock drafts directory: {e}")));
            }
        }
    }
}

/// Learn our euid without `unsafe`: create a probe file and read its owner.
pub fn probe_uid(dir: &Path) -> Result<u32> {
    let probe = dir.join(format!(".probe-{}", random_token(16)));
    let f = super::store::open_new(&probe)
        .map_err(|e| super::store::io_err("cannot write to drafts directory", e))?;
    let uid = f.metadata().map(|m| m.uid());
    drop(f);
    let _ = std::fs::remove_file(&probe);
    uid.map_err(|e| super::store::io_err("cannot stat probe file", e))
}
