//! Private workflow records share the draft mutation lock.

use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use super::{DraftStore, Inner, blocking, io_err, open_new};
use crate::draft::model::Stored;
use crate::draft::model::random_token;
use crate::error::{Error, Result};

pub(crate) const MAX_WORKFLOW_BYTES: usize = 8 * 1024 * 1024;

fn validate_key(key: &str) -> Result<()> {
    if key.is_empty()
        || key.len() > 100
        || !key
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(Error::Validation("invalid internal workflow key".into()));
    }
    Ok(())
}

fn read_record(inner: &Inner, key: &str) -> Result<Option<Value>> {
    let path = inner.dir.join(format!(".workflow-{key}.json"));
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err("cannot open workflow record", e)),
    };
    let meta = file
        .metadata()
        .map_err(|e| io_err("cannot stat workflow record", e))?;
    if !meta.is_file() || meta.uid() != inner.uid || meta.mode() & 0o077 != 0 || meta.nlink() != 1 {
        return Err(Error::Draft(
            "workflow record must be a private owned regular file with one link".into(),
        ));
    }
    if meta.len() > MAX_WORKFLOW_BYTES as u64 {
        return Err(Error::Draft("workflow record exceeds 8 MiB limit".into()));
    }
    let mut bytes = Vec::new();
    file.take(MAX_WORKFLOW_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_err("cannot read workflow record", e))?;
    if bytes.len() > MAX_WORKFLOW_BYTES {
        return Err(Error::Draft("workflow record exceeds 8 MiB limit".into()));
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| Error::Draft("corrupt workflow record; refusing to reset it".into()))
}

fn sync_directory(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

fn write_record(
    inner: &Inner,
    key: &str,
    record: &Value,
    sync: impl FnOnce(&Path) -> std::io::Result<()>,
) -> Result<()> {
    let bytes = serde_json::to_vec(record)
        .map_err(|_| Error::Draft("cannot serialize workflow record".into()))?;
    if bytes.len() > MAX_WORKFLOW_BYTES {
        return Err(Error::Draft(
            "workflow record exceeds 8 MiB limit; nothing was advanced".into(),
        ));
    }
    let temp = inner
        .dir
        .join(format!(".tmp-{}.workflow.part", random_token(24)));
    let result = (|| {
        let mut file =
            open_new(&temp).map_err(|e| io_err("cannot create workflow temporary file", e))?;
        file.write_all(&bytes)
            .map_err(|e| io_err("cannot write workflow record", e))?;
        file.sync_all()
            .map_err(|e| io_err("cannot sync workflow record", e))?;
        fs::rename(&temp, inner.dir.join(format!(".workflow-{key}.json")))
            .map_err(|e| io_err("cannot replace workflow record", e))?;
        sync(&inner.dir).map_err(|e| {
            io_err(
                "cannot durably sync workflow directory; no send is permitted",
                e,
            )
        })
    })();
    let _ = fs::remove_file(temp);
    result
}

impl DraftStore {
    pub async fn workflow_read(&self, key: &str) -> Result<Option<Value>> {
        validate_key(key)?;
        let (inner, key) = (self.inner.clone(), key.to_owned());
        blocking(move || inner.with_lock(|| read_record(&inner, &key))).await
    }

    pub async fn workflow_transaction<R, F>(
        &self,
        key: &str,
        draft_id: Option<&str>,
        f: F,
    ) -> Result<R>
    where
        R: Send + 'static,
        F: FnOnce(Option<Value>, Option<Stored>) -> Result<(Option<Value>, R)> + Send + 'static,
    {
        validate_key(key)?;
        let (inner, key, draft_id) = (
            self.inner.clone(),
            key.to_owned(),
            draft_id.map(str::to_owned),
        );
        blocking(move || {
            inner.with_lock(|| {
                let old = read_record(&inner, &key)?;
                let draft = draft_id.as_deref().map(|id| inner.read(id)).transpose()?;
                let (new, result) = f(old, draft)?;
                if let Some(value) = new {
                    write_record(&inner, &key, &value, sync_directory)?;
                }
                Ok(result)
            })
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::{PermissionsExt, symlink};

    #[tokio::test]
    async fn records_are_private_atomic_and_persistent() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("drafts");
        let store = DraftStore::open(dir.clone()).unwrap();
        let value = store
            .workflow_transaction("state", None, |old, draft| {
                assert!(old.is_none() && draft.is_none());
                Ok((Some(json!({"counter":1})), "saved"))
            })
            .await
            .unwrap();
        assert_eq!(value, "saved");
        let file = dir.join(".workflow-state.json");
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let reopened = DraftStore::open(dir.clone()).unwrap();
        assert_eq!(
            reopened.workflow_read("state").await.unwrap(),
            Some(json!({"counter":1}))
        );
        reopened
            .workflow_transaction("state", None, |old, _| {
                assert_eq!(old, Some(json!({"counter":1})));
                Ok((None, ()))
            })
            .await
            .unwrap();
        assert_eq!(
            reopened.workflow_read("state").await.unwrap(),
            Some(json!({"counter":1}))
        );
        assert!(reopened.list(None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn malformed_and_insecure_records_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("drafts");
        let store = DraftStore::open(dir.clone()).unwrap();
        let external = temp.path().join("external");
        std::fs::write(&external, "{}").unwrap();
        symlink(&external, dir.join(".workflow-linked.json")).unwrap();
        assert!(store.workflow_read("linked").await.is_err());
        let corrupt = dir.join(".workflow-corrupt.json");
        std::fs::write(&corrupt, "{broken").unwrap();
        std::fs::set_permissions(&corrupt, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(store.workflow_read("corrupt").await.is_err());
        let public = dir.join(".workflow-public.json");
        std::fs::write(&public, "{}").unwrap();
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(store.workflow_read("public").await.is_err());
        for key in ["../escape", "UPPER", "a/b", "", &"a".repeat(101)] {
            assert!(store.workflow_read(key).await.is_err());
        }
    }

    #[tokio::test]
    async fn transaction_serializes_concurrent_updates() {
        let temp = tempfile::tempdir().unwrap();
        let store = DraftStore::open(temp.path().join("drafts")).unwrap();
        let mut jobs = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            jobs.push(tokio::spawn(async move {
                store
                    .workflow_transaction("counter", None, |old, _| {
                        let n = old.and_then(|v| v["n"].as_u64()).unwrap_or(0);
                        Ok((Some(json!({"n":n+1})), ()))
                    })
                    .await
                    .unwrap();
            }));
        }
        for job in jobs {
            job.await.unwrap();
        }
        assert_eq!(
            store.workflow_read("counter").await.unwrap().unwrap()["n"],
            8
        );
    }

    #[tokio::test]
    async fn size_limits_preserve_previous_record() {
        let temp = tempfile::tempdir().unwrap();
        let store = DraftStore::open(temp.path().join("drafts")).unwrap();
        store
            .workflow_transaction("state", None, |_, _| Ok((Some(json!({"safe":true})), ())))
            .await
            .unwrap();
        assert!(
            store
                .workflow_transaction("state", None, |_, _| Ok((
                    Some(json!("x".repeat(MAX_WORKFLOW_BYTES))),
                    ()
                )))
                .await
                .is_err()
        );
        assert_eq!(
            store.workflow_read("state").await.unwrap(),
            Some(json!({"safe":true}))
        );
    }

    #[test]
    fn directory_sync_failure_is_an_error_and_keeps_consumed_record() {
        let temp = tempfile::tempdir().unwrap();
        let store = DraftStore::open(temp.path().join("drafts")).unwrap();
        let value = json!({"state":"attempting"});
        let result = write_record(&store.inner, "claim", &value, |_| {
            Err(std::io::Error::other("injected sync failure"))
        });
        assert!(result.is_err());
        assert_eq!(read_record(&store.inner, "claim").unwrap(), Some(value));
    }

    #[tokio::test]
    async fn stale_workflow_temps_are_removed_but_young_and_unrelated_files_remain() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("drafts");
        let store = DraftStore::open(dir.clone()).unwrap();
        let stale = dir.join(".tmp-abandoned.workflow.part");
        let old = open_new(&stale).unwrap();
        old.set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(601)),
        )
        .unwrap();
        drop(old);
        let young = dir.join(".tmp-active.workflow.part");
        open_new(&young).unwrap();
        let unrelated = dir.join("keep.workflow.part");
        open_new(&unrelated).unwrap();
        store.workflow_read("missing").await.unwrap();
        assert!(!stale.exists());
        assert!(young.exists() && unrelated.exists());
    }
}
