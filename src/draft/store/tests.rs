use std::os::unix::fs::{PermissionsExt, symlink};

use tempfile::TempDir;

use super::*;

fn draft(id: &str) -> Draft {
    Draft::new(id.into(), format!("title {id}"))
}

async fn store() -> (TempDir, DraftStore) {
    let t = TempDir::new().unwrap();
    let s = DraftStore::open(t.path().join("drafts")).unwrap();
    (t, s)
}

#[tokio::test]
async fn crud_round_trip() {
    let (_t, s) = store().await;
    let c = s.create(draft("a"), "body".into()).await.unwrap();
    assert_eq!(c.draft.revision, 1);
    assert_eq!(s.get("a").await.unwrap(), c);
    let u = s
        .update("a", Some(1), |d, b| {
            d.title = "new".into();
            *b = "b2".into();
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!((u.draft.revision, u.body.as_str()), (2, "b2"));
    s.delete("a", Some(2)).await.unwrap();
    assert!(s.get("a").await.is_err());
    assert!(s.delete("a", None).await.is_err());
}

#[tokio::test]
async fn concurrent_create_one_winner() {
    let (_t, s) = store().await;
    let mut hs = Vec::new();
    for n in 0..8 {
        let s = s.clone();
        hs.push(tokio::spawn(async move {
            s.create(draft("same"), format!("b{n}")).await
        }));
    }
    let mut ok = 0;
    for h in hs {
        if h.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    assert_eq!(ok, 1);
}

#[tokio::test]
async fn concurrent_updates_no_lost_update() {
    let (_t, s) = store().await;
    s.create(draft("a"), "".into()).await.unwrap();
    let mut hs = Vec::new();
    for _ in 0..8 {
        let s = s.clone();
        hs.push(tokio::spawn(async move {
            s.update("a", Some(1), |d, _| {
                d.notes = Some("x".into());
                Ok(())
            })
            .await
        }));
    }
    let mut ok = 0;
    for h in hs {
        match h.await.unwrap() {
            Ok(_) => ok += 1,
            Err(e) => assert!(e.to_string().contains("revision conflict"), "{e}"),
        }
    }
    assert_eq!(ok, 1);
    assert_eq!(s.get("a").await.unwrap().draft.revision, 2);
}

#[tokio::test]
async fn lock_busy() {
    let t = TempDir::new().unwrap();
    let dir = t.path().join("d");
    let s = DraftStore::open_with_timeout(dir.clone(), Duration::from_millis(200)).unwrap();
    let held = lock::acquire(&dir, s.inner.uid, Duration::from_secs(1)).unwrap();
    assert!(matches!(
        s.create(draft("a"), "".into()).await,
        Err(Error::Busy)
    ));
    assert!(matches!(s.delete("a", None).await, Err(Error::Busy)));
    drop(held);
    s.create(draft("a"), "".into()).await.unwrap();
}

#[tokio::test]
async fn symlinked_dir_rejected() {
    let t = TempDir::new().unwrap();
    fs::create_dir(t.path().join("real")).unwrap();
    symlink(t.path().join("real"), t.path().join("link")).unwrap();
    assert!(DraftStore::open(t.path().join("link")).is_err());
}

#[tokio::test]
async fn dir_swapped_to_symlink_detected_before_mutation() {
    let (t, s) = store().await;
    let d = t.path().join("drafts");
    fs::rename(&d, t.path().join("moved")).unwrap();
    symlink(t.path().join("moved"), &d).unwrap();
    assert!(s.create(draft("a"), "".into()).await.is_err());
    assert!(s.list(None).await.is_err());
}

#[tokio::test]
async fn loose_dir_mode_rejected() {
    let t = TempDir::new().unwrap();
    let d = t.path().join("d");
    fs::create_dir(&d).unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(DraftStore::open(d.clone()).is_err());
    fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
    let s = DraftStore::open(d.clone()).unwrap();
    fs::set_permissions(&d, fs::Permissions::from_mode(0o770)).unwrap();
    assert!(s.create(draft("a"), "".into()).await.is_err());
}

#[tokio::test]
async fn new_dir_is_0700() {
    let (t, _s) = store().await;
    let m = fs::metadata(t.path().join("drafts")).unwrap();
    assert_eq!(m.mode() & 0o777, 0o700);
}

#[tokio::test]
async fn loose_lock_file_rejected() {
    let (t, s) = store().await;
    s.create(draft("a"), "".into()).await.unwrap();
    let lp = t.path().join("drafts").join(lock::LOCK_NAME);
    fs::set_permissions(&lp, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(s.create(draft("b"), "".into()).await.is_err());
}

#[tokio::test]
async fn symlinked_lock_file_rejected() {
    let (t, s) = store().await;
    let dir = t.path().join("drafts");
    fs::write(t.path().join("elsewhere"), "").unwrap();
    symlink(t.path().join("elsewhere"), dir.join(lock::LOCK_NAME)).unwrap();
    assert!(s.create(draft("a"), "".into()).await.is_err());
}

#[tokio::test]
async fn symlinked_draft_file_rejected_and_ignored() {
    let (t, s) = store().await;
    let dir = t.path().join("drafts");
    s.create(draft("real"), "b".into()).await.unwrap();
    symlink(dir.join("real.md"), dir.join("link.md")).unwrap();
    assert!(s.get("link").await.is_err());
    assert!(s.update("link", None, |_, _| Ok(())).await.is_err());
    let ids: Vec<_> = s
        .list(None)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(ids, vec!["real"]);
}

#[tokio::test]
async fn stale_temp_swept_fresh_kept() {
    let (t, s) = store().await;
    let dir = t.path().join("drafts");
    let old = dir.join(".tmp-old.md.part");
    let fresh = dir.join(".tmp-fresh.md.part");
    fs::write(&old, "x").unwrap();
    fs::write(&fresh, "x").unwrap();
    let past = SystemTime::now() - Duration::from_secs(3600);
    File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(past)
        .unwrap();
    s.create(draft("a"), "".into()).await.unwrap();
    assert!(!old.exists());
    assert!(fresh.exists());
}

#[tokio::test]
async fn oversize_rejected() {
    let (t, s) = store().await;
    let mut d = draft("a");
    d.notes = Some("n".repeat(20_000));
    d.impact = Some("n".repeat(20_000));
    d.references = vec!["r".repeat(2_000); 50];
    let body = "x".repeat(199_000);
    // within each limit individually, but over the file limit in total
    assert!(s.create(d.clone(), body.clone()).await.is_err());
    // oversize file on disk is rejected on read
    fs::write(
        t.path().join("drafts").join("big.md"),
        "x".repeat(MAX_FILE_BYTES + 1),
    )
    .unwrap();
    assert!(s.get("big").await.is_err());
    let rows = s.list(None).await.unwrap();
    assert!(rows.iter().all(|r| r.id != "big" || !r.valid));
}

#[tokio::test]
async fn traversal_ids_rejected_everywhere() {
    let (_t, s) = store().await;
    let long = "a".repeat(65);
    for id in ["../x", "a/b", ".", "..", "", "ABC", "é", long.as_str()] {
        assert!(matches!(s.get(id).await, Err(Error::Validation(_))), "{id}");
        assert!(matches!(
            s.update(id, None, |_, _| Ok(())).await,
            Err(Error::Validation(_))
        ));
        assert!(matches!(
            s.delete(id, None).await,
            Err(Error::Validation(_))
        ));
        let mut d = draft("ok");
        d.id = id.to_string();
        assert!(matches!(
            s.create(d, "".into()).await,
            Err(Error::Validation(_))
        ));
    }
}

#[tokio::test]
async fn list_ignores_junk_sorts_and_limits() {
    let (t, s) = store().await;
    let dir = t.path().join("drafts");
    for id in ["a", "b", "c"] {
        s.create(draft(id), "".into()).await.unwrap();
    }
    s.update("a", None, |_, _| Ok(())).await.unwrap();
    fs::write(dir.join("README.txt"), "x").unwrap();
    fs::write(dir.join("Bad Name.md"), "x").unwrap();
    fs::write(dir.join(".tmp-x.md.part"), "x").unwrap();
    fs::create_dir(dir.join("sub.md")).unwrap();
    fs::write(dir.join("broken.md"), "garbage").unwrap();
    let rows = s.list(None).await.unwrap();
    let mut ids: Vec<_> = rows.iter().map(|r| r.id.as_str()).collect();
    ids.sort();
    assert_eq!(ids, vec!["a", "b", "broken", "c"]);
    assert!(!rows.iter().find(|r| r.id == "broken").unwrap().valid);
    assert_eq!(s.list(Some(2)).await.unwrap().len(), 2);
    assert_eq!(s.list(Some(0)).await.unwrap().len(), 1);
}

#[tokio::test]
async fn mismatching_id_in_file_rejected() {
    let (t, s) = store().await;
    s.create(draft("a"), "".into()).await.unwrap();
    let dir = t.path().join("drafts");
    fs::copy(dir.join("a.md"), dir.join("b.md")).unwrap();
    assert!(s.get("b").await.is_err());
}

#[tokio::test]
async fn fifo_draft_does_not_hang() {
    use std::process::Command;
    use tokio::time::timeout;
    let (t, s) = store().await;
    let fifo = t.path().join("drafts").join("pipe.md");
    match Command::new("mkfifo").arg(&fifo).status() {
        Ok(st) if st.success() => {}
        _ => return, // mkfifo unavailable: skip
    }
    let w = Duration::from_secs(3);
    assert!(timeout(w, s.get("pipe")).await.unwrap().is_err());
    assert!(
        timeout(w, s.update("pipe", None, |_, _| Ok(())))
            .await
            .unwrap()
            .is_err()
    );
    assert!(
        timeout(w, s.delete("pipe", Some(1)))
            .await
            .unwrap()
            .is_err()
    );
    let rows = timeout(w, s.list(None)).await.unwrap().unwrap();
    assert!(rows.iter().all(|r| r.id != "pipe" || !r.valid));
    // lock released: a following create succeeds
    timeout(w, s.create(draft("after"), "".into()))
        .await
        .unwrap()
        .unwrap();
}
