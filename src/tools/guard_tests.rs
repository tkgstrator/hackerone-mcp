//! Pins the tool surface and the explicitly enabled submission boundary.

use std::collections::BTreeSet;

use tempfile::TempDir;

use super::*;

const EXPECTED: [&str; 24] = [
    "hacktivity_search",
    "hacker_activity",
    "hacktivity_trends",
    "report_list",
    "report_get",
    "report_updates",
    "report_reply_draft",
    "report_reply_draft_get",
    "report_submit_prepare",
    "report_submit",
    "report_submission_get",
    "program_discover",
    "program_list",
    "program_get",
    "program_scope",
    "program_scope_exclusions",
    "program_weaknesses",
    "program_submission_options",
    "draft_create",
    "draft_get",
    "draft_update",
    "draft_list",
    "draft_delete",
    "draft_validate",
];

fn names() -> (TempDir, Vec<String>) {
    let t = TempDir::new().unwrap();
    let store = Arc::new(DraftStore::open(t.path().join("d")).unwrap());
    let s = HackerOneServer::new(None, store);
    let n = s
        .tool_router
        .list_all()
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    (t, n)
}

#[test]
fn tool_set_is_exactly_the_expected_twenty_four() {
    let (_t, n) = names();
    let got: BTreeSet<&str> = n.iter().map(String::as_str).collect();
    let want: BTreeSet<&str> = EXPECTED.into_iter().collect();
    assert_eq!(n.len(), EXPECTED.len(), "duplicate or extra tools: {n:?}");
    assert_eq!(got, want);
}

#[test]
fn submission_defaults_disabled_and_has_side_effect_annotations() {
    let t = TempDir::new().unwrap();
    let store = Arc::new(DraftStore::open(t.path().join("d")).unwrap());
    let server = HackerOneServer::new(None, store);
    assert!(!server.allow_submit);
    let tool = server
        .tool_router
        .list_all()
        .into_iter()
        .find(|t| t.name == "report_submit")
        .unwrap();
    let annotations = tool.annotations.unwrap();
    assert_eq!(annotations.read_only_hint, Some(false));
    assert_eq!(annotations.destructive_hint, Some(true));
    assert_eq!(annotations.idempotent_hint, Some(false));
    assert_eq!(annotations.open_world_hint, Some(true));
}

#[test]
fn public_insights_are_read_only() {
    let t = TempDir::new().unwrap();
    let store = Arc::new(DraftStore::open(t.path().join("d")).unwrap());
    let server = HackerOneServer::new(None, store);
    for name in ["hacktivity_search", "hacker_activity", "hacktivity_trends"] {
        let tool = server
            .tool_router
            .list_all()
            .into_iter()
            .find(|tool| tool.name == name)
            .unwrap();
        let annotations = tool.annotations.unwrap();
        assert_eq!(annotations.read_only_hint, Some(true));
        assert_eq!(annotations.destructive_hint, Some(false));
        assert_eq!(annotations.open_world_hint, Some(true));
    }
}

#[test]
fn http_building_stays_in_the_client_module() {
    fn visit(dir: &std::path::Path) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path.file_name().unwrap() != "client" {
                    visit(&path);
                }
            } else if path.extension().is_some_and(|e| e == "rs") {
                let source = std::fs::read_to_string(&path).unwrap();
                for needle in [["req", "west::"].concat(), [".po", "st("].concat()] {
                    assert!(
                        !source.contains(&needle),
                        "HTTP outside client: {}",
                        path.display()
                    );
                }
            }
        }
    }
    visit(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .as_path(),
    );
}
