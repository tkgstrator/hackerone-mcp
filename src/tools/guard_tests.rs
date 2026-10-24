//! Guards the exposed tool surface: no tool may submit anything to HackerOne.

use std::collections::BTreeSet;

use tempfile::TempDir;

use super::*;

const EXPECTED: [&str; 12] = [
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
fn tool_set_is_exactly_the_expected_twelve() {
    let (_t, n) = names();
    let got: BTreeSet<&str> = n.iter().map(String::as_str).collect();
    let want: BTreeSet<&str> = EXPECTED.into_iter().collect();
    assert_eq!(n.len(), EXPECTED.len(), "duplicate or extra tools: {n:?}");
    assert_eq!(got, want);
}

#[test]
fn no_tool_name_suggests_submission() {
    let (_t, n) = names();
    let banned = [
        "submit",
        "send",
        "post",
        "publish",
        "upload",
        "report_remote",
    ];
    for name in &n {
        let lower = name.to_lowercase();
        for b in banned {
            assert!(!lower.contains(b), "tool '{name}' matches banned '{b}'");
        }
    }
}
