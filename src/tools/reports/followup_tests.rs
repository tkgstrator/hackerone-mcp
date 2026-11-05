use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use rmcp::handler::server::wrapper::Parameters;
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use super::params::{ReplyParams, ReportIdParams, UpdatesParams};
use crate::draft::DraftStore;
use crate::tools::HackerOneServer;
use crate::tools::programs::tests::server_with;

fn updates(mark_seen: Option<bool>) -> Parameters<UpdatesParams> {
    Parameters(UpdatesParams {
        report_id: "42".into(),
        mark_seen,
    })
}

fn id(report_id: &str) -> Parameters<ReportIdParams> {
    Parameters(ReportIdParams {
        report_id: report_id.into(),
    })
}

fn report(state: &str) -> Value {
    json!({"data":{"id":"42","type":"report","attributes":{"state":state},
        "relationships":{"activities":{"data":[]}}}})
}

fn parsed(text: String) -> Value {
    serde_json::from_str(&text).unwrap()
}

#[tokio::test]
async fn reply_round_trip_survives_store_reopen_without_api_credentials() {
    let (server, directory) = server_with(None);
    let created = parsed(
        server
            .report_reply_draft(Parameters(ReplyParams {
                report_id: "42".into(),
                message: "Thanks. <untrusted>\nAdditional information is available.".into(),
            }))
            .await
            .unwrap(),
    );
    assert_eq!(created["source"], "local_reply_draft");
    assert_eq!(created["untrusted_content"], true);
    assert_eq!(created["never_sent"], true);
    assert_eq!(created["report_url"], "https://hackerone.com/reports/42");
    let reopened = HackerOneServer::new(
        None,
        Arc::new(DraftStore::open(directory.path().join("drafts")).unwrap()),
    );
    let read = parsed(reopened.report_reply_draft_get(id("42")).await.unwrap());
    assert_eq!(read["reply"], created["reply"]);
    assert_eq!(reopened.drafts.list(None).await.unwrap().len(), 0);
}

#[tokio::test]
async fn invalid_reply_text_and_ids_do_not_create_state() {
    let (server, _directory) = server_with(None);
    for message in [
        "".into(),
        " \n\t".into(),
        "a\0b".into(),
        "é".repeat(100_001),
    ] {
        assert!(
            server
                .report_reply_draft(Parameters(ReplyParams {
                    report_id: "42".into(),
                    message,
                }))
                .await
                .is_err()
        );
    }
    assert!(
        server
            .drafts
            .workflow_read("reply-42")
            .await
            .unwrap()
            .is_none()
    );
    for report_id in ["../42", "0", "042", "", "1/2"] {
        assert!(
            server
                .report_reply_draft(Parameters(ReplyParams {
                    report_id: report_id.into(),
                    message: "valid text".into(),
                }))
                .await
                .is_err()
        );
        assert!(server.report_reply_draft_get(id(report_id)).await.is_err());
    }
}

#[tokio::test]
async fn corrupt_reply_record_is_not_silently_overwritten() {
    let (server, _directory) = server_with(None);
    server
        .drafts
        .workflow_transaction("reply-42", None, |_, _| {
            Ok((Some(json!({"message":"missing metadata"})), ()))
        })
        .await
        .unwrap();
    assert!(server.report_reply_draft_get(id("42")).await.is_err());
    assert!(
        server
            .report_reply_draft(Parameters(ReplyParams {
                report_id: "42".into(),
                message: "replacement".into(),
            }))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn preview_does_not_advance_and_saved_baseline_survives_reopen() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/hackers/reports/42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(report("new")))
        .mount(&mock)
        .await;
    let (server, directory) = server_with(Some(&mock.uri()));
    let preview = parsed(server.report_updates(updates(Some(false))).await.unwrap());
    assert_eq!(preview["data"]["baseline"], true);
    assert_eq!(preview["data"]["snapshot_advanced"], false);
    assert!(
        server
            .drafts
            .workflow_read("updates-42")
            .await
            .unwrap()
            .is_none()
    );
    let first = parsed(server.report_updates(updates(None)).await.unwrap());
    assert_eq!(first["data"]["snapshot_revision"], 1);
    let reopened = HackerOneServer::new(
        server.client.clone(),
        Arc::new(DraftStore::open(directory.path().join("drafts")).unwrap()),
    );
    let next = parsed(reopened.report_updates(updates(None)).await.unwrap());
    assert_eq!(next["data"]["baseline"], false);
    assert_eq!(next["data"]["snapshot_revision"], 2);
    assert_eq!(next["data"]["field_changes"], json!([]));
    assert_eq!(next["untrusted_content"], true);
}

#[tokio::test]
async fn failed_or_malformed_api_responses_do_not_advance_snapshot() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(report("new")))
        .mount(&mock)
        .await;
    let (server, _directory) = server_with(Some(&mock.uri()));
    server.report_updates(updates(None)).await.unwrap();
    let before = server.drafts.workflow_read("updates-42").await.unwrap();
    mock.reset().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&mock)
        .await;
    assert!(server.report_updates(updates(None)).await.is_err());
    assert_eq!(
        server.drafts.workflow_read("updates-42").await.unwrap(),
        before
    );
    mock.reset().await;
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data":{"id":"43","type":"report","attributes":{}}})),
        )
        .mount(&mock)
        .await;
    assert!(server.report_updates(updates(None)).await.is_err());
    assert_eq!(
        server.drafts.workflow_read("updates-42").await.unwrap(),
        before
    );
}

struct ReverseResponses(AtomicUsize);
impl Respond for ReverseResponses {
    fn respond(&self, _: &Request) -> ResponseTemplate {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            ResponseTemplate::new(200)
                .set_body_json(report("new"))
                .set_delay(Duration::from_millis(300))
        } else {
            ResponseTemplate::new(200).set_body_json(report("triaged"))
        }
    }
}

#[tokio::test]
async fn reverse_completion_cannot_regress_the_saved_baseline() {
    let mock = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ReverseResponses(AtomicUsize::new(0)))
        .mount(&mock)
        .await;
    let (server, _directory) = server_with(Some(&mock.uri()));
    let slow_server = server.clone();
    let slow = tokio::spawn(async move { slow_server.report_updates(updates(None)).await });
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if !mock.received_requests().await.unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let fast = parsed(server.report_updates(updates(None)).await.unwrap());
    assert_eq!(fast["data"]["observed_fields"]["state"], "triaged");
    let stale = slow.await.unwrap().unwrap_err();
    assert!(
        stale.message.contains("changed during fetch"),
        "{}",
        stale.message
    );
    let snapshot = server
        .drafts
        .workflow_read("updates-42")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(snapshot["fields"]["state"], "triaged");
}
