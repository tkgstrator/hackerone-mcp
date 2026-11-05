use super::*;
use crate::{
    client::H1Client,
    config::Credentials,
    draft::{DraftStore, model::Draft},
};
use serde_json::Value;
use std::sync::Arc;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn fixture(mock: &MockServer) -> (tempfile::TempDir, HackerOneServer) {
    let temp = tempfile::tempdir().unwrap();
    let store = Arc::new(DraftStore::open(temp.path().join("d")).unwrap());
    let mut draft = Draft::new("example".into(), "Example report".into());
    draft.team_handle = Some("acme".into());
    draft.impact = Some("Example impact".into());
    store.create(draft, "Example body".into()).await.unwrap();
    let client = H1Client::with_base_url(
        &Credentials {
            username: "test-user".into(),
            api_key: "test-key".into(),
        },
        &mock.uri(),
    )
    .unwrap();
    (
        temp,
        HackerOneServer::new_with_submit(Some(Arc::new(client)), store, true),
    )
}

async fn preview(server: &HackerOneServer) -> Value {
    serde_json::from_str(
        &server
            .report_submit_prepare(Parameters(PrepareParams {
                draft_id: "example".into(),
                expected_revision: 1,
            }))
            .await
            .unwrap(),
    )
    .unwrap()
}

fn args(preview: &Value) -> Parameters<SubmitParams> {
    Parameters(SubmitParams {
        draft_id: "example".into(),
        expected_revision: 1,
        confirmation_token: preview["confirmation_token"].as_str().unwrap().into(),
        confirm: true,
    })
}

async fn accepted(mock: &MockServer, delay: std::time::Duration) {
    Mock::given(method("POST"))
        .and(path("/v1/hackers/reports"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_delay(delay)
                .set_body_json(serde_json::json!({"data":{"type":"report","id":"12345"}})),
        )
        .expect(1)
        .mount(mock)
        .await;
}

#[tokio::test]
async fn concurrent_calls_send_once_and_receipt_survives_draft_deletion_and_restart() {
    let mock = MockServer::start().await;
    accepted(&mock, std::time::Duration::ZERO).await;
    let (temp, server) = fixture(&mock).await;
    let prepared = preview(&server).await;
    let (a, b) = tokio::join!(
        server.report_submit(args(&prepared)),
        server.report_submit(args(&prepared))
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let requests = mock.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].body,
        prepared["request_body_json"].as_str().unwrap().as_bytes()
    );
    server.drafts.delete("example", Some(1)).await.unwrap();
    let reopened = Arc::new(DraftStore::open(temp.path().join("d")).unwrap());
    let restarted = HackerOneServer::new_with_submit(server.client.clone(), reopened.clone(), true);
    let receipt: Value = serde_json::from_str(
        &restarted
            .report_submission_get(Parameters(StatusParams {
                draft_id: "example".into(),
            }))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(receipt["submission"]["state"], "submitted");
    assert_eq!(
        receipt["submission"]["report_url"],
        "https://hackerone.com/reports/12345"
    );
    let mut draft = Draft::new("example".into(), "Another report".into());
    draft.team_handle = Some("acme".into());
    draft.impact = Some("Example impact".into());
    reopened.create(draft, "Another body".into()).await.unwrap();
    assert!(
        restarted
            .report_submit_prepare(Parameters(PrepareParams {
                draft_id: "example".into(),
                expected_revision: 1
            }))
            .await
            .is_err()
    );
    assert!(restarted.report_submit(args(&prepared)).await.is_err());
    assert_eq!(mock.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn failures_consume_attempt_and_are_not_replayed() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500).set_body_string("PRIVATE_BODY test-key"))
        .expect(1)
        .mount(&mock)
        .await;
    let (_temp, server) = fixture(&mock).await;
    let prepared = preview(&server).await;
    let text = server.report_submit(args(&prepared)).await.unwrap();
    assert!(!text.contains("PRIVATE_BODY") && !text.contains("test-key"));
    let receipt: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(receipt["submission"]["state"], "unknown");
    assert_eq!(receipt["submission"]["outcome_uncertain"], true);
    assert!(server.report_submit(args(&prepared)).await.is_err());
    assert!(
        server
            .report_submit_prepare(Parameters(PrepareParams {
                draft_id: "example".into(),
                expected_revision: 1
            }))
            .await
            .is_err()
    );
    assert_eq!(mock.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn interrupted_claim_and_corrupt_ledger_never_send() {
    let mock = MockServer::start().await;
    let (_temp, server) = fixture(&mock).await;
    let prepared = preview(&server).await;
    server
        .drafts
        .workflow_transaction("submit-example", None, |old, _| {
            let mut record = decode(old.unwrap(), "example")?;
            record.state = State::Attempting;
            record.attempted_at = Some(now_secs());
            Ok((Some(encode(&record)?), ()))
        })
        .await
        .unwrap();
    assert!(server.report_submit(args(&prepared)).await.is_err());
    let text = server
        .report_submission_get(Parameters(StatusParams {
            draft_id: "example".into(),
        }))
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["submission"]["outcome_uncertain"],
        true
    );
    server
        .drafts
        .workflow_transaction("submit-example", None, |_, _| {
            Ok((Some(serde_json::json!({"broken":true})), ()))
        })
        .await
        .unwrap();
    assert!(server.report_submit(args(&prepared)).await.is_err());
    assert!(
        server
            .report_submission_get(Parameters(StatusParams {
                draft_id: "example".into()
            }))
            .await
            .is_err()
    );
    assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn superseded_tokens_wrong_account_and_false_confirmation_do_not_claim_or_send() {
    let mock = MockServer::start().await;
    let (_temp, server) = fixture(&mock).await;
    let old = preview(&server).await;
    let current = preview(&server).await;
    assert_ne!(old["confirmation_token"], current["confirmation_token"]);
    assert!(server.report_submit(args(&old)).await.is_err());
    let mut unconfirmed = args(&current);
    unconfirmed.0.confirm = false;
    assert!(server.report_submit(unconfirmed).await.is_err());
    let client = H1Client::with_base_url(
        &Credentials {
            username: "another-user".into(),
            api_key: "another-key".into(),
        },
        &mock.uri(),
    )
    .unwrap();
    let other =
        HackerOneServer::new_with_submit(Some(Arc::new(client)), server.drafts.clone(), true);
    assert!(other.report_submit(args(&current)).await.is_err());
    assert!(mock.received_requests().await.unwrap().is_empty());
    let status = server
        .drafts
        .workflow_read("submit-example")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status["state"], "prepared");
}

#[tokio::test]
async fn cancelling_waiter_still_records_accepted_receipt() {
    let mock = MockServer::start().await;
    accepted(&mock, std::time::Duration::from_millis(150)).await;
    let (_temp, server) = fixture(&mock).await;
    let prepared = preview(&server).await;
    let worker = server.clone();
    let waiting = tokio::spawn(async move { worker.report_submit(args(&prepared)).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while mock.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    waiting.abort();
    let _ = waiting.await;
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let value = server
                .drafts
                .workflow_read("submit-example")
                .await
                .unwrap()
                .unwrap();
            if value["state"] == "submitted" {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(mock.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn accepted_report_id_is_returned_when_receipt_cannot_be_saved() {
    let mock = MockServer::start().await;
    let (temp, server) = fixture(&mock).await;
    let prepared = preview(&server).await;
    let ledger = temp.path().join("d/.workflow-submit-example.json");
    Mock::given(method("POST"))
        .respond_with(move |_: &wiremock::Request| {
            std::fs::write(&ledger, "corrupted storage").unwrap();
            ResponseTemplate::new(201)
                .set_body_json(serde_json::json!({"data":{"type":"report","id":"12345"}}))
        })
        .expect(1)
        .mount(&mock)
        .await;
    let error = server.report_submit(args(&prepared)).await.unwrap_err();
    assert!(
        error
            .message
            .contains("https://hackerone.com/reports/12345")
    );
    assert!(server.report_submit(args(&prepared)).await.is_err());
    assert_eq!(mock.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn consumed_receipt_is_readable_when_current_draft_validation_changes() {
    let mock = MockServer::start().await;
    let (_temp, server) = fixture(&mock).await;
    let prepared = preview(&server).await;
    server
        .drafts
        .workflow_transaction("submit-example", None, |old, _| {
            let mut record = decode(old.unwrap(), "example")?;
            record.state = State::Unknown;
            record.attempted_at = Some(now_secs());
            // Simulate metadata accepted by an earlier validator. A consumed
            // receipt is diagnostic history and must never enable another send.
            record.stored.draft.status = "legacy-status".into();
            Ok((Some(encode(&record)?), ()))
        })
        .await
        .unwrap();
    let text = server
        .report_submission_get(Parameters(StatusParams {
            draft_id: "example".into(),
        }))
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["submission"]["state"],
        "unknown"
    );
    assert!(server.report_submit(args(&prepared)).await.is_err());
    assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn prepare_binds_exact_payload_and_rejects_later_edit() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Arc::new(DraftStore::open(tmp.path().join("d")).unwrap());
    let mut draft = Draft::new("example".into(), "Example report".into());
    draft.team_handle = Some("acme".into());
    draft.impact = Some("Example impact".into());
    draft.notes = Some("private notes".into());
    store.create(draft, "Example body".into()).await.unwrap();
    let client = Arc::new(
        H1Client::new(&Credentials {
            username: "test-user".into(),
            api_key: "test-key".into(),
        })
        .unwrap(),
    );
    let server = HackerOneServer::new_with_submit(Some(client), store.clone(), true);
    let response = server
        .report_submit_prepare(Parameters(PrepareParams {
            draft_id: "example".into(),
            expected_revision: 1,
        }))
        .await
        .unwrap();
    let prepared: Value = serde_json::from_str(&response).unwrap();
    assert_eq!(
        prepared["request_body"]["data"]["attributes"]["vulnerability_information"],
        "Example body"
    );
    assert!(
        prepared["request_body"]["data"]["attributes"]
            .get("notes")
            .is_none()
    );
    assert_eq!(prepared["never_sent"], true);
    let token = prepared["confirmation_token"].as_str().unwrap().to_string();
    let status: Value = serde_json::from_str(
        &server
            .report_submission_get(Parameters(StatusParams {
                draft_id: "example".into(),
            }))
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(status["submission"]["state"], "prepared");
    store
        .update("example", Some(1), |_, body| {
            *body = "Edited".into();
            Ok(())
        })
        .await
        .unwrap();
    assert!(
        server
            .report_submit(Parameters(SubmitParams {
                draft_id: "example".into(),
                expected_revision: 1,
                confirmation_token: token,
                confirm: true
            }))
            .await
            .is_err()
    );
}
