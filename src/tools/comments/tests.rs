use super::*;
use crate::{client::H1Client, config::Credentials, draft::DraftStore};
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn server_for(
    temp: &tempfile::TempDir,
    mock: &MockServer,
    user: &str,
    allow: bool,
) -> HackerOneServer {
    let store = Arc::new(DraftStore::open(temp.path().join("d")).unwrap());
    let client = H1Client::with_base_url(
        &Credentials {
            username: user.into(),
            api_key: "test-key".into(),
        },
        &mock.uri(),
    )
    .unwrap();
    HackerOneServer::new_with_submit(Some(Arc::new(client)), store, allow)
}

async fn fixture(mock: &MockServer) -> (tempfile::TempDir, HackerOneServer) {
    let temp = tempfile::tempdir().unwrap();
    let server = server_for(&temp, mock, "test-user", true);
    (temp, server)
}

async fn prepare(server: &HackerOneServer, message: &str) -> Value {
    serde_json::from_str(
        &server
            .report_comment_prepare(Parameters(CommentPrepareParams {
                report_id: "12345".into(),
                message: message.into(),
            }))
            .await
            .unwrap(),
    )
    .unwrap()
}

fn args(preview: &Value) -> Parameters<CommentSubmitParams> {
    Parameters(CommentSubmitParams {
        comment_id: preview["comment_id"].as_str().unwrap().into(),
        confirmation_token: preview["confirmation_token"].as_str().unwrap().into(),
        confirm: true,
    })
}

async fn get(server: &HackerOneServer, preview: &Value) -> Value {
    serde_json::from_str(
        &server
            .report_comment_get(Parameters(CommentGetParams {
                comment_id: preview["comment_id"].as_str().unwrap().into(),
            }))
            .await
            .unwrap(),
    )
    .unwrap()
}

async fn accepted(mock: &MockServer, delay: Duration) {
    Mock::given(method("POST"))
        .and(path("/v1/reports/12345/activities"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_delay(delay)
                .set_body_json(json!({"data":{"type":"activity-comment","id":"987"}})),
        )
        .expect(1)
        .mount(mock)
        .await;
}

#[tokio::test]
async fn prepare_validates_inputs_and_never_touches_network() {
    let mock = MockServer::start().await;
    let (_t, server) = fixture(&mock).await;
    let too_long = "x".repeat(200_001);
    for (id, message) in [
        ("0", "ok"),
        ("1/2", "ok"),
        ("12345", ""),
        ("12345", " \n\t"),
        ("12345", "a\0b"),
        ("12345", too_long.as_str()),
    ] {
        let result = server
            .report_comment_prepare(Parameters(CommentPrepareParams {
                report_id: id.into(),
                message: message.into(),
            }))
            .await;
        assert!(result.is_err(), "{id} {}", message.len());
    }
    assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn prepare_previews_exact_public_request_without_sending() {
    let mock = MockServer::start().await;
    let (_t, server) = fixture(&mock).await;
    let p = prepare(&server, "  Hello\nworld  ").await;
    assert_eq!(p["never_sent"], true);
    assert_eq!(p["method"], "POST");
    assert_eq!(
        p["endpoint"],
        "https://api.hackerone.com/v1/reports/12345/activities"
    );
    assert_eq!(p["account"], "test-user");
    assert_eq!(p["request_body"]["data"]["type"], "activity-comment");
    assert_eq!(p["request_body"]["data"]["attributes"]["internal"], false);
    assert_eq!(
        p["request_body"]["data"]["attributes"]["message"],
        "  Hello\nworld  "
    );
    assert!(p["guidance"].as_str().unwrap().contains("Customer API"));
    assert_eq!(get(&server, &p).await["comment"]["state"], "prepared");
    assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn submit_sends_exact_bytes_once_and_receipt_survives_restart() {
    let mock = MockServer::start().await;
    accepted(&mock, Duration::ZERO).await;
    let (temp, server) = fixture(&mock).await;
    let p = prepare(&server, "Public note").await;
    let (a, b) = tokio::join!(
        server.report_comment_submit(args(&p)),
        server.report_comment_submit(args(&p))
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let requests = mock.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].body,
        p["request_body_json"].as_str().unwrap().as_bytes()
    );
    let restarted = server_for(&temp, &mock, "test-user", true);
    let receipt = get(&restarted, &p).await;
    assert_eq!(receipt["comment"]["state"], "submitted");
    assert_eq!(receipt["comment"]["activity_id"], "987");
    assert!(restarted.report_comment_submit(args(&p)).await.is_err());
    assert_eq!(mock.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn disabled_unconfirmed_wrong_token_and_wrong_account_never_send() {
    let mock = MockServer::start().await;
    let (temp, server) = fixture(&mock).await;
    let p = prepare(&server, "Public note").await;
    let disabled = server_for(&temp, &mock, "test-user", false);
    assert!(disabled.report_comment_submit(args(&p)).await.is_err());
    let mut unconfirmed = args(&p);
    unconfirmed.0.confirm = false;
    assert!(server.report_comment_submit(unconfirmed).await.is_err());
    let mut wrong = args(&p);
    wrong.0.confirmation_token = "0".repeat(48);
    assert!(server.report_comment_submit(wrong).await.is_err());
    let other = server_for(&temp, &mock, "other-user", true);
    assert!(other.report_comment_submit(args(&p)).await.is_err());
    let mut bad_id = args(&p);
    bad_id.0.comment_id = "../x".into();
    assert!(server.report_comment_submit(bad_id).await.is_err());
    assert_eq!(get(&server, &p).await["comment"]["state"], "prepared");
    assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn failure_consumes_attempt_without_leaks_or_replay() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_string("PRIVATE_BODY test-key"))
        .expect(1)
        .mount(&mock)
        .await;
    let (_t, server) = fixture(&mock).await;
    let p = prepare(&server, "Public note").await;
    let text = server.report_comment_submit(args(&p)).await.unwrap();
    assert!(!text.contains("PRIVATE_BODY") && !text.contains("test-key"));
    let receipt: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(receipt["comment"]["state"], "unknown");
    assert_eq!(receipt["comment"]["outcome_uncertain"], true);
    assert!(
        receipt["comment"]["failure"]
            .as_str()
            .unwrap()
            .contains("permission")
    );
    assert!(server.report_comment_submit(args(&p)).await.is_err());
    assert_eq!(mock.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn interrupted_claim_and_corrupt_ledger_never_send() {
    let mock = MockServer::start().await;
    let (_t, server) = fixture(&mock).await;
    let p = prepare(&server, "Public note").await;
    let key = p["comment_id"].as_str().unwrap().to_owned();
    let id = p["comment_id"].as_str().unwrap().to_owned();
    server
        .drafts
        .workflow_transaction(&key, None, move |old, _| {
            let mut record = decode(old.unwrap(), &id)?;
            record.state = State::Attempting;
            record.attempted_at = Some(now_secs());
            Ok((Some(encode(&record)?), ()))
        })
        .await
        .unwrap();
    assert!(server.report_comment_submit(args(&p)).await.is_err());
    assert_eq!(get(&server, &p).await["comment"]["outcome_uncertain"], true);
    server
        .drafts
        .workflow_transaction(&key, None, |_, _| Ok((Some(json!({"broken":true})), ())))
        .await
        .unwrap();
    assert!(server.report_comment_submit(args(&p)).await.is_err());
    assert!(
        server
            .report_comment_get(Parameters(CommentGetParams {
                comment_id: p["comment_id"].as_str().unwrap().into()
            }))
            .await
            .is_err()
    );
    assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn cancelling_waiter_still_records_receipt() {
    let mock = MockServer::start().await;
    accepted(&mock, Duration::from_millis(150)).await;
    let (_t, server) = fixture(&mock).await;
    let p = prepare(&server, "Public note").await;
    let worker = server.clone();
    let call = args(&p);
    let waiting = tokio::spawn(async move { worker.report_comment_submit(call).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while mock.received_requests().await.unwrap().is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    waiting.abort();
    let _ = waiting.await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while get(&server, &p).await["comment"]["state"] != "submitted" {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(mock.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn accepted_activity_id_is_returned_when_receipt_cannot_be_saved() {
    let mock = MockServer::start().await;
    let (temp, server) = fixture(&mock).await;
    let p = prepare(&server, "Public note").await;
    let ledger = temp.path().join(format!(
        "d/.workflow-{}.json",
        p["comment_id"].as_str().unwrap()
    ));
    Mock::given(method("POST"))
        .respond_with(move |_: &wiremock::Request| {
            std::fs::write(&ledger, "corrupted storage").unwrap();
            ResponseTemplate::new(201)
                .set_body_json(json!({"data":{"type":"activity-comment","id":"987"}}))
        })
        .expect(1)
        .mount(&mock)
        .await;
    let error = server.report_comment_submit(args(&p)).await.unwrap_err();
    assert!(error.message.contains("987"), "{}", error.message);
    assert!(server.report_comment_submit(args(&p)).await.is_err());
    assert_eq!(mock.received_requests().await.unwrap().len(), 1);
}
