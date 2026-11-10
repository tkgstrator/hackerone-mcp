use super::*;
use crate::{client::H1Client, config::Credentials, draft::DraftStore};
use std::sync::Arc;
use std::time::Duration;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const BEARER: &str = "Bearer dGVzdC11c2VyOnRlc3Qta2V5";

fn gql_ok(message: &str) -> Value {
    json!({"data":{"createActivityComment":{"was_successful":true,"errors":{"edges":[]},
        "activity":{"__typename":"ActivitiesComment","id":"Z2lkOi8vaGFja2Vyb25lL0FjdGl2aXRpZXM6OkNvbW1lbnQvOTg3","databaseId":"987",
            "message":message,"internal":false}}}})
}

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
        .and(path("/graphql"))
        .and(header("authorization", BEARER))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(delay)
                .set_body_json(gql_ok("Public note")),
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
    assert_eq!(p["endpoint"], "https://hackerone.com/graphql");
    assert_eq!(p["account"], "test-user");
    let body = &p["request_body"];
    assert_eq!(body["operationName"], "AddCommentToHackerOneReport");
    assert!(
        body["query"]
            .as_str()
            .unwrap()
            .contains("createActivityComment")
    );
    assert_eq!(
        body["variables"]["reportId"],
        "Z2lkOi8vaGFja2Vyb25lL1JlcG9ydC8xMjM0NQ=="
    );
    assert_eq!(body["variables"]["message"], "  Hello\nworld  ");
    assert_eq!(body["variables"]["internal"], false);
    assert!(body.get("data").is_none());
    assert_eq!(
        serde_json::from_str::<Value>(p["request_body_json"].as_str().unwrap()).unwrap(),
        *body
    );
    let guidance = p["guidance"].as_str().unwrap();
    assert!(guidance.contains("GraphQL") && !guidance.contains("Customer API"));
    assert_eq!(get(&server, &p).await["comment"]["state"], "prepared");
    let stored = server
        .drafts
        .workflow_read(p["comment_id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored["schema_version"], 2);
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
    assert_eq!(receipt["comment"]["visibility_confirmed"], true);
    assert!(restarted.report_comment_submit(args(&p)).await.is_err());
    assert_eq!(mock.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn explicit_null_visibility_submits_once_and_survives_restart_as_unconfirmed() {
    let mock = MockServer::start().await;
    let mut response = gql_ok("Public note");
    response["data"]["createActivityComment"]["activity"]["internal"] = Value::Null;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(header("authorization", BEARER))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .expect(1)
        .mount(&mock)
        .await;
    let (temp, server) = fixture(&mock).await;
    let p = prepare(&server, "Public note").await;
    let receipt: Value =
        serde_json::from_str(&server.report_comment_submit(args(&p)).await.unwrap()).unwrap();
    assert_eq!(receipt["comment"]["state"], "submitted");
    assert_eq!(receipt["comment"]["activity_id"], "987");
    assert_eq!(receipt["comment"]["visibility_confirmed"], false);
    assert_eq!(receipt["comment"]["public"], true);
    assert_eq!(receipt["comment"]["outcome_uncertain"], false);
    let stored = server
        .drafts
        .workflow_read(p["comment_id"].as_str().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored["activity_id"], "987");
    assert_eq!(stored["visibility_confirmed"], false);
    drop(server);
    let restarted = server_for(&temp, &mock, "test-user", true);
    assert_eq!(get(&restarted, &p).await, receipt);
    assert!(restarted.report_comment_submit(args(&p)).await.is_err());
    let requests = mock.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let request: Value = serde_json::from_slice(&requests[0].body).unwrap();
    assert_eq!(request["variables"]["internal"], false);
}

#[tokio::test]
async fn invalid_visibility_consumes_attempt_and_remains_unknown_after_restart() {
    for internal in [
        None,
        Some(json!(true)),
        Some(json!("false")),
        Some(json!(0)),
    ] {
        let mock = MockServer::start().await;
        let mut response = gql_ok("Public note");
        let activity = response["data"]["createActivityComment"]["activity"]
            .as_object_mut()
            .unwrap();
        match internal {
            Some(value) => {
                activity.insert("internal".into(), value);
            }
            None => {
                activity.remove("internal");
            }
        }
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .expect(1)
            .mount(&mock)
            .await;
        let (temp, server) = fixture(&mock).await;
        let p = prepare(&server, "Public note").await;
        let receipt: Value =
            serde_json::from_str(&server.report_comment_submit(args(&p)).await.unwrap()).unwrap();
        assert_eq!(receipt["comment"]["state"], "unknown");
        assert!(receipt["comment"]["activity_id"].is_null());
        assert!(receipt["comment"]["visibility_confirmed"].is_null());
        assert_eq!(receipt["comment"]["outcome_uncertain"], true);
        drop(server);
        let restarted = server_for(&temp, &mock, "test-user", true);
        assert_eq!(get(&restarted, &p).await, receipt);
        assert!(restarted.report_comment_submit(args(&p)).await.is_err());
        assert_eq!(mock.received_requests().await.unwrap().len(), 1);
    }
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
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(403)
                .set_body_string("PRIVATE_BODY test-key dGVzdC11c2VyOnRlc3Qta2V5"),
        )
        .expect(1)
        .mount(&mock)
        .await;
    let (_t, server) = fixture(&mock).await;
    let p = prepare(&server, "Public note").await;
    let text = server.report_comment_submit(args(&p)).await.unwrap();
    assert!(!text.contains("PRIVATE_BODY") && !text.contains("test-key"));
    assert!(!text.contains("dGVzdC11c2VyOnRlc3Qta2V5"));
    let receipt: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(receipt["comment"]["state"], "unknown");
    assert_eq!(receipt["comment"]["outcome_uncertain"], true);
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
            ResponseTemplate::new(200).set_body_json(gql_ok("Public note"))
        })
        .expect(1)
        .mount(&mock)
        .await;
    let error = server.report_comment_submit(args(&p)).await.unwrap_err();
    assert!(error.message.contains("987"), "{}", error.message);
    assert!(server.report_comment_submit(args(&p)).await.is_err());
    assert_eq!(mock.received_requests().await.unwrap().len(), 1);
}

fn legacy_record(id: &str, state: &str, activity: Option<&str>) -> Value {
    let message = "Old public note";
    let body = serde_json::to_string(&json!({"data":{"type":"activity-comment",
        "attributes":{"message":message,"internal":false}}}))
    .unwrap();
    json!({"schema_version":1,"comment_id":id,"account":"test-user","state":state,
        "report_id":"12345","message":message,"request_body":body,
        "confirmation_token":"a".repeat(64),"prepared_at":1_700_000_000u64,
        "attempted_at":if state=="prepared" {Value::Null} else {json!(1_700_000_001u64)},
        "activity_id":activity,"failure":Value::Null})
}

async fn store_legacy(server: &HackerOneServer, state: &str, activity: Option<&str>) -> Value {
    let id = format!("comment-{}", "b".repeat(24));
    let value = legacy_record(&id, state, activity);
    let stored = value.clone();
    server
        .drafts
        .workflow_transaction(&id, None, move |_, _| Ok((Some(stored), ())))
        .await
        .unwrap();
    json!({"comment_id":id,"confirmation_token":"a".repeat(64)})
}

#[tokio::test]
async fn schema1_rest_receipts_remain_readable_and_immutable() {
    let mock = MockServer::start().await;
    let (_t, server) = fixture(&mock).await;
    let p = store_legacy(&server, "submitted", Some("987")).await;
    let receipt = get(&server, &p).await;
    assert_eq!(receipt["comment"]["state"], "submitted");
    assert_eq!(receipt["comment"]["activity_id"], "987");
    assert!(
        receipt["comment"]
            .get("visibility_confirmed")
            .unwrap()
            .is_null()
    );
    assert!(server.report_comment_submit(args(&p)).await.is_err());
    let unknown = store_legacy(&server, "unknown", None).await;
    assert_eq!(
        get(&server, &unknown).await["comment"]["outcome_uncertain"],
        true
    );
    assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn schema2_receipt_without_visibility_field_remains_readable_and_consumed() {
    let mock = MockServer::start().await;
    let (temp, server) = fixture(&mock).await;
    let p = prepare(&server, "Public note").await;
    let id = p["comment_id"].as_str().unwrap().to_owned();
    server
        .drafts
        .workflow_transaction(&id, None, |old, _| {
            let mut record = old.unwrap();
            record["state"] = json!("submitted");
            record["attempted_at"] = json!(1_700_000_001u64);
            record["activity_id"] = json!("987");
            record
                .as_object_mut()
                .unwrap()
                .remove("visibility_confirmed");
            Ok((Some(record), ()))
        })
        .await
        .unwrap();
    drop(server);
    let restarted = server_for(&temp, &mock, "test-user", true);
    let receipt = get(&restarted, &p).await;
    assert_eq!(receipt["comment"]["state"], "submitted");
    assert_eq!(receipt["comment"]["activity_id"], "987");
    assert!(
        receipt["comment"]
            .get("visibility_confirmed")
            .unwrap()
            .is_null()
    );
    assert!(restarted.report_comment_submit(args(&p)).await.is_err());
    let stored = restarted.drafts.workflow_read(&id).await.unwrap().unwrap();
    assert!(
        !stored
            .as_object()
            .unwrap()
            .contains_key("visibility_confirmed")
    );
    assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn schema1_prepared_preview_is_rejected_without_send_or_state_change() {
    let mock = MockServer::start().await;
    let (_t, server) = fixture(&mock).await;
    let p = store_legacy(&server, "prepared", None).await;
    let error = server.report_comment_submit(args(&p)).await.unwrap_err();
    assert!(error.message.contains("prepare a new"), "{}", error.message);
    assert_eq!(get(&server, &p).await["comment"]["state"], "prepared");
    assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn http_200_graphql_errors_record_unknown_once_without_leaks() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"errors":[{"message":"PRIVATE_GQL test-key"}],"data":null})),
        )
        .expect(1)
        .mount(&mock)
        .await;
    let (_t, server) = fixture(&mock).await;
    let p = prepare(&server, "Public note").await;
    let text = server.report_comment_submit(args(&p)).await.unwrap();
    assert!(!text.contains("PRIVATE_GQL") && !text.contains("test-key"));
    let receipt: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(receipt["comment"]["state"], "unknown");
    assert_eq!(receipt["comment"]["outcome_uncertain"], true);
    assert!(receipt["comment"]["activity_id"].is_null());
    assert!(server.report_comment_submit(args(&p)).await.is_err());
    assert_eq!(mock.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn mismatched_graphql_receipt_is_unknown_not_submitted() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(200).set_body_json(gql_ok("Other text")))
        .expect(1)
        .mount(&mock)
        .await;
    let (_t, server) = fixture(&mock).await;
    let p = prepare(&server, "Public note").await;
    let receipt: Value =
        serde_json::from_str(&server.report_comment_submit(args(&p)).await.unwrap()).unwrap();
    assert_eq!(receipt["comment"]["state"], "unknown");
    assert!(receipt["comment"]["activity_id"].is_null());
    assert_eq!(mock.received_requests().await.unwrap().len(), 1);
}
