use super::*;
use serde_json::json;
use wiremock::matchers::{basic_auth, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const BODY: &str =
    "{ \"data\": {\"type\":\"report\",\"attributes\":{\"title\":\"Private draft text\"}} }";

fn client(server: &MockServer) -> H1Client {
    H1Client::with_base_url(
        &Credentials {
            username: "test_user".into(),
            api_key: "test_key".into(),
        },
        &server.uri(),
    )
    .unwrap()
}

fn accepted() -> Value {
    json!({"data":{"type":"report","id":"12345"}})
}

#[tokio::test]
async fn post_sends_exact_approved_bytes_with_json_and_account_auth() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/hackers/reports"))
        .and(header("accept", "application/json"))
        .and(header("content-type", "application/json"))
        .and(basic_auth("test_user", "test_key"))
        .respond_with(ResponseTemplate::new(201).set_body_json(accepted()))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server);
    assert_eq!(c.account_username(), "test_user");
    assert_eq!(c.submit_report(BODY.into()).await.unwrap(), accepted());
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, BODY.as_bytes());
    assert!(requests[0].url.query().is_none());
}

#[tokio::test]
async fn post_never_retries_status_errors_or_echoes_confidential_content() {
    for status in [400, 401, 403, 408, 422, 429, 500, 503] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_string("Private draft text test_user test_key echo from API")
                    .insert_header("retry-after", "0"),
            )
            .mount(&server)
            .await;
        let error = client(&server)
            .submit_report(BODY.into())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(&status.to_string()), "{error}");
        assert!(
            error.contains("outcome uncertain") && error.contains("inspect HackerOne"),
            "{error}"
        );
        for confidential in [
            "Private draft text",
            "test_user",
            "test_key",
            "echo from API",
        ] {
            assert!(!error.contains(confidential), "{error}");
        }
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "status {status}"
        );
    }
}

#[tokio::test]
async fn post_redirect_is_not_followed_or_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", "/another-report"))
        .mount(&server)
        .await;
    let error = client(&server)
        .submit_report(BODY.into())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("307"), "{error}");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn post_malformed_or_wrong_report_success_is_uncertain_without_body_leak() {
    for response in [
        "Private draft text".to_string(),
        json!({"data":{"type":"report","id":"0123"}}).to_string(),
        json!({"data":{"type":"report","id":123}}).to_string(),
        json!({"data":{"type":"program","id":"123"}}).to_string(),
        json!({"data":{"type":"report","id":"1/evil"}}).to_string(),
        json!({"data":{"type":"report","id":"123456789012345678901"}}).to_string(),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(201).set_body_string(response))
            .mount(&server)
            .await;
        let error = client(&server)
            .submit_report(BODY.into())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("outcome uncertain"), "{error}");
        assert!(!error.contains("Private draft text"), "{error}");
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn post_oversized_success_is_bounded_uncertain_and_never_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201).set_body_string("Private draft text".repeat(20)))
        .mount(&server)
        .await;
    let mut c = client(&server);
    c.limits.response_bytes = 64;
    let error = c.submit_report(BODY.into()).await.unwrap_err().to_string();
    assert!(error.contains("outcome uncertain"), "{error}");
    assert!(!error.contains("Private draft text"), "{error}");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn post_timeout_is_one_attempt_and_uncertain() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_json(accepted())
                .set_delay(Duration::from_secs(3)),
        )
        .mount(&server)
        .await;
    let mut c = client(&server);
    c.retry.request_timeout = Duration::from_millis(500);
    let error = c.submit_report(BODY.into()).await.unwrap_err().to_string();
    assert!(error.contains("outcome uncertain"), "{error}");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

const BEARER: &str = "Bearer dGVzdF91c2VyOnRlc3Rfa2V5";
const MESSAGE: &str = "Private note";

fn comment_body() -> String {
    json!({"operationName":graphql::OPERATION,
        "query":graphql::MUTATION,
        "variables":{"reportId":"Z2lkOi8vaGFja2Vyb25lL1JlcG9ydC8xMjM0NQ==","message":MESSAGE,"internal":false}})
    .to_string()
}

fn gql_receipt(message: &str, internal: bool, id: Value) -> Value {
    json!({"data":{"createActivityComment":{"was_successful":true,"errors":{"edges":[]},
        "activity":{"__typename":"ActivitiesComment","id":"Z2lkOi8vaGFja2Vyb25lL0FjdGl2aXRpZXM6OkNvbW1lbnQvOTg3","databaseId":id,
            "message":message,"internal":internal}}}})
}

fn gql_accepted() -> Value {
    gql_receipt(MESSAGE, false, json!("987"))
}

#[tokio::test]
async fn comment_post_uses_graphql_bearer_with_exact_bytes() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .and(header("content-type", "application/json"))
        .and(header("authorization", BEARER))
        .respond_with(ResponseTemplate::new(200).set_body_json(gql_accepted()))
        .expect(1)
        .mount(&server)
        .await;
    let value = client(&server)
        .post_report_comment("12345", comment_body())
        .await
        .unwrap();
    // The accepted receipt is normalized for the existing workflow.
    assert_eq!(value["data"]["type"], "activity-comment");
    assert_eq!(value["data"]["id"], "987");
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].body, comment_body().as_bytes());
    assert!(requests[0].url.query().is_none());
    assert!(!requests[0].headers.contains_key("cookie"));
}

#[tokio::test]
async fn comment_invalid_report_id_fails_before_network() {
    let server = MockServer::start().await;
    for id in ["", "0", "01", "1/../2", "1?x=1", "123456789012345678901"] {
        assert!(
            client(&server)
                .post_report_comment(id, comment_body())
                .await
                .is_err(),
            "{id}"
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn comment_rejects_unfixed_query_before_network() {
    let server = MockServer::start().await;
    let mut request: Value = serde_json::from_str(&comment_body()).unwrap();
    request["query"] =
        json!("mutation AddCommentToHackerOneReport { createActivityComment { was_successful } }");
    assert!(
        client(&server)
            .post_report_comment("12345", request.to_string())
            .await
            .is_err()
    );
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn comment_errors_never_retry_or_leak_bodies_or_credentials() {
    for status in [401, 403, 429, 500] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(
                ResponseTemplate::new(status)
                    .set_body_string("Private note test_key dGVzdF91c2VyOnRlc3Rfa2V5 echo"),
            )
            .mount(&server)
            .await;
        let error = client(&server)
            .post_report_comment("12345", comment_body())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains(&status.to_string()) && error.contains("outcome uncertain"));
        for secret in [
            "Private note",
            "test_key",
            "dGVzdF91c2VyOnRlc3Rfa2V5",
            "echo",
        ] {
            assert!(!error.contains(secret), "{error}");
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn comment_redirect_is_not_followed_or_retried() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/graphql"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", "/elsewhere"))
        .mount(&server)
        .await;
    let error = client(&server)
        .post_report_comment("12345", comment_body())
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("307") && error.contains("outcome uncertain"),
        "{error}"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn comment_http_200_graphql_failures_are_uncertain_single_attempts() {
    let mut unsuccessful = gql_accepted();
    unsuccessful["data"]["createActivityComment"]["was_successful"] = json!(false);
    let mut mutation_errors = gql_accepted();
    mutation_errors["data"]["createActivityComment"]["errors"] = json!({"edges":[
        {"node":{"field":"message","message":"Private note rejected test_key"}}]});
    let mut no_activity = gql_accepted();
    no_activity["data"]["createActivityComment"]["activity"] = Value::Null;
    let mut missing_errors = gql_accepted();
    missing_errors["data"]["createActivityComment"]
        .as_object_mut()
        .unwrap()
        .remove("errors");
    let mut null_errors = gql_accepted();
    null_errors["data"]["createActivityComment"]["errors"] = Value::Null;
    let mut null_edges = gql_accepted();
    null_edges["data"]["createActivityComment"]["errors"] = json!({"edges":null});
    for response in [
        json!({"errors":[{"message":"Private note test_key not authorized"}],"data":null}),
        json!({"errors":[{"message":"partial"}],"data":gql_accepted()["data"]}),
        unsuccessful,
        mutation_errors,
        missing_errors,
        null_errors,
        null_edges,
        no_activity,
        json!({"data":{"createActivityComment":null}}),
        json!({"data":null}),
        json!({}),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;
        let error = client(&server)
            .post_report_comment("12345", comment_body())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("outcome uncertain"), "{error}");
        for secret in ["Private note", "test_key", "not authorized", "rejected"] {
            assert!(!error.contains(secret), "{error}");
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn comment_success_requires_matching_activity_comment_receipt() {
    let mut wrong_kind = gql_accepted();
    wrong_kind["data"]["createActivityComment"]["activity"] =
        json!({"__typename":"ActivitiesBugClosed","id":"not-a-valid-id"});
    let mut no_internal = gql_accepted();
    no_internal["data"]["createActivityComment"]["activity"]
        .as_object_mut()
        .unwrap()
        .remove("internal");
    for response in [
        wrong_kind,
        no_internal,
        gql_receipt("Different message", false, json!("987")),
        gql_receipt(MESSAGE, true, json!("987")),
        gql_receipt(MESSAGE, false, json!("0987")),
        gql_receipt(MESSAGE, false, json!("0")),
        gql_receipt(MESSAGE, false, json!(987)),
        gql_receipt(MESSAGE, false, json!("98x")),
        gql_receipt(MESSAGE, false, json!("123456789012345678901")),
        gql_receipt(MESSAGE, false, Value::Null),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(response))
            .mount(&server)
            .await;
        let error = client(&server)
            .post_report_comment("12345", comment_body())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("outcome uncertain"), "{error}");
        assert!(!error.contains("Different message"), "{error}");
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn comment_malformed_oversized_and_timeout_are_single_uncertain_attempts() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("Private note not json"))
        .mount(&server)
        .await;
    let error = client(&server)
        .post_report_comment("12345", comment_body())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("outcome uncertain") && !error.contains("Private note"));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(gql_accepted()))
        .mount(&server)
        .await;
    let mut c = client(&server);
    c.limits.response_bytes = 32;
    let error = c
        .post_report_comment("12345", comment_body())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("outcome uncertain"), "{error}");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(gql_accepted())
                .set_delay(Duration::from_secs(3)),
        )
        .mount(&server)
        .await;
    let mut c = client(&server);
    c.retry.request_timeout = Duration::from_millis(500);
    let error = c
        .post_report_comment("12345", comment_body())
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("outcome uncertain"), "{error}");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
