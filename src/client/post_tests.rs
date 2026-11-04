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
