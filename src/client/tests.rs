use serde_json::json;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

const USER: &str = "alice_user";
const KEY: &str = "s3cr3t-key-XYZ";

fn creds() -> Credentials {
    Credentials {
        username: USER.into(),
        api_key: KEY.into(),
    }
}

fn client(server: &MockServer) -> H1Client {
    H1Client::with_base_url(&creds(), &server.uri()).unwrap()
}

async fn assert_all_get_v1(server: &MockServer) {
    let reqs = server.received_requests().await.unwrap();
    assert!(!reqs.is_empty());
    for r in reqs {
        assert_eq!(r.method.as_str(), "GET");
        assert!(r.url.path().starts_with("/v1/hackers/"), "{}", r.url.path());
    }
}

#[tokio::test]
async fn sends_basic_auth_accept_and_user_agent() {
    // base64("alice_user:s3cr3t-key-XYZ")
    let expected = "Basic YWxpY2VfdXNlcjpzM2NyM3Qta2V5LVhZWg==";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/hackers/programs/acme"))
        .and(header("authorization", expected))
        .and(header("accept", "application/json"))
        .and(header(
            "user-agent",
            concat!("hackerone-mcp/", env!("CARGO_PKG_VERSION")),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": {"id": 1}})))
        .expect(1)
        .mount(&server)
        .await;
    let v = client(&server).program("acme").await.unwrap();
    assert_eq!(v["data"]["id"], 1);
}

#[tokio::test]
async fn every_endpoint_is_get_under_v1_hackers() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(&server)
        .await;
    let c = client(&server);
    let p = PageParams::default();
    c.programs(p).await.unwrap();
    c.program("acme").await.unwrap();
    c.structured_scopes("acme", p, &ScopeFilters::default())
        .await
        .unwrap();
    c.weaknesses("acme", p).await.unwrap();
    c.scope_exclusions("acme").await.unwrap();
    c.structured_scopes_all("acme").await.unwrap();
    c.weaknesses_all("acme").await.unwrap();
    assert_all_get_v1(&server).await;
    let paths: Vec<String> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.url.path().to_string())
        .collect();
    for want in [
        "/v1/hackers/programs",
        "/v1/hackers/programs/acme",
        "/v1/hackers/programs/acme/structured_scopes",
        "/v1/hackers/programs/acme/weaknesses",
        "/v1/hackers/programs/acme/scope_exclusions",
    ] {
        assert!(paths.iter().any(|p| p == want), "missing {want}");
    }
}

#[tokio::test]
async fn redirect_is_not_followed() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/hackers/programs/acme"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/evil"))
        .mount(&server)
        .await;
    let err = client(&server).program("acme").await.unwrap_err();
    assert!(err.to_string().contains("302"), "{err}");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn hostile_handles_rejected_without_request() {
    let server = MockServer::start().await;
    let c = client(&server);
    let long = "a".repeat(65);
    for h in [
        "a/b",
        "a?b",
        "a#b",
        "%2e%2e",
        "..",
        "",
        long.as_str(),
        "a b",
        "a\\b",
    ] {
        assert!(
            matches!(c.program(h).await, Err(Error::Validation(_))),
            "handle {h:?}"
        );
        assert!(c.scope_exclusions(h).await.is_err());
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn page_bounds_validated_and_serialized() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/hackers/programs"))
        .and(query_param("page[number]", "2"))
        .and(query_param("page[size]", "100"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server);
    for (number, size) in [
        (Some(0), None),
        (Some(1001), None),
        (None, Some(0)),
        (None, Some(101)),
    ] {
        let r = c.programs(PageParams { number, size }).await;
        assert!(matches!(r, Err(Error::Validation(_))));
    }
    c.programs(PageParams {
        number: Some(2),
        size: Some(100),
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn filters_serialize_and_validate() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/hackers/programs/acme/structured_scopes"))
        .and(query_param("filter[id__gt]", "57"))
        .and(query_param(
            "filter[created_at__gt]",
            "2024-01-01T00:00:00Z",
        ))
        .and(query_param(
            "filter[updated_at__gt]",
            "2024-02-01T00:00:00.000+09:00",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .expect(1)
        .mount(&server)
        .await;
    let c = client(&server);
    let f = ScopeFilters {
        id_gt: Some(57),
        created_at_gt: Some("2024-01-01T00:00:00Z".into()),
        updated_at_gt: Some("2024-02-01T00:00:00.000+09:00".into()),
    };
    c.structured_scopes("acme", PageParams::default(), &f)
        .await
        .unwrap();
    for bad in [
        "",
        "yesterday",
        "2024-01-01&x=1",
        "2024-01-01T00:00:00Z;",
        &"1".repeat(41),
    ] {
        let f = ScopeFilters {
            created_at_gt: Some(bad.into()),
            ..Default::default()
        };
        assert!(
            c.structured_scopes("acme", PageParams::default(), &f)
                .await
                .is_err(),
            "{bad}"
        );
    }
}

#[tokio::test]
async fn retries_429_with_retry_after_then_succeeds() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "5"))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": 1})))
        .mount(&server)
        .await;
    let started = Instant::now();
    let v = client(&server).program("acme").await.unwrap();
    assert_eq!(v["data"], 1);
    // Retry-After: 5 s is capped to 50 ms by the test policy.
    assert!(started.elapsed() < Duration::from_millis(2500));
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn retry_exhaustion_stops_at_three_attempts() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503).set_body_string("down"))
        .mount(&server)
        .await;
    let err = client(&server).program("acme").await.unwrap_err();
    assert!(err.to_string().contains("503"));
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn client_errors_are_not_retried() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    assert!(client(&server).program("acme").await.is_err());
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn response_size_cap_enforced() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(2048)))
        .mount(&server)
        .await;
    let mut c = client(&server);
    c.limits.response_bytes = 1024;
    let err = c.program("acme").await.unwrap_err();
    assert!(err.to_string().contains("exceeded"), "{err}");
}

#[tokio::test]
async fn pagination_bounded_by_pages_and_ignores_links_next() {
    let server = MockServer::start().await;
    let items: Vec<Value> = (0..100).map(|i| json!({"id": i.to_string()})).collect();
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": items,
            "links": {"next": "https://evil.example/steal"}
        })))
        .mount(&server)
        .await;
    let mut c = client(&server);
    c.limits.pages = 3;
    let paged = c.weaknesses_all("acme").await.unwrap();
    assert!(paged.truncated);
    assert_eq!(paged.items.len(), 300);
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 3);
    assert!(
        reqs.iter()
            .all(|r| r.url.host_str() != Some("evil.example"))
    );
    assert_all_get_v1(&server).await;
}

#[tokio::test]
async fn pagination_bounded_by_total_bytes() {
    let server = MockServer::start().await;
    let items: Vec<Value> = (0..100).map(|i| json!({"id": i})).collect();
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": items})))
        .mount(&server)
        .await;
    let mut c = client(&server);
    c.limits.total_bytes = 1500;
    let paged = c.structured_scopes_all("acme").await.unwrap();
    assert!(paged.truncated);
    assert!(server.received_requests().await.unwrap().len() <= 3);
}

#[tokio::test]
async fn errors_never_leak_credentials() {
    let server = MockServer::start().await;
    let echo = format!("bad creds {USER}:{KEY} \n\t end");
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(401).set_body_string(echo))
        .mount(&server)
        .await;
    let c = client(&server);
    let err = c.program("acme").await.unwrap_err().to_string();
    assert!(!err.contains(KEY) && !err.contains(USER), "{err}");
    assert!(err.contains("401"));
    let dbg = format!("{c:?}");
    assert!(!dbg.contains(KEY) && !dbg.contains(USER));
    // Connection failure text also carries no secrets.
    let dead = H1Client::with_base_url(&creds(), "http://127.0.0.1:1").unwrap();
    let err = dead.program("acme").await.unwrap_err().to_string();
    assert!(!err.contains(KEY) && !err.contains(USER) && !err.contains("127.0.0.1"));
}

fn slow_client(server: &MockServer, cap_ms: u64) -> H1Client {
    let mut c = client(server);
    c.retry.total_cap = Duration::from_millis(cap_ms);
    c.retry.request_timeout = Duration::from_secs(5);
    c
}

#[tokio::test]
async fn total_cap_is_hard_bound_on_slow_response() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(3)))
        .mount(&server)
        .await;
    let c = slow_client(&server, 800);
    let started = Instant::now();
    let err = c.program("acme").await.unwrap_err().to_string();
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "{:?}",
        started.elapsed()
    );
    assert!(err.contains("budget exhausted"), "{err}");
    assert!(!err.contains(KEY) && !err.contains(USER));
}

#[tokio::test]
async fn third_attempt_not_started_after_budget_spent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503).set_delay(Duration::from_millis(450)))
        .mount(&server)
        .await;
    let c = slow_client(&server, 800);
    let started = Instant::now();
    assert!(c.program("acme").await.is_err());
    assert!(
        started.elapsed() < Duration::from_millis(2000),
        "{:?}",
        started.elapsed()
    );
    assert!(server.received_requests().await.unwrap().len() == 2);
}
