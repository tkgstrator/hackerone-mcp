use std::sync::Arc;

use rmcp::handler::server::wrapper::Parameters;
use serde_json::{Value, json};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::params::{HandlePageParams, HandleParams, ListParams, ScopeParams};
use super::*;
use crate::config::Credentials;
use crate::draft::DraftStore;

fn drafts_dir(dir: &tempfile::TempDir) -> std::path::PathBuf {
    use std::os::unix::fs::DirBuilderExt;
    let p = dir.path().join("drafts");
    std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
    p
}

fn server_with(base: Option<&str>) -> (HackerOneServer, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let client = base.map(|b| {
        let c = Credentials {
            username: "u".into(),
            api_key: "k".into(),
        };
        Arc::new(H1Client::with_base_url(&c, b).unwrap())
    });
    let drafts = Arc::new(DraftStore::open(drafts_dir(&dir)).unwrap());
    (HackerOneServer::new(client, drafts), dir)
}

fn handle(h: &str) -> Parameters<HandleParams> {
    Parameters(HandleParams { handle: h.into() })
}

async fn mock_all(server: &MockServer) {
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": [{"id": "1337", "type": "weakness",
                "attributes": {"name": "CSRF", "external_id": "cwe-352"}}]
        })))
        .mount(server)
        .await;
}

#[tokio::test]
async fn no_credentials_gives_config_error() {
    let (s, _d) = server_with(None);
    let e = s.program_get(handle("acme")).await.unwrap_err();
    assert!(
        e.message.contains("H1_USERNAME and H1_API_KEY"),
        "{}",
        e.message
    );
    assert!(
        s.program_list(Parameters(ListParams {
            page: None,
            page_size: None
        }))
        .await
        .is_err()
    );
    assert!(s.program_submission_options(handle("acme")).await.is_err());
}

#[tokio::test]
async fn tools_use_expected_get_paths_and_envelope() {
    let mock = MockServer::start().await;
    mock_all(&mock).await;
    let (s, _d) = server_with(Some(&mock.uri()));

    let out = s
        .program_list(Parameters(ListParams {
            page: Some(1),
            page_size: Some(5),
        }))
        .await
        .unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["source"], "hackerone_api");
    assert_eq!(v["untrusted_content"], true);
    assert_eq!(v["endpoint"], "programs");
    assert!(v["data"]["data"].is_array());

    s.program_get(handle("acme")).await.unwrap();
    s.program_scope(Parameters(ScopeParams {
        handle: "acme".into(),
        page: None,
        page_size: None,
        id_gt: Some(3),
        created_at_gt: None,
        updated_at_gt: None,
    }))
    .await
    .unwrap();
    s.program_scope_exclusions(handle("acme")).await.unwrap();
    s.program_weaknesses(Parameters(HandlePageParams {
        handle: "acme".into(),
        page: None,
        page_size: None,
    }))
    .await
    .unwrap();

    let reqs = mock.received_requests().await.unwrap();
    let got: Vec<(String, String)> = reqs
        .iter()
        .map(|r| (r.method.to_string(), r.url.path().to_string()))
        .collect();
    assert_eq!(
        got,
        vec![
            ("GET".into(), "/v1/hackers/programs".into()),
            ("GET".into(), "/v1/hackers/programs/acme".into()),
            (
                "GET".into(),
                "/v1/hackers/programs/acme/structured_scopes".into()
            ),
            (
                "GET".into(),
                "/v1/hackers/programs/acme/scope_exclusions".into()
            ),
            ("GET".into(), "/v1/hackers/programs/acme/weaknesses".into()),
        ]
    );
    assert_eq!(reqs[2].url.query(), Some("filter%5Bid__gt%5D=3"));
}

#[tokio::test]
async fn hostile_handle_makes_no_request() {
    let mock = MockServer::start().await;
    mock_all(&mock).await;
    let (s, _d) = server_with(Some(&mock.uri()));
    for h in ["../x", "a/b", "", "%2e%2e"] {
        assert!(s.program_get(handle(h)).await.is_err());
        assert!(s.program_submission_options(handle(h)).await.is_err());
    }
    assert!(mock.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn submission_options_aggregates_three_endpoints() {
    let mock = MockServer::start().await;
    let respond = |body: Value| ResponseTemplate::new(200).set_body_json(body);
    Mock::given(method("GET")).and(wiremock::matchers::path("/v1/hackers/programs/acme"))
        .respond_with(respond(json!({"data": {"id": 9, "attributes": {"submission_state": "open", "state": "public_mode"}}})))
        .mount(&mock).await;
    Mock::given(method("GET"))
        .and(wiremock::matchers::path(
            "/v1/hackers/programs/acme/structured_scopes",
        ))
        .respond_with(respond(json!({"data": [{"id": "57", "attributes": {
            "asset_identifier": "api.example.com", "asset_type": "URL",
            "eligible_for_submission": true, "max_severity": "critical"}}]})))
        .mount(&mock)
        .await;
    Mock::given(method("GET")).and(wiremock::matchers::path("/v1/hackers/programs/acme/weaknesses"))
        .respond_with(respond(json!({"data": [{"id": "1337", "attributes": {"name": "CSRF", "external_id": "cwe-352"}}]})))
        .mount(&mock).await;
    let (s, _d) = server_with(Some(&mock.uri()));
    let out = s.program_submission_options(handle("acme")).await.unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["derived"], true);
    assert_eq!(v["sources"].as_array().unwrap().len(), 3);
    assert!(v["note"].as_str().unwrap().contains("scope_exclusions"));
    let d = &v["data"];
    assert_eq!(d["submission_state"], "open");
    assert_eq!(d["structured_scopes"][0]["id"], "57");
    assert_eq!(
        d["structured_scopes"][0]["asset_identifier"],
        "api.example.com"
    );
    assert_eq!(d["structured_scopes"][0]["eligible_for_submission"], true);
    assert_eq!(d["structured_scopes"][0]["max_severity"], "critical");
    assert_eq!(d["weaknesses"][0]["id"], "1337");
    assert_eq!(d["weaknesses"][0]["external_id"], "cwe-352");
    assert_eq!(d["weaknesses"][0]["name"], "CSRF");
    let reqs = mock.received_requests().await.unwrap();
    assert!(
        reqs.iter()
            .all(|r| r.method.as_str() == "GET" && r.url.path().starts_with("/v1/hackers/"))
    );
    assert!(reqs.len() >= 3);
}
