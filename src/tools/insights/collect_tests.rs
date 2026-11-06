use std::time::{Duration, UNIX_EPOCH};

use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::collect::{InsightLimits, activity_with_limits, search_with_limits, trends_with_limits};
use super::params::{ActivityParams, SearchParams, TrendsParams};
use crate::client::H1Client;
use crate::config::Credentials;

fn limits() -> InsightLimits {
    InsightLimits {
        deadline: Duration::from_secs(5),
        input_bytes: 5 * 1024 * 1024,
        output_bytes: 1024 * 1024,
        now: UNIX_EPOCH + Duration::from_secs(1_793_923_200),
    }
}

fn client(server: &MockServer) -> H1Client {
    H1Client::with_base_url(
        &Credentials {
            username: "fixture-user".into(),
            api_key: "fixture-key-not-real".into(),
        },
        &server.uri(),
    )
    .unwrap()
}

fn row(id: u32, disclosed: &str) -> Value {
    json!({"id":id,"type":"report","attributes":{"title":"Public fixture","disclosed":true,"disclosed_at":disclosed,"submitted_at":"2026-01-01T00:00:00Z","cwe":"XSS","severity_rating":"high","total_awarded_amount":null,"vulnerability_information":"NEVER_INCLUDE_THIS_PRIVATE_BODY"},"relationships":{"reporter":{"data":{"type":"user","attributes":{"username":"alice"}}},"program":{"data":{"type":"program","attributes":{"handle":"acme"}}}}})
}

#[tokio::test]
async fn aggregates_page_at_the_live_cap_and_retain_the_tail_without_next_links() {
    let server = MockServer::start().await;
    let first: Vec<_> = (1..=50).map(|n| row(n, "2026-11-05T00:00:00Z")).collect();
    let tail: Vec<_> = (51..=60).map(|n| row(n, "2026-11-05T00:00:00Z")).collect();
    page(&server, 1, json!({"data":first,"links":{}})).await;
    page(&server, 2, json!({"data":tail,"links":{}})).await;
    let got = parse(
        activity_with_limits(&client(&server), activity(), limits())
            .await
            .unwrap(),
    );
    assert_eq!(got["data"]["coverage"]["unique_reports"], 60);
    assert_eq!(got["data"]["coverage"]["pages_received"], 2);
    assert_eq!(got["data"]["coverage"]["source_exhausted"], true);
    for request in server.received_requests().await.unwrap() {
        assert!(
            request
                .url
                .query_pairs()
                .any(|(k, v)| k == "page[size]" && v == "50")
        );
    }
}

fn activity() -> ActivityParams {
    ActivityParams {
        username: "alice".into(),
        max_pages: Some(2),
    }
}
fn search() -> SearchParams {
    serde_json::from_value(json!({})).unwrap()
}
fn trends() -> TrendsParams {
    serde_json::from_value(json!({"end_date":"2026-11-06","days":30})).unwrap()
}
fn parse(text: String) -> Value {
    serde_json::from_str(&text).unwrap()
}

async fn page(server: &MockServer, number: u32, body: Value) {
    Mock::given(method("GET"))
        .and(path("/v1/hackers/hacktivity"))
        .and(query_param("page[number]", number.to_string()))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

#[tokio::test]
async fn search_selects_public_metadata_deduplicates_and_excludes_filter_mismatches() {
    let server = MockServer::start().await;
    let mut wrong = row(2, "2026-11-05T00:00:00Z");
    wrong["attributes"]["cwe"] = json!("Other");
    page(
        &server,
        1,
        json!({"data":[row(1,"2026-11-05T00:00:00Z"),row(1,"2026-11-05T00:00:00Z"),wrong]}),
    )
    .await;
    let mut p = search();
    p.cwe = Some("XSS".into());
    let text = search_with_limits(&client(&server), p, limits())
        .await
        .unwrap();
    assert!(!text.contains("NEVER_INCLUDE_THIS_PRIVATE_BODY"));
    let got = parse(text);
    assert_eq!(got["untrusted_content"], true);
    assert_eq!(got["data"]["items"].as_array().unwrap().len(), 1);
    assert_eq!(got["data"]["coverage"]["duplicate_items"], 1);
    assert_eq!(got["data"]["coverage"]["excluded_items"], 1);
    assert_eq!(got["data"]["coverage"]["cohort_complete"], false);
}

#[tokio::test]
async fn short_page_with_next_keeps_generated_paging_but_never_follows_link() {
    let server = MockServer::start().await;
    page(&server,1,json!({"data":[row(1,"2026-11-05T00:00:00Z")],"links":{"next":format!("{}/trap",server.uri())}})).await;
    page(&server, 2, json!({"data":[],"links":{"next":null}})).await;
    Mock::given(path("/trap"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let got = parse(
        activity_with_limits(&client(&server), activity(), limits())
            .await
            .unwrap(),
    );
    assert_eq!(got["data"]["coverage"]["pages_received"], 2);
    assert_eq!(got["data"]["coverage"]["source_exhausted"], true);
    assert_eq!(got["data"]["coverage"]["pagination_inconsistent"], true);
    assert_eq!(got["data"]["coverage"]["cohort_complete"], false);
}

#[tokio::test]
async fn full_page_at_budget_is_truncated_even_without_a_next_link() {
    let server = MockServer::start().await;
    let rows: Vec<_> = (1..=50).map(|n| row(n, "2026-11-05T00:00:00Z")).collect();
    page(&server, 1, json!({"data":rows})).await;
    let mut p = activity();
    p.max_pages = Some(1);
    let got = parse(
        activity_with_limits(&client(&server), p, limits())
            .await
            .unwrap(),
    );
    assert_eq!(got["data"]["coverage"]["truncated"], true);
    assert_eq!(got["data"]["coverage"]["stop_reason"], "page_limit");
}

#[tokio::test]
async fn duplicates_across_pages_suppress_completeness_even_after_exhaustion() {
    let server = MockServer::start().await;
    let rows: Vec<_> = (1..=50).map(|n| row(n, "2026-11-05T00:00:00Z")).collect();
    page(&server, 1, json!({"data":rows})).await;
    page(&server, 2, json!({"data":[row(50,"2026-11-05T00:00:00Z")]})).await;
    let got = parse(
        activity_with_limits(&client(&server), activity(), limits())
            .await
            .unwrap(),
    );
    assert_eq!(got["data"]["coverage"]["unique_reports"], 50);
    assert_eq!(got["data"]["coverage"]["duplicate_items"], 1);
    assert_eq!(got["data"]["coverage"]["source_exhausted"], true);
    assert_eq!(got["data"]["coverage"]["cohort_complete"], false);
}

#[tokio::test]
async fn later_fetch_error_retains_prior_reports() {
    let server = MockServer::start().await;
    page(&server,1,json!({"data":[row(1,"2026-11-05T00:00:00Z")],"links":{"next":"https://example.invalid/ignored"}})).await;
    Mock::given(path("/v1/hackers/hacktivity"))
        .and(query_param("page[number]", "2"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let got = parse(
        activity_with_limits(&client(&server), activity(), limits())
            .await
            .unwrap(),
    );
    assert_eq!(got["data"]["coverage"]["unique_reports"], 1);
    assert_eq!(got["data"]["coverage"]["stop_reason"], "fetch_error");
    assert_eq!(got["data"]["coverage"]["truncated"], true);
}

#[tokio::test]
async fn malformed_first_page_errors_and_malformed_later_page_preserves_prior_rows() {
    let server = MockServer::start().await;
    page(&server, 1, json!({"data":{}})).await;
    assert!(
        activity_with_limits(&client(&server), activity(), limits())
            .await
            .is_err()
    );
    let server = MockServer::start().await;
    page(
        &server,
        1,
        json!({"data":[row(1,"2026-11-05T00:00:00Z")],"links":{"next":"ignored"}}),
    )
    .await;
    page(&server, 2, json!({"data":{}})).await;
    let got = parse(
        activity_with_limits(&client(&server), activity(), limits())
            .await
            .unwrap(),
    );
    assert_eq!(got["data"]["coverage"]["unique_reports"], 1);
    assert_eq!(got["data"]["coverage"]["stop_reason"], "malformed_page");
}

#[tokio::test]
async fn input_budget_discards_over_budget_page_and_stops() {
    let server = MockServer::start().await;
    page(&server, 1, json!({"data":[row(1,"2026-11-05T00:00:00Z")]})).await;
    let mut l = limits();
    l.input_bytes = 10;
    let got = parse(
        activity_with_limits(&client(&server), activity(), l)
            .await
            .unwrap(),
    );
    assert_eq!(got["data"]["coverage"]["unique_reports"], 0);
    assert_eq!(got["data"]["coverage"]["admitted_response_bytes"], 0);
    assert_eq!(got["data"]["coverage"]["stop_reason"], "input_byte_limit");
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn whole_tool_deadline_cancels_wait_without_losing_a_false_completeness_claim() {
    let server = MockServer::start().await;
    Mock::given(path("/v1/hackers/hacktivity"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(200))
                .set_body_json(json!({"data":[]})),
        )
        .mount(&server)
        .await;
    let mut l = limits();
    l.deadline = Duration::from_millis(20);
    let got = parse(
        activity_with_limits(&client(&server), activity(), l)
            .await
            .unwrap(),
    );
    assert_eq!(got["data"]["coverage"]["stop_reason"], "deadline");
    assert_eq!(got["data"]["coverage"]["cohort_complete"], false);
}

#[tokio::test]
async fn trends_preserve_current_when_previous_first_request_fails() {
    let server = MockServer::start().await;
    Mock::given(path("/v1/hackers/hacktivity"))
        .and(query_param(
            "queryString",
            "disclosed:true AND disclosed_at:[2026-10-07 TO 2026-11-06}",
        ))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"data":[row(1,"2026-11-01T00:00:00Z")]})),
        )
        .mount(&server)
        .await;
    Mock::given(path("/v1/hackers/hacktivity"))
        .and(query_param(
            "queryString",
            "disclosed:true AND disclosed_at:[2026-09-07 TO 2026-10-07}",
        ))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let got = parse(
        trends_with_limits(&client(&server), trends(), limits())
            .await
            .unwrap(),
    );
    assert_eq!(got["data"]["current_coverage"]["unique_reports"], 1);
    assert_eq!(
        got["data"]["previous_coverage"]["stop_reason"],
        "fetch_error"
    );
    assert!(
        !got["data"]["comparison_unavailable_reasons"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(got["data"]["comparison"]["count_change"].is_null());
}

#[tokio::test]
async fn trends_use_disclosure_dates_not_submission_dates_and_match_windows_locally() {
    let server = MockServer::start().await;
    Mock::given(path("/v1/hackers/hacktivity")).and(query_param("queryString","disclosed:true AND disclosed_at:[2026-10-07 TO 2026-11-06}" )).respond_with(ResponseTemplate::new(200).set_body_json(json!({"data":[row(1,"2026-11-01T00:00:00Z"),row(2,"2026-10-07T00:00:00Z"),row(3,"2026-11-06T00:00:00Z")]}))).mount(&server).await;
    Mock::given(path("/v1/hackers/hacktivity"))
        .and(query_param(
            "queryString",
            "disclosed:true AND disclosed_at:[2026-09-07 TO 2026-10-07}",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data":[]})))
        .mount(&server)
        .await;
    let got = parse(
        trends_with_limits(&client(&server), trends(), limits())
            .await
            .unwrap(),
    );
    assert_eq!(got["data"]["current_coverage"]["unique_reports"], 2);
    assert_eq!(got["data"]["current_coverage"]["excluded_items"], 1);
    assert_eq!(got["data"]["date_basis"], "disclosed_at");
    for request in server.received_requests().await.unwrap() {
        assert!(
            request
                .url
                .query_pairs()
                .any(|(k, v)| k == "page[size]" && v == "50")
        );
    }
    assert!(got["data"]["comparison"]["count_change"].is_null());
}

#[tokio::test]
async fn invalid_aggregate_arguments_do_not_reach_network() {
    let server = MockServer::start().await;
    let c = client(&server);
    for args in [
        json!({"days":0}),
        json!({"days":91}),
        json!({"max_pages":0}),
        json!({"max_pages":11}),
        json!({"end_date":"2026-02-30"}),
        json!({"end_date":"9999-12-31"}),
        json!({"end_date":"2000-01-01","days":1}),
        json!({"program":"../../oops"}),
    ] {
        assert!(
            trends_with_limits(&c, serde_json::from_value(args).unwrap(), limits())
                .await
                .is_err()
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn search_page_and_size_invalid_before_network() {
    let server = MockServer::start().await;
    for args in [
        json!({"page":0}),
        json!({"page":1001}),
        json!({"page_size":0}),
        json!({"page_size":51}),
        json!({"page_size":100}),
        json!({"page_size":101}),
    ] {
        assert!(
            search_with_limits(
                &client(&server),
                serde_json::from_value(args).unwrap(),
                limits()
            )
            .await
            .is_err()
        );
    }
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn output_pressure_trims_optional_items_and_preserves_coverage() {
    let server = MockServer::start().await;
    let rows: Vec<_> = (1..=25).map(|n| row(n, "2026-11-05T00:00:00Z")).collect();
    page(&server, 1, json!({"data":rows})).await;
    let mut l = limits();
    l.output_bytes = 3000;
    let text = search_with_limits(&client(&server), search(), l)
        .await
        .unwrap();
    assert!(text.len() <= 3000);
    let got = parse(text);
    assert_eq!(got["output_truncated"], true);
    assert_eq!(got["data"]["coverage"]["unique_reports"], 25);
    assert!(got["data"]["items"].as_array().unwrap().len() < 25);
    assert!(got["output_omitted_entries"].as_u64().unwrap() > 0);
}
