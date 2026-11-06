use super::{SelectionError, select};
use crate::client::HacktivityFilters;
use serde_json::{Value, json};

fn fixture() -> Value {
    json!({"id":42,"attributes":{
        "disclosed":true,"title":"Synthetic report","submitted_at":"2026-02-01T00:30:00+01:00",
        "disclosed_at":"2026-03-01T00:30:00+01:00","severity_rating":"high",
        "total_awarded_amount":"0","cwe":"Cross-site Scripting (XSS)",
        "vulnerability_information":"SECRET","summary":"SECRET",
        "url":"https://evil.example/42"},"relationships":{
        "reporter":{"data":{"attributes":{"username":"Alice"}}},
        "program":{"data":{"attributes":{"handle":"Acme","currency":"USD"}}}}})
}

#[test]
fn selected_metadata_is_canonical_bounded_and_omits_private_text() {
    let mut raw = fixture();
    raw["attributes"]["title"] = json!("é".repeat(1000));
    let record = select(&raw, &HacktivityFilters::default()).unwrap();
    let got = serde_json::to_value(record).unwrap();
    assert_eq!(got["id"], "42");
    assert_eq!(got["url"], "https://hackerone.com/reports/42");
    assert_eq!(got["reporter"]["url"], "https://hackerone.com/Alice");
    assert!(got["title"].as_str().unwrap().len() <= 500);
    assert_eq!(got["submitted_at"], "2026-01-31T23:30:00Z");
    assert!(!got.to_string().contains("SECRET"));
    assert!(!got.to_string().contains("evil.example"));
}

#[test]
fn rejects_unsafe_ids_and_undisclosed_rows() {
    for bad in [
        json!("../42"),
        json!("042"),
        json!("-1"),
        json!(0),
        json!("4e2"),
        json!("9".repeat(80)),
    ] {
        let mut raw = fixture();
        raw["id"] = bad;
        assert!(matches!(
            select(&raw, &HacktivityFilters::default()),
            Err(SelectionError::Invalid)
        ));
    }
    let mut raw = fixture();
    raw["attributes"]["disclosed"] = json!(false);
    assert!(matches!(
        select(&raw, &HacktivityFilters::default()),
        Err(SelectionError::Excluded)
    ));
}

#[test]
fn every_supplied_filter_is_enforced_locally() {
    let filters = HacktivityFilters {
        username: Some("alice".into()),
        program: Some("acme".into()),
        cwe: Some("Cross-site Scripting (XSS)".into()),
        severity_rating: Some("high".into()),
        disclosed_after: Some("2026-02-28".into()),
        disclosed_before: Some("2026-03-01".into()),
    };
    assert!(select(&fixture(), &filters).is_ok());
    for (field, value) in [
        ("cwe", json!("cross-site Scripting (XSS)")),
        ("severity_rating", json!("critical")),
        ("disclosed_at", json!("2026-03-01T00:00:00Z")),
        ("disclosed_at", json!("bad date")),
    ] {
        let mut raw = fixture();
        raw["attributes"][field] = value;
        assert!(select(&raw, &filters).is_err(), "{field}");
    }
    for relationship in ["reporter", "program"] {
        let mut raw = fixture();
        raw["relationships"][relationship]["data"]["attributes"] =
            json!({"username":"bob","handle":"other"});
        assert!(select(&raw, &filters).is_err());
    }
}

#[test]
fn invalid_handles_never_create_profile_links() {
    let mut raw = fixture();
    raw["relationships"]["reporter"]["data"]["attributes"] = json!({"username":"../escape"});
    raw["relationships"]["program"]["data"]["attributes"] =
        json!({"handle":"a/b","currency":"USD"});
    let got = serde_json::to_value(select(&raw, &HacktivityFilters::default()).unwrap()).unwrap();
    assert!(got["reporter"].is_null());
    assert!(got["program"].is_null());
}

#[test]
fn jsonapi_relationships_are_selected_without_retaining_arbitrary_fields() {
    let mut raw = fixture();
    raw["relationships"] =
        json!({"reporter":{"data":{"attributes":{"username":"Bob","bio":"SECRET"}}}});
    let got = serde_json::to_value(select(&raw, &HacktivityFilters::default()).unwrap()).unwrap();
    assert_eq!(got["reporter"]["handle"], "Bob");
    assert!(!got.to_string().contains("SECRET"));
}
