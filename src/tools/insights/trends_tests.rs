use super::super::model::select;
use super::compare;
use crate::client::HacktivityFilters;
use serde_json::json;

#[test]
fn complete_comparison_never_divides_by_zero() {
    let row=select(&json!({"id":1,"attributes":{"disclosed":true,"disclosed_at":"2026-01-01T00:00:00Z","cwe":"XSS"}}),&HacktivityFilters::default()).unwrap();
    let got = compare(&[row], &[], true);
    assert_eq!(got["count_change"], 1);
    assert!(got["percentage_change"].is_null());
    assert_eq!(got["groups"]["cwe"]["items"][0]["current_share"], 1.0);
    assert!(got["groups"]["cwe"]["items"][0]["percentage_change"].is_null());
}

#[test]
fn incomplete_comparison_suppresses_all_growth_figures() {
    let got = compare(&[], &[], false);
    assert_eq!(got["reason"], "incomplete_cohort");
    assert!(got["count_change"].is_null());
    assert!(got["percentage_change"].is_null());
}

#[test]
fn empty_complete_comparison_retains_zero_count_change_and_null_percent() {
    let got = compare(&[], &[], true);
    assert_eq!(got["count_change"], 0);
    assert!(got["percentage_change"].is_null());
}

fn classified_row() -> serde_json::Value {
    json!({"id":1,"attributes":{"disclosed":true,
        "disclosed_at":"2026-01-01T00:00:00Z","cwe":"XSS","severity_rating":"high"},
        "relationships":{"program":{"data":{"attributes":{"handle":"acme"}}},
            "reporter":{"data":{"attributes":{"username":"alice"}}}}})
}

#[test]
fn missing_classification_suppresses_only_affected_dimension_growth_in_either_window() {
    // Dropping an unknown classification must not turn an observed count into a decline.
    for kind in ["cwe", "severity", "program", "reporter"] {
        for missing_current in [true, false] {
            let known = select(&classified_row(), &HacktivityFilters::default()).unwrap();
            let mut raw = classified_row();
            match kind {
                "cwe" => raw["attributes"]["cwe"] = serde_json::Value::Null,
                "severity" => raw["attributes"]["severity_rating"] = serde_json::Value::Null,
                _ => raw["relationships"][kind] = serde_json::Value::Null,
            }
            let missing = select(&raw, &HacktivityFilters::default()).unwrap();
            let got = if missing_current {
                compare(&[missing], &[known], true)
            } else {
                compare(&[known], &[missing], true)
            };
            let group = &got["groups"][kind];
            assert_eq!(
                group["current_missing_metadata"],
                usize::from(missing_current),
                "{kind}"
            );
            assert_eq!(
                group["previous_missing_metadata"],
                usize::from(!missing_current),
                "{kind}"
            );
            assert_eq!(group["comparable"], false, "{kind}");
            assert_eq!(group["reason"], "incomplete_metadata", "{kind}");
            let item = &group["items"][0];
            assert!(item["count_change"].is_null(), "{kind}");
            assert!(item["percentage_change"].is_null(), "{kind}");
            if missing_current {
                assert_eq!(item["current_count"], 0);
                assert_eq!(item["previous_count"], 1);
                assert_eq!(item["current_share"], 0.0);
                assert_eq!(item["previous_share"], 1.0);
            } else {
                assert_eq!(item["current_count"], 1);
                assert_eq!(item["previous_count"], 0);
                assert_eq!(item["current_share"], 1.0);
                assert_eq!(item["previous_share"], 0.0);
            }
            assert_eq!(got["comparable"], true);
            assert_eq!(got["count_change"], 0);
            assert_eq!(got["percentage_change"], 0.0);
            for unaffected in ["cwe", "severity", "program", "reporter"] {
                if unaffected != kind {
                    assert_eq!(got["groups"][unaffected]["comparable"], true);
                    assert_eq!(got["groups"][unaffected]["items"][0]["count_change"], 0);
                }
            }
        }
    }
}

#[test]
fn incomplete_cohort_still_suppresses_fully_classified_group_growth() {
    let row = select(&classified_row(), &HacktivityFilters::default()).unwrap();
    let got = compare(
        std::slice::from_ref(&row),
        std::slice::from_ref(&row),
        false,
    );
    for kind in ["cwe", "severity", "program", "reporter"] {
        let group = &got["groups"][kind];
        assert_eq!(group["current_missing_metadata"], 0);
        assert_eq!(group["previous_missing_metadata"], 0);
        assert_eq!(group["comparable"], false);
        assert_eq!(group["reason"], "incomplete_cohort");
        assert!(group["items"][0]["count_change"].is_null());
        assert!(group["items"][0]["percentage_change"].is_null());
    }
}
