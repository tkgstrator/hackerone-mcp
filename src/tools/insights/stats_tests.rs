use super::super::model::{Record, select};
use super::summarize;
use crate::client::HacktivityFilters;
use serde_json::{Value, json};

fn row(id: u64, amount: Value, currency: Value, program: Value, date: &str) -> Record {
    select(
        &json!({"id":id,"attributes":{"disclosed":true,"submitted_at":date,
        "disclosed_at":"2026-05-01T00:00:00Z","severity_rating":"high",
        "cwe":"XSS","total_awarded_amount":amount},"relationships":{
        "reporter":{"data":{"attributes":{"username":"alice"}}},
        "program":{"data":{"attributes":{"handle":program,"currency":currency}}}}}),
        &HacktivityFilters::default(),
    )
    .unwrap()
}
fn usd(amount: Value) -> Record {
    row(
        1,
        amount,
        json!("USD"),
        json!("acme"),
        "2026-01-01T00:00:00Z",
    )
}

#[test]
fn money_uses_exact_large_numeric_lexemes_and_seventh_digit_median() {
    let large: Value = serde_json::from_str("999999999999999999.999999").unwrap();
    let got = summarize(&[usd(large), usd(json!("0"))]);
    let bucket = &got["rewards"]["buckets"][0];
    assert_eq!(bucket["sum"], "999999999999999999.999999");
    assert_eq!(bucket["median"], "499999999999999999.9999995");
    assert_eq!(bucket["known_amounts"], 2);
}

#[test]
fn sum_can_exceed_individual_bound_without_overflow() {
    let rows = vec![usd(json!("999999999999999999.999999")); 1000];
    assert_eq!(
        summarize(&rows)["rewards"]["buckets"][0]["sum"],
        "999999999999999999999.999"
    );
}

#[test]
fn exponents_are_bounded_before_normalization_and_bad_amounts_are_counted() {
    let invalid = [
        "1e999999999999999999999999999999",
        "1e-9999999999999999999999",
        "-1",
        "NaN",
        "1000000000000000000",
        "0.0000001",
        "1.0000001",
        "1e19",
    ];
    let mut rows: Vec<_> = invalid.iter().map(|v| usd(json!(v))).collect();
    rows.extend([usd(json!("1.25e2")), usd(json!("1e-6")), usd(Value::Null)]);
    let got = summarize(&rows);
    assert_eq!(got["rewards"]["invalid_amounts"], 8);
    assert_eq!(got["rewards"]["unknown_amounts"], 1);
    assert_eq!(got["rewards"]["buckets"][0]["sum"], "125.000001");
}

#[test]
fn unknown_currency_stays_within_program_and_anonymous_sums_are_null() {
    let rows = [
        row(1, json!("3"), Value::Null, json!("a"), ""),
        row(2, json!("4"), Value::Null, json!("b"), ""),
        row(3, json!("5"), Value::Null, Value::Null, ""),
        row(4, json!("7"), Value::Null, Value::Null, ""),
        row(5, json!("0"), json!("USD"), json!("a"), ""),
        row(6, Value::Null, json!("EUR"), json!("a"), ""),
    ];
    let got = summarize(&rows);
    let buckets = got["rewards"]["buckets"].as_array().unwrap();
    assert_eq!(buckets.len(), 5);
    let a = buckets
        .iter()
        .find(|b| b["program"] == "a" && b["currency"].is_null())
        .unwrap();
    assert_eq!(a["sum"], "3");
    let anonymous = buckets
        .iter()
        .find(|b| b["program"].is_null() && b["currency"].is_null())
        .unwrap();
    assert!(anonymous["sum"].is_null());
    assert!(anonymous["median"].is_null());
    assert_eq!(anonymous["known_amounts"], 2);
    let usd = buckets.iter().find(|b| b["currency"] == "USD").unwrap();
    assert_eq!(usd["sum"], "0");
    let eur = buckets.iter().find(|b| b["currency"] == "EUR").unwrap();
    assert!(eur["sum"].is_null());
}

#[test]
fn cadence_uses_utc_submitted_dates_and_labels_only_the_retrieved_cohort() {
    let rows = [
        row(
            1,
            Value::Null,
            Value::Null,
            json!("a"),
            "2026-02-01T00:30:00+01:00",
        ),
        row(
            2,
            Value::Null,
            Value::Null,
            json!("a"),
            "2026-02-02T23:30:00Z",
        ),
        row(3, Value::Null, Value::Null, json!("a"), "bad"),
    ];
    let got = summarize(&rows);
    assert_eq!(got["cohort"], "disclosed_only");
    assert_eq!(got["all_findings_complete"], false);
    assert_eq!(
        got["cadence"]["monthly_submissions_in_cohort"][0]["month"],
        "2026-01"
    );
    assert_eq!(
        got["cadence"]["monthly_submissions_in_cohort"][0]["all_findings_complete"],
        false
    );
    assert_eq!(
        got["cadence"]["median_inter_submission_gap_days_in_cohort"],
        2.0
    );
    assert_eq!(got["cadence"]["missing_submission_dates_in_cohort"], 1);
}

#[test]
fn empty_cohort_has_null_unknown_cadence_and_money() {
    let got = summarize(&[]);
    assert_eq!(got["reports_in_cohort"], 0);
    assert!(got["cadence"]["first_submission_in_cohort"].is_null());
    assert!(got["cadence"]["median_inter_submission_gap_days_in_cohort"].is_null());
    assert_eq!(got["rewards"]["buckets"], json!([]));
}

#[test]
fn group_reward_and_recent_lists_have_deterministic_omission_counts() {
    let rows: Vec<_> = (1..=12)
        .map(|n| {
            row(
                n,
                json!(n),
                Value::Null,
                json!(format!("p{n:02}")),
                "2026-01-01T00:00:00Z",
            )
        })
        .collect();
    let got = summarize(&rows);
    assert_eq!(
        got["groups"]["program"]["items"].as_array().unwrap().len(),
        10
    );
    assert_eq!(got["groups"]["program"]["omitted_groups"], 2);
    assert_eq!(got["rewards"]["omitted_groups"], 2);
    assert_eq!(got["recent_reports"].as_array().unwrap().len(), 10);
    assert_eq!(got["omitted_reports"], 2);
}
