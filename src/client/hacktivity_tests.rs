//! Contract tests for the typed Hacktivity request. Written before the
//! implementation: the stubs return a not-implemented `Error::Config`, so
//! every test below must fail until endpoint, query and date logic exist.

use serde_json::json;
use wiremock::matchers::{basic_auth, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

const SYNTHETIC_USER: &str = "synthetic_user";
const SYNTHETIC_KEY: &str = "synthetic-key-not-real";

#[tokio::test]
async fn hacktivity_rejects_the_live_silently_clamped_page_size_before_network() {
    for size in [51, 100] {
        assert_rejected_without_network(
            PageParams {
                number: Some(2),
                size: Some(size),
            },
            &f(),
            HacktivitySort::default(),
        )
        .await;
    }
}

fn creds() -> Credentials {
    Credentials {
        username: SYNTHETIC_USER.into(),
        api_key: SYNTHETIC_KEY.into(),
    }
}

fn client(server: &MockServer) -> H1Client {
    H1Client::with_base_url(&creds(), &server.uri()).unwrap()
}

async fn mount_ok(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/hackers/hacktivity"))
        .and(basic_auth(SYNTHETIC_USER, SYNTHETIC_KEY))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .mount(server)
        .await;
}

async fn only_query(server: &MockServer) -> (String, Vec<(String, String)>) {
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1, "expected exactly one request");
    let url = &reqs[0].url;
    let pairs = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    (url.query().unwrap_or_default().to_owned(), pairs)
}

fn pair(k: &str, v: &str) -> (String, String) {
    (k.into(), v.into())
}

async fn query_string_for(filters: &HacktivityFilters) -> String {
    let server = MockServer::start().await;
    mount_ok(&server).await;
    client(&server)
        .hacktivity(PageParams::default(), filters, HacktivitySort::default())
        .await
        .unwrap();
    let (_, pairs) = only_query(&server).await;
    pairs
        .into_iter()
        .find(|(k, _)| k == "queryString")
        .expect("queryString present")
        .1
}

fn f() -> HacktivityFilters {
    HacktivityFilters::default()
}

fn s(v: &str) -> Option<String> {
    Some(v.into())
}

fn assert_validation<T: std::fmt::Debug>(r: Result<T>) {
    match r {
        Err(Error::Validation(_)) => {}
        other => panic!("expected Error::Validation, got {other:?}"),
    }
}

/// Invalid input must fail locally and never reach the network.
async fn assert_rejected_without_network(
    page: PageParams,
    filters: &HacktivityFilters,
    sort: HacktivitySort,
) {
    let server = MockServer::start().await;
    mount_ok(&server).await;
    assert_validation(client(&server).hacktivity(page, filters, sort).await);
    assert!(server.received_requests().await.unwrap().is_empty());
}

// ---- wire format -------------------------------------------------------

#[tokio::test]
async fn unfiltered_request_is_fixed_get_with_disclosed_constraint_and_default_sort() {
    let server = MockServer::start().await;
    mount_ok(&server).await;
    let (value, len) = client(&server)
        .hacktivity(PageParams::default(), &f(), HacktivitySort::default())
        .await
        .unwrap();
    assert_eq!(value, json!({"data": []}));
    assert!(len > 0);
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method.as_str(), "GET");
    assert_eq!(reqs[0].url.path(), "/v1/hackers/hacktivity");
    let (raw, pairs) = only_query(&server).await;
    assert_eq!(
        pairs,
        vec![
            pair("queryString", "disclosed:true"),
            pair("sort", "-latest_disclosable_activity_at"),
        ]
    );
    // The queryString parameter is URL-query encoded exactly once.
    assert_eq!(
        raw,
        "queryString=disclosed%3Atrue&sort=-latest_disclosable_activity_at"
    );
}

#[tokio::test]
async fn page_params_are_sent_after_sort_in_fixed_order() {
    let server = MockServer::start().await;
    mount_ok(&server).await;
    client(&server)
        .hacktivity(
            PageParams {
                number: Some(2),
                size: Some(50),
            },
            &f(),
            HacktivitySort::DisclosedAtDesc,
        )
        .await
        .unwrap();
    let (raw, pairs) = only_query(&server).await;
    assert_eq!(
        pairs,
        vec![
            pair("queryString", "disclosed:true"),
            pair("sort", "-disclosed_at"),
            pair("page[number]", "2"),
            pair("page[size]", "50"),
        ]
    );
    assert_eq!(
        raw,
        "queryString=disclosed%3Atrue&sort=-disclosed_at&page%5Bnumber%5D=2&page%5Bsize%5D=50"
    );
}

#[tokio::test]
async fn full_filter_set_compiles_to_one_ordered_quoted_query() {
    let filters = HacktivityFilters {
        username: s("Jobert_1"),
        program: s("security-team"),
        cwe: s("Cross-Site Scripting (XSS) - Stored"),
        severity_rating: s("high"),
        disclosed_after: s("2026-10-07"),
        disclosed_before: s("2026-11-06"),
    };
    assert_eq!(
        query_string_for(&filters).await,
        concat!(
            "disclosed:true",
            " AND reporter:\"Jobert_1\"",
            " AND team:\"security-team\"",
            " AND cwe:\"Cross-Site Scripting (XSS) - Stored\"",
            " AND severity_rating:\"high\"",
            " AND disclosed_at:[2026-10-07 TO 2026-11-06}",
        )
    );
}

#[tokio::test]
async fn single_filters_each_add_exactly_one_clause() {
    let cases = [
        (
            HacktivityFilters {
                username: s("jobert"),
                ..f()
            },
            "disclosed:true AND reporter:\"jobert\"",
        ),
        (
            HacktivityFilters {
                program: s("acme"),
                ..f()
            },
            "disclosed:true AND team:\"acme\"",
        ),
        (
            HacktivityFilters {
                severity_rating: s("critical"),
                ..f()
            },
            "disclosed:true AND severity_rating:\"critical\"",
        ),
        (
            HacktivityFilters {
                disclosed_after: s("2026-10-07"),
                ..f()
            },
            "disclosed:true AND disclosed_at:[2026-10-07 TO *}",
        ),
        (
            HacktivityFilters {
                disclosed_before: s("2026-11-06"),
                ..f()
            },
            "disclosed:true AND disclosed_at:[* TO 2026-11-06}",
        ),
    ];
    for (filters, expected) in cases {
        assert_eq!(query_string_for(&filters).await, expected);
    }
}

#[tokio::test]
async fn cwe_quotes_and_backslashes_are_escaped_not_interpreted() {
    let filters = HacktivityFilters {
        cwe: s(r#"a"b\c" OR disclosed:false"#),
        ..f()
    };
    assert_eq!(
        query_string_for(&filters).await,
        r#"disclosed:true AND cwe:"a\"b\\c\" OR disclosed:false""#
    );
}

#[tokio::test]
async fn cwe_special_characters_are_url_encoded_on_the_wire() {
    let server = MockServer::start().await;
    mount_ok(&server).await;
    let filters = HacktivityFilters {
        cwe: s("A&B=C#D+E é"),
        ..f()
    };
    client(&server)
        .hacktivity(PageParams::default(), &filters, HacktivitySort::default())
        .await
        .unwrap();
    let (raw, pairs) = only_query(&server).await;
    assert_eq!(pairs.len(), 2, "no injected extra parameters: {raw}");
    assert_eq!(pairs[0].1, "disclosed:true AND cwe:\"A&B=C#D+E é\"");
    assert!(!raw.contains('#') && !raw.contains("&B"), "{raw}");
}

#[tokio::test]
async fn every_sort_is_sent_with_its_documented_string() {
    let all = [
        (
            HacktivitySort::RecentActivityAsc,
            "latest_disclosable_activity_at",
        ),
        (
            HacktivitySort::RecentActivityDesc,
            "-latest_disclosable_activity_at",
        ),
        (HacktivitySort::DisclosedAtAsc, "disclosed_at"),
        (HacktivitySort::DisclosedAtDesc, "-disclosed_at"),
        (HacktivitySort::AwardedAmountAsc, "total_awarded_amount"),
        (HacktivitySort::AwardedAmountDesc, "-total_awarded_amount"),
        (HacktivitySort::VotesAsc, "votes"),
        (HacktivitySort::VotesDesc, "-votes"),
    ];
    for (sort, wire) in all {
        let server = MockServer::start().await;
        mount_ok(&server).await;
        client(&server)
            .hacktivity(PageParams::default(), &f(), sort)
            .await
            .unwrap();
        let (_, pairs) = only_query(&server).await;
        assert_eq!(pairs[1], pair("sort", wire));
    }
}

#[tokio::test]
async fn basic_auth_and_accept_headers_are_sent() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/hackers/hacktivity"))
        .and(basic_auth(SYNTHETIC_USER, SYNTHETIC_KEY))
        .and(wiremock::matchers::header("accept", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"data": []})))
        .expect(1)
        .mount(&server)
        .await;
    client(&server)
        .hacktivity(PageParams::default(), &f(), HacktivitySort::default())
        .await
        .unwrap();
}

// ---- sort / filter deserialization -------------------------------------

#[test]
fn sort_deserializes_exactly_the_eight_documented_strings() {
    let all = [
        (
            "latest_disclosable_activity_at",
            HacktivitySort::RecentActivityAsc,
        ),
        (
            "-latest_disclosable_activity_at",
            HacktivitySort::RecentActivityDesc,
        ),
        ("disclosed_at", HacktivitySort::DisclosedAtAsc),
        ("-disclosed_at", HacktivitySort::DisclosedAtDesc),
        ("total_awarded_amount", HacktivitySort::AwardedAmountAsc),
        ("-total_awarded_amount", HacktivitySort::AwardedAmountDesc),
        ("votes", HacktivitySort::VotesAsc),
        ("-votes", HacktivitySort::VotesDesc),
    ];
    for (wire, want) in all {
        let got: HacktivitySort = serde_json::from_value(json!(wire)).unwrap();
        assert_eq!(got, want, "{wire}");
    }
}

#[test]
fn sort_rejects_unknown_or_malformed_values() {
    for bad in [
        "",
        "created_at",
        "-created_at",
        "Votes",
        "VOTES",
        " votes",
        "votes ",
        "--votes",
        "+votes",
        "disclosed_at,votes",
        "votes:desc",
        "-latest_activity_at",
    ] {
        assert!(
            serde_json::from_value::<HacktivitySort>(json!(bad)).is_err(),
            "{bad:?} must be rejected"
        );
    }
    assert!(serde_json::from_value::<HacktivitySort>(json!(null)).is_err());
    assert!(serde_json::from_value::<HacktivitySort>(json!(1)).is_err());
}

#[test]
fn sort_defaults_to_recent_activity_descending() {
    assert_eq!(
        HacktivitySort::default(),
        HacktivitySort::RecentActivityDesc
    );
}

#[test]
fn sort_schema_lists_only_the_whitelist() {
    let schema = serde_json::to_string(&schemars::schema_for!(HacktivitySort)).unwrap();
    for wire in [
        "latest_disclosable_activity_at",
        "-latest_disclosable_activity_at",
        "disclosed_at",
        "-disclosed_at",
        "total_awarded_amount",
        "-total_awarded_amount",
        "votes",
        "-votes",
    ] {
        assert!(
            schema.contains(&format!("\"{wire}\"")),
            "{wire} in {schema}"
        );
    }
}

#[test]
fn filters_deserialize_all_six_optional_strings() {
    let all: HacktivityFilters = serde_json::from_value(json!({
        "username": "u", "program": "p", "cwe": "c",
        "severity_rating": "low",
        "disclosed_after": "2026-01-01", "disclosed_before": "2026-02-01",
    }))
    .unwrap();
    assert_eq!(all.username.as_deref(), Some("u"));
    assert_eq!(all.program.as_deref(), Some("p"));
    assert_eq!(all.cwe.as_deref(), Some("c"));
    assert_eq!(all.severity_rating.as_deref(), Some("low"));
    assert_eq!(all.disclosed_after.as_deref(), Some("2026-01-01"));
    assert_eq!(all.disclosed_before.as_deref(), Some("2026-02-01"));
    let none: HacktivityFilters = serde_json::from_value(json!({})).unwrap();
    assert_eq!(none, HacktivityFilters::default());
}

// ---- handle validation -------------------------------------------------

#[test]
fn handle_filters_accept_the_existing_grammar() {
    let max = "a".repeat(64);
    for ok in ["a", "A-b_9", max.as_str()] {
        let filters = HacktivityFilters {
            username: s(ok),
            program: s(ok),
            ..f()
        };
        filters.validate().unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
}

#[test]
fn handle_filters_reject_bad_values_with_validation_error() {
    let too_long = "a".repeat(65);
    for bad in [
        "",
        too_long.as_str(),
        "a b",
        "a\"b",
        "a\\b",
        "a:b",
        "a/b",
        "a.b",
        "a*b",
        "é",
        "a\nb",
        "a)",
        "\u{ff21}",
    ] {
        assert_validation(
            HacktivityFilters {
                username: s(bad),
                ..f()
            }
            .validate(),
        );
        assert_validation(
            HacktivityFilters {
                program: s(bad),
                ..f()
            }
            .validate(),
        );
    }
}

#[tokio::test]
async fn invalid_handles_never_reach_the_network() {
    for filters in [
        HacktivityFilters {
            username: s("bad handle"),
            ..f()
        },
        HacktivityFilters {
            program: s(&"a".repeat(65)),
            ..f()
        },
        HacktivityFilters {
            username: s("x\" OR reporter:\"y"),
            ..f()
        },
    ] {
        assert_rejected_without_network(PageParams::default(), &filters, HacktivitySort::default())
            .await;
    }
}

// ---- CWE validation ----------------------------------------------------

#[test]
fn cwe_accepts_bounded_text_including_multibyte_within_200_bytes() {
    let max = "x".repeat(200);
    let multibyte_ok = "é".repeat(100); // 200 bytes
    for ok in [
        "CWE-79",
        "a",
        "Improper Input (SQL) 'x'",
        max.as_str(),
        multibyte_ok.as_str(),
    ] {
        HacktivityFilters { cwe: s(ok), ..f() }
            .validate()
            .unwrap_or_else(|e| panic!("{ok:?}: {e}"));
    }
}

#[test]
fn cwe_rejects_empty_blank_oversized_and_control_characters() {
    let too_long = "x".repeat(201);
    let multibyte_long = "é".repeat(101); // 202 bytes, only 101 chars
    for bad in [
        "",
        " ",
        "   ",
        "\t",
        "\u{a0}",
        too_long.as_str(),
        multibyte_long.as_str(),
        "a\nb",
        "a\rb",
        "a\tb",
        "a\0b",
        "a\u{7f}b",
        "a\u{1b}[0m",
    ] {
        assert_validation(HacktivityFilters { cwe: s(bad), ..f() }.validate());
    }
}

#[tokio::test]
async fn invalid_cwe_never_reaches_the_network() {
    for bad in ["", "   ", "line\nbreak", &"x".repeat(201)] {
        let filters = HacktivityFilters { cwe: s(bad), ..f() };
        assert_rejected_without_network(PageParams::default(), &filters, HacktivitySort::default())
            .await;
    }
}

// ---- severity ----------------------------------------------------------

#[test]
fn severity_accepts_documented_ratings_and_rejects_others() {
    for ok in ["none", "low", "medium", "high", "critical"] {
        HacktivityFilters {
            severity_rating: s(ok),
            ..f()
        }
        .validate()
        .unwrap_or_else(|e| panic!("{ok}: {e}"));
    }
    for bad in ["", "extreme", "high\"", "high OR low", "hi gh", "*", "\n"] {
        assert_validation(
            HacktivityFilters {
                severity_rating: s(bad),
                ..f()
            }
            .validate(),
        );
    }
}

// ---- dates -------------------------------------------------------------

fn date(y: i32, m: u32, d: u32) -> chrono::NaiveDate {
    chrono::NaiveDate::from_ymd_opt(y, m, d).unwrap()
}

#[test]
fn parse_date_accepts_valid_calendar_dates_and_range_edges() {
    assert_eq!(parse_date("2026-11-06").unwrap(), date(2026, 11, 6));
    assert_eq!(parse_date("2024-02-29").unwrap(), date(2024, 2, 29));
    assert_eq!(parse_date("2000-02-29").unwrap(), date(2000, 2, 29));
    assert_eq!(parse_date("2000-01-01").unwrap(), date(2000, 1, 1));
    assert_eq!(parse_date("9999-12-31").unwrap(), date(9999, 12, 31));
}

#[test]
fn parse_date_rejects_non_calendar_dates() {
    for bad in [
        "2026-02-29",
        "2100-02-29",
        "1900-02-29",
        "2026-04-31",
        "2026-13-01",
        "2026-00-10",
        "2026-01-00",
        "2026-01-32",
        "2026-06-31",
    ] {
        assert_validation(parse_date(bad));
    }
}

#[test]
fn parse_date_rejects_non_exact_formats() {
    for bad in [
        "",
        "2026-1-5",
        "2026-11-6",
        "26-11-06",
        "20261106",
        "2026/11/06",
        "2026-11-06T00:00:00Z",
        "2026-11-06Z",
        " 2026-11-06",
        "2026-11-06 ",
        "2026-11-06\n",
        "+2026-11-06",
        "-2026-11-06",
        "02026-11-06",
        "10000-01-01",
        "２０２６-11-06",
        "2026-11-0６",
        "today",
        "2026-W45-5",
    ] {
        assert_validation(parse_date(bad));
    }
}

#[test]
fn parse_date_enforces_2000_floor_and_9999_ceiling() {
    for bad in ["1999-12-31", "1970-01-01", "0001-01-01", "0000-01-01"] {
        assert_validation(parse_date(bad));
    }
}

#[test]
fn date_filters_are_validated_individually() {
    for bad in ["2026-02-29", "1999-12-31", "2026-11-06T00:00:00Z", ""] {
        assert_validation(
            HacktivityFilters {
                disclosed_after: s(bad),
                ..f()
            }
            .validate(),
        );
        assert_validation(
            HacktivityFilters {
                disclosed_before: s(bad),
                ..f()
            }
            .validate(),
        );
    }
    HacktivityFilters {
        disclosed_after: s("2000-01-01"),
        ..f()
    }
    .validate()
    .unwrap();
    HacktivityFilters {
        disclosed_before: s("9999-12-31"),
        ..f()
    }
    .validate()
    .unwrap();
}

#[test]
fn after_must_be_strictly_before_before() {
    let with = |a: &str, b: &str| HacktivityFilters {
        disclosed_after: s(a),
        disclosed_before: s(b),
        ..f()
    };
    with("2026-10-07", "2026-11-06").validate().unwrap();
    with("2026-11-05", "2026-11-06").validate().unwrap();
    assert_validation(with("2026-11-06", "2026-11-06").validate());
    assert_validation(with("2026-11-07", "2026-11-06").validate());
    assert_validation(with("2026-12-01", "2026-01-01").validate());
}

#[tokio::test]
async fn invalid_dates_and_order_never_reach_the_network() {
    for (after, before) in [
        (Some("2026-02-29"), None),
        (None, Some("1999-12-31")),
        (Some("2026-11-06"), Some("2026-11-06")),
        (Some("2026-11-07"), Some("2026-11-06")),
        (Some("2026-11-06T00:00:00Z"), None),
    ] {
        let filters = HacktivityFilters {
            disclosed_after: after.map(Into::into),
            disclosed_before: before.map(Into::into),
            ..f()
        };
        assert_rejected_without_network(PageParams::default(), &filters, HacktivitySort::default())
            .await;
    }
}

// ---- pagination --------------------------------------------------------

#[tokio::test]
async fn out_of_range_pages_never_reach_the_network() {
    for page in [
        PageParams {
            number: Some(0),
            size: None,
        },
        PageParams {
            number: Some(1001),
            size: None,
        },
        PageParams {
            number: None,
            size: Some(0),
        },
        PageParams {
            number: None,
            size: Some(101),
        },
    ] {
        assert_rejected_without_network(page, &f(), HacktivitySort::default()).await;
    }
}

#[tokio::test]
async fn page_boundaries_are_accepted() {
    let server = MockServer::start().await;
    mount_ok(&server).await;
    for (number, size) in [(1, 1), (1000, 50)] {
        client(&server)
            .hacktivity(
                PageParams {
                    number: Some(number),
                    size: Some(size),
                },
                &f(),
                HacktivitySort::default(),
            )
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn one_invalid_filter_among_valid_ones_rejects_the_whole_request() {
    let filters = HacktivityFilters {
        username: s("jobert"),
        program: s("acme"),
        cwe: s("CWE-79"),
        severity_rating: s("high"),
        disclosed_after: s("2026-10-07"),
        disclosed_before: s("not-a-date"),
    };
    assert_rejected_without_network(PageParams::default(), &filters, HacktivitySort::default())
        .await;
}
