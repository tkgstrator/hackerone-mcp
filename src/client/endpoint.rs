//! Typed HackerOne hacker-API endpoints. URLs are built only from
//! validated local parameters; nothing here accepts a path, URL or method.

use chrono::NaiveDate;
use reqwest::Url;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const MAX_HANDLE_LEN: usize = 64;
const MAX_REPORT_ID_LEN: usize = 20;
pub const MAX_PAGE_SIZE: u32 = 100;
// Live Hacktivity caps the result limit at 50 but offsets by the requested size.
// Larger requests silently skip results on the next page.
pub(crate) const HACKTIVITY_MAX_PAGE_SIZE: u32 = 50;
pub const MAX_PAGE_NUMBER: u32 = 1000;

/// Optional pagination parameters (`page[number]`, `page[size]`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PageParams {
    pub number: Option<u32>,
    pub size: Option<u32>,
}

impl PageParams {
    fn validate(&self) -> Result<()> {
        if let Some(n) = self.number
            && !(1..=MAX_PAGE_NUMBER).contains(&n)
        {
            return Err(Error::Validation(format!(
                "page must be between 1 and {MAX_PAGE_NUMBER}"
            )));
        }
        if let Some(s) = self.size
            && !(1..=MAX_PAGE_SIZE).contains(&s)
        {
            return Err(Error::Validation(format!(
                "page_size must be between 1 and {MAX_PAGE_SIZE}"
            )));
        }
        Ok(())
    }
}

/// Optional filters supported by the structured_scopes endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeFilters {
    pub id_gt: Option<u64>,
    pub created_at_gt: Option<String>,
    pub updated_at_gt: Option<String>,
}

fn validate_timestamp(name: &str, v: &str) -> Result<()> {
    let ok_chars = v
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'T' | b'Z' | b':' | b'+' | b'.' | b'-'));
    let b = v.as_bytes();
    let shape = b.len() >= 10 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-';
    if !(10..=40).contains(&v.len()) || !ok_chars || !shape {
        return Err(Error::Validation(format!(
            "{name} must be an RFC3339 timestamp such as 2024-01-31T00:00:00Z"
        )));
    }
    Ok(())
}

impl ScopeFilters {
    fn validate(&self) -> Result<()> {
        if let Some(v) = &self.created_at_gt {
            validate_timestamp("created_at_gt", v)?;
        }
        if let Some(v) = &self.updated_at_gt {
            validate_timestamp("updated_at_gt", v)?;
        }
        Ok(())
    }
}

const MAX_CWE_BYTES: usize = 200;
const SEVERITIES: [&str; 5] = ["none", "low", "medium", "high", "critical"];

/// Optional filters for `GET /v1/hackers/hacktivity`. Every value is validated
/// locally before any request and compiled into one quoted/escaped Lucene
/// `queryString`; raw Lucene is never accepted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub struct HacktivityFilters {
    /// Reporter handle, `[A-Za-z0-9_-]{1,64}`.
    pub username: Option<String>,
    /// Program handle, `[A-Za-z0-9_-]{1,64}`.
    pub program: Option<String>,
    /// Exact weakness label, 1..=200 UTF-8 bytes, nonblank, no control characters.
    pub cwe: Option<String>,
    /// Severity rating label, e.g. `high`.
    pub severity_rating: Option<String>,
    /// Inclusive UTC disclosure start, `YYYY-MM-DD`.
    pub disclosed_after: Option<String>,
    /// Exclusive UTC disclosure end, `YYYY-MM-DD`.
    pub disclosed_before: Option<String>,
}

impl HacktivityFilters {
    /// Validate every supplied filter without touching the network.
    pub fn validate(&self) -> Result<()> {
        for handle in [&self.username, &self.program].into_iter().flatten() {
            validate_handle(handle)?;
        }
        if let Some(cwe) = &self.cwe
            && (cwe.len() > MAX_CWE_BYTES
                || cwe.trim().is_empty()
                || cwe.chars().any(char::is_control))
        {
            return Err(Error::Validation(format!(
                "cwe must be 1..={MAX_CWE_BYTES} bytes, nonblank, without control characters"
            )));
        }
        if let Some(sev) = &self.severity_rating
            && !SEVERITIES.contains(&sev.as_str())
        {
            return Err(Error::Validation(
                "severity_rating must be one of none, low, medium, high, critical".into(),
            ));
        }
        let after = self
            .disclosed_after
            .as_deref()
            .map(parse_date)
            .transpose()?;
        let before = self
            .disclosed_before
            .as_deref()
            .map(parse_date)
            .transpose()?;
        if let (Some(a), Some(b)) = (after, before)
            && a >= b
        {
            return Err(Error::Validation(
                "disclosed_after must be earlier than disclosed_before".into(),
            ));
        }
        Ok(())
    }

    /// Lucene `queryString`. Call only after `validate()`: handles, severity and
    /// dates use restricted grammars, so only the CWE needs quote escaping.
    fn query_string(&self) -> String {
        let mut q = String::from("disclosed:true");
        if let Some(v) = &self.username {
            q.push_str(&format!(" AND reporter:\"{v}\""));
        }
        if let Some(v) = &self.program {
            q.push_str(&format!(" AND team:\"{v}\""));
        }
        if let Some(v) = &self.cwe {
            let escaped = v.replace('\\', "\\\\").replace('"', "\\\"");
            q.push_str(&format!(" AND cwe:\"{escaped}\""));
        }
        if let Some(v) = &self.severity_rating {
            q.push_str(&format!(" AND severity_rating:\"{v}\""));
        }
        if self.disclosed_after.is_some() || self.disclosed_before.is_some() {
            let after = self.disclosed_after.as_deref().unwrap_or("*");
            let before = self.disclosed_before.as_deref().unwrap_or("*");
            q.push_str(&format!(" AND disclosed_at:[{after} TO {before}}}"));
        }
        q
    }
}

/// Documented Hacktivity sort whitelist (Hacker Resources, 2026-09-23 revision).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
pub enum HacktivitySort {
    #[serde(rename = "latest_disclosable_activity_at")]
    RecentActivityAsc,
    #[default]
    #[serde(rename = "-latest_disclosable_activity_at")]
    RecentActivityDesc,
    #[serde(rename = "disclosed_at")]
    DisclosedAtAsc,
    #[serde(rename = "-disclosed_at")]
    DisclosedAtDesc,
    #[serde(rename = "total_awarded_amount")]
    AwardedAmountAsc,
    #[serde(rename = "-total_awarded_amount")]
    AwardedAmountDesc,
    #[serde(rename = "votes")]
    VotesAsc,
    #[serde(rename = "-votes")]
    VotesDesc,
}

impl HacktivitySort {
    fn as_str(self) -> &'static str {
        match self {
            Self::RecentActivityAsc => "latest_disclosable_activity_at",
            Self::RecentActivityDesc => "-latest_disclosable_activity_at",
            Self::DisclosedAtAsc => "disclosed_at",
            Self::DisclosedAtDesc => "-disclosed_at",
            Self::AwardedAmountAsc => "total_awarded_amount",
            Self::AwardedAmountDesc => "-total_awarded_amount",
            Self::VotesAsc => "votes",
            Self::VotesDesc => "-votes",
        }
    }
}

/// Parse exactly `YYYY-MM-DD`, a real calendar date within 2000-01-01..=9999-12-31.
pub(crate) fn parse_date(value: &str) -> Result<NaiveDate> {
    let invalid =
        || Error::Validation("date must be a real YYYY-MM-DD date from 2000-01-01".into());
    let shape = value.len() == 10
        && value.bytes().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                c == b'-'
            } else {
                c.is_ascii_digit()
            }
        });
    if !shape {
        return Err(invalid());
    }
    let date = NaiveDate::parse_from_str(value, "%Y-%m-%d").map_err(|_| invalid())?;
    if date < NaiveDate::from_ymd_opt(2000, 1, 1).ok_or_else(invalid)? {
        return Err(invalid());
    }
    Ok(date)
}

pub fn validate_handle(handle: &str) -> Result<()> {
    let ok = (1..=MAX_HANDLE_LEN).contains(&handle.len())
        && handle
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(Error::Validation(
            "handle must match [A-Za-z0-9_-]{1,64}".into(),
        ))
    }
}

/// Report IDs are canonical positive decimal integers: `[1-9][0-9]{0,19}`.
pub fn validate_report_id(id: &str) -> Result<()> {
    let ok = (1..=MAX_REPORT_ID_LEN).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_digit())
        && !id.starts_with('0');
    if ok {
        Ok(())
    } else {
        Err(Error::Validation(
            "report_id must match [1-9][0-9]{0,19}".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub(super) enum Endpoint<'a> {
    CreateReport,
    Reports {
        page: PageParams,
    },
    Report {
        id: &'a str,
    },
    Programs {
        page: PageParams,
    },
    Program {
        handle: &'a str,
    },
    StructuredScopes {
        handle: &'a str,
        page: PageParams,
        filters: &'a ScopeFilters,
    },
    Weaknesses {
        handle: &'a str,
        page: PageParams,
    },
    ScopeExclusions {
        handle: &'a str,
    },
    Hacktivity {
        page: PageParams,
        filters: &'a HacktivityFilters,
        sort: HacktivitySort,
    },
}

const PROGRAMS: &[&str] = &["v1", "hackers", "programs"];

impl Endpoint<'_> {
    /// Build the request URL below `origin` (scheme+host only is expected).
    pub(super) fn url(&self, origin: &Url) -> Result<Url> {
        let mut url = origin.clone();
        // (base path segments, validated trailing segments, pagination)
        let (base, tail, page): (&[&str], Vec<&str>, PageParams) = match self {
            Self::CreateReport => (&["v1", "hackers", "reports"], vec![], PageParams::default()),
            Self::Reports { page } => (&["v1", "hackers", "me", "reports"], vec![], *page),
            Self::Report { id } => {
                validate_report_id(id)?;
                (
                    &["v1", "hackers", "reports"],
                    vec![*id],
                    PageParams::default(),
                )
            }
            Self::Programs { page } => (PROGRAMS, vec![], *page),
            Self::Program { handle } => {
                validate_handle(handle)?;
                (PROGRAMS, vec![*handle], PageParams::default())
            }
            Self::StructuredScopes {
                handle,
                page,
                filters,
            } => {
                filters.validate()?;
                validate_handle(handle)?;
                (PROGRAMS, vec![*handle, "structured_scopes"], *page)
            }
            Self::Weaknesses { handle, page } => {
                validate_handle(handle)?;
                (PROGRAMS, vec![*handle, "weaknesses"], *page)
            }
            Self::Hacktivity { page, filters, .. } => {
                filters.validate()?;
                if page
                    .size
                    .is_some_and(|size| size > HACKTIVITY_MAX_PAGE_SIZE)
                {
                    return Err(Error::Validation(format!(
                        "Hacktivity page_size must be 1..={HACKTIVITY_MAX_PAGE_SIZE}"
                    )));
                }
                (&["v1", "hackers", "hacktivity"], vec![], *page)
            }
            Self::ScopeExclusions { handle } => {
                validate_handle(handle)?;
                (
                    PROGRAMS,
                    vec![*handle, "scope_exclusions"],
                    PageParams::default(),
                )
            }
        };
        page.validate()?;
        {
            let mut seg = url
                .path_segments_mut()
                .map_err(|()| Error::Config("invalid base URL".into()))?;
            seg.pop_if_empty().extend(base).extend(tail);
        }
        {
            let mut q = url.query_pairs_mut();
            if let Self::Hacktivity { filters, sort, .. } = self {
                q.append_pair("queryString", &filters.query_string());
                q.append_pair("sort", sort.as_str());
            }
            if let Some(n) = page.number {
                q.append_pair("page[number]", &n.to_string());
            }
            if let Some(s) = page.size {
                q.append_pair("page[size]", &s.to_string());
            }
            if let Self::StructuredScopes { filters, .. } = self {
                if let Some(v) = filters.id_gt {
                    q.append_pair("filter[id__gt]", &v.to_string());
                }
                if let Some(v) = &filters.created_at_gt {
                    q.append_pair("filter[created_at__gt]", v);
                }
                if let Some(v) = &filters.updated_at_gt {
                    q.append_pair("filter[updated_at__gt]", v);
                }
            }
        }
        if url.query() == Some("") {
            url.set_query(None);
        }
        Ok(url)
    }
}
