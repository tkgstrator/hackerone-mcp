use schemars::JsonSchema;
use serde::Deserialize;

use crate::client::{HacktivityFilters, HacktivitySort};

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchParams {
    /// Exact HackerOne username (not a user directory search).
    pub username: Option<String>,
    pub program: Option<String>,
    /// Exact weakness label, e.g. "Information Disclosure", not a CWE ID lookup.
    pub cwe: Option<String>,
    /// none, low, medium, high or critical.
    pub severity_rating: Option<String>,
    /// Inclusive UTC date YYYY-MM-DD.
    pub disclosed_after: Option<String>,
    /// Exclusive UTC date YYYY-MM-DD.
    pub disclosed_before: Option<String>,
    pub sort: Option<HacktivitySort>,
    pub page: Option<u32>,
    pub page_size: Option<u32>,
}

impl SearchParams {
    pub(super) fn filters(&self) -> HacktivityFilters {
        HacktivityFilters {
            username: self.username.clone(),
            program: self.program.clone(),
            cwe: self.cwe.clone(),
            severity_rating: self.severity_rating.clone(),
            disclosed_after: self.disclosed_after.clone(),
            disclosed_before: self.disclosed_before.clone(),
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ActivityParams {
    /// Exact username. Empty activity does not prove a nonexistent account.
    pub username: String,
    /// Maximum source pages, 1..=10; default 3 (100 reports/page).
    pub max_pages: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct TrendsParams {
    /// Equal UTC disclosure windows of 1..=90 days; default 30.
    pub days: Option<u32>,
    /// Exclusive end YYYY-MM-DD, defaults to today's UTC date. No future dates.
    pub end_date: Option<String>,
    pub program: Option<String>,
    /// Exact API weakness label, not a CWE ID lookup.
    pub cwe: Option<String>,
    pub severity_rating: Option<String>,
    /// Maximum source pages per window, 1..=10; default 3.
    pub max_pages: Option<u32>,
}
