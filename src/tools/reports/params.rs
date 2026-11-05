use schemars::JsonSchema;
use serde::Deserialize;

/// Parameters for `report_list`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReportListParams {
    /// Page number to retrieve (1..=1000). Defaults to 1.
    pub page: Option<u32>,
    /// Objects per page (1..=100). Defaults to the API default (25).
    pub page_size: Option<u32>,
}

/// Parameters for `report_get`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReportIdParams {
    /// Report ID as a decimal string without leading zeros, e.g. `1234567` ([1-9][0-9]{0,19}).
    pub report_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdatesParams {
    /// Report ID as a canonical positive decimal string.
    pub report_id: String,
    /// Advance the local baseline. Defaults to true; false previews without saving.
    pub mark_seen: Option<bool>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ReplyParams {
    /// Report ID as a canonical positive decimal string.
    pub report_id: String,
    /// Local reply text, nonblank, no NUL, at most 200000 UTF-8 bytes. Never posted.
    pub message: String,
}
