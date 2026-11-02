use schemars::JsonSchema;
use serde::Deserialize;

use crate::client::PageParams;

/// Parameters for `program_list`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListParams {
    /// Page number to retrieve (1..=1000). Defaults to 1.
    pub page: Option<u32>,
    /// Objects per page (1..=100). Defaults to the API default (25).
    pub page_size: Option<u32>,
}

/// Parameters for tools that take only a program handle.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct HandleParams {
    /// Program handle, e.g. `security`. Must match [A-Za-z0-9_-]{1,64}.
    pub handle: String,
}

/// Parameters for tools returning a paginated list for one program.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct HandlePageParams {
    /// Program handle. Must match [A-Za-z0-9_-]{1,64}.
    pub handle: String,
    /// Page number to retrieve (1..=1000). Defaults to 1.
    pub page: Option<u32>,
    /// Objects per page (1..=100). Defaults to the API default (25).
    pub page_size: Option<u32>,
}

/// Parameters for `program_scope`.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct ScopeParams {
    /// Program handle. Must match [A-Za-z0-9_-]{1,64}.
    pub handle: String,
    /// Page number to retrieve (1..=1000). Defaults to 1.
    pub page: Option<u32>,
    /// Objects per page (1..=100). Defaults to the API default (25).
    pub page_size: Option<u32>,
    /// Only scopes whose ID is greater than this value (filter[id__gt]).
    pub id_gt: Option<u64>,
    /// Only scopes created after this RFC3339 timestamp, e.g. 2024-01-31T00:00:00Z.
    pub created_at_gt: Option<String>,
    /// Only scopes updated after this RFC3339 timestamp, e.g. 2024-01-31T00:00:00Z.
    pub updated_at_gt: Option<String>,
}

pub fn page(number: Option<u32>, size: Option<u32>) -> PageParams {
    PageParams { number, size }
}

/// Parameters for bounded iOS program discovery.
#[derive(Debug, Deserialize, JsonSchema)]
pub struct DiscoverParams {
    /// Source program page, 1..=1000; defaults to 1.
    pub page: Option<u32>,
    /// Programs per source page, 1..=10; defaults to 5.
    pub page_size: Option<u32>,
    /// Require public_mode; defaults to true.
    pub public_only: Option<bool>,
    /// Require open submissions; defaults to true.
    pub accepting_submissions_only: Option<bool>,
    /// Require program and scope bounty eligibility; defaults to true.
    pub bounty_only: Option<bool>,
}
