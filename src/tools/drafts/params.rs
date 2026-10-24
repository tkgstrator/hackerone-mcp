//! Parameter structs for the draft tools.

use schemars::JsonSchema;
use serde::Deserialize;

use crate::draft::model::Severity;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct CreateParams {
    /// Report title: a single line of at most 300 characters.
    pub title: String,
    /// Markdown body: the report's vulnerability_information.
    pub vulnerability_information: Option<String>,
    /// HackerOne program handle the report is intended for.
    pub team_handle: Option<String>,
    /// Impact statement.
    pub impact: Option<String>,
    /// Severity rating: none, low, medium, high or critical.
    pub severity_rating: Option<Severity>,
    /// Integer HackerOne weakness id (NOT the CWE number).
    pub weakness_id: Option<u64>,
    /// Integer HackerOne structured scope id.
    pub structured_scope_id: Option<u64>,
    /// Local CWE label such as "cwe-79". Informational only.
    pub cwe: Option<String>,
    /// CVSS vector string.
    pub cvss_vector: Option<String>,
    /// Affected versions, free text on a single line.
    pub affected_versions: Option<String>,
    /// Reference URLs or notes (at most 50).
    pub references: Option<Vec<String>>,
    /// Private local notes; never part of the request body preview.
    pub notes: Option<String>,
    /// Optional draft id matching [a-z0-9-]{1,64}. Generated from the title when omitted.
    pub id: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct IdParams {
    /// Draft id matching [a-z0-9-]{1,64}.
    pub id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct UpdateParams {
    /// Draft id matching [a-z0-9-]{1,64}.
    pub id: String,
    /// If set, the update fails unless the draft is at this revision (guards lost updates).
    pub expected_revision: Option<u64>,
    /// New title (single line, at most 300 characters).
    pub title: Option<String>,
    /// New Markdown body (vulnerability_information).
    pub vulnerability_information: Option<String>,
    pub team_handle: Option<String>,
    pub impact: Option<String>,
    pub severity_rating: Option<Severity>,
    /// Integer HackerOne weakness id (NOT the CWE number).
    pub weakness_id: Option<u64>,
    pub structured_scope_id: Option<u64>,
    /// Local CWE label such as "cwe-79".
    pub cwe: Option<String>,
    pub cvss_vector: Option<String>,
    pub affected_versions: Option<String>,
    /// Replaces the whole references list.
    pub references: Option<Vec<String>>,
    pub notes: Option<String>,
    /// Optional fields to clear. Allowed names: team_handle, impact, severity_rating,
    /// weakness_id, structured_scope_id, cwe, cvss_vector, affected_versions,
    /// references, notes.
    #[serde(default)]
    pub clear: Vec<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DeleteParams {
    /// Draft id matching [a-z0-9-]{1,64}.
    pub id: String,
    /// If set, deletion fails unless the draft is at this revision.
    pub expected_revision: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct ListParams {
    /// Maximum rows to return (default 50, max 200).
    pub limit: Option<usize>,
}
