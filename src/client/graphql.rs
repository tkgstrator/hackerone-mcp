//! Fixed researcher-token GraphQL comment mutation: request bytes and receipt validation.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use super::validate_report_id;
use crate::error::{Error, Result};

pub(crate) const OPERATION: &str = "AddCommentToHackerOneReport";
pub(crate) const ENDPOINT: &str = "https://hackerone.com/graphql";

pub(crate) const MUTATION: &str = "mutation AddCommentToHackerOneReport($reportId: ID!, $message: String!, $internal: Boolean!) { createActivityComment(input: { report_id: $reportId, message: $message, internal: $internal }) { was_successful errors { edges { node { field message } } } activity { __typename ... on ActivitiesComment { id databaseId: _id message internal } } } }";

/// GraphQL node ID of a report: base64 of its global URI.
pub(crate) fn report_global_id(report_id: &str) -> String {
    STANDARD.encode(format!("gid://hackerone/Report/{report_id}"))
}

/// `Authorization` value: `Bearer base64(username:api_key)`.
pub(crate) fn bearer(username: &str, api_key: &str) -> String {
    format!(
        "Bearer {}",
        STANDARD.encode(format!("{username}:{api_key}"))
    )
}

/// Exact JSON bytes of the public-comment mutation for a validated report ID.
pub(crate) fn request_body(report_id: &str, message: &str) -> Result<String> {
    validate_report_id(report_id)?;
    serde_json::to_string(&json!({
        "operationName": OPERATION,
        "query": MUTATION,
        "variables": {
            "reportId": report_global_id(report_id),
            "message": message,
            "internal": false,
        },
    }))
    .map_err(|_| Error::Draft("cannot serialize comment preview".into()))
}

pub(crate) struct AcceptedActivity {
    pub(crate) id: String,
    pub(crate) visibility_confirmed: bool,
}

/// Check a response against the request. Returns the numeric activity ID and
/// whether the receipt explicitly confirms public visibility, or a fixed reason
/// (never server text). The schema allows an explicit null `internal` value.
pub(crate) fn accepted_activity_receipt(
    response: &Value,
    request: &Value,
) -> std::result::Result<AcceptedActivity, &'static str> {
    if response.get("errors").is_some_and(|e| !e.is_null()) {
        return Err("GraphQL errors");
    }
    let result = response
        .pointer("/data/createActivityComment")
        .filter(|v| v.is_object())
        .ok_or("missing mutation result")?;
    if result.get("was_successful") != Some(&Value::Bool(true)) {
        return Err("mutation was not successful");
    }
    let edges = match result.pointer("/errors/edges") {
        Some(Value::Array(edges)) => edges,
        _ => return Err("malformed mutation errors"),
    };
    if !edges.is_empty() {
        return Err("mutation validation errors");
    }
    let activity = result
        .get("activity")
        .filter(|v| v.is_object())
        .ok_or("missing activity")?;
    if activity.get("__typename").and_then(Value::as_str) != Some("ActivitiesComment") {
        return Err("unexpected activity kind");
    }
    let sent = request.get("variables");
    let message = sent.and_then(|v| v.get("message")).and_then(Value::as_str);
    if message.is_none() || activity.get("message").and_then(Value::as_str) != message {
        return Err("receipt message mismatch");
    }
    let visibility_confirmed = match activity.get("internal") {
        Some(Value::Bool(false)) => true,
        Some(Value::Null) => false,
        _ => return Err("receipt visibility mismatch"),
    };
    let id = activity
        .get("databaseId")
        .and_then(Value::as_str)
        .filter(|id| validate_report_id(id).is_ok())
        .ok_or("invalid activity ID")?;
    Ok(AcceptedActivity {
        id: id.to_owned(),
        visibility_confirmed,
    })
}
