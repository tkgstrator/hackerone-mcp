//! Offline validation of a draft against the fields HackerOne requires.

use serde::Serialize;
use serde_json::{Value, json};

use super::model::{Draft, MAX_BODY_BYTES, check_body};

pub const DISCLAIMER: &str = "Offline check only. It does not prove you may submit to this program \
(scope, eligibility, and program rules are not verified). Nothing is sent to HackerOne; \
submit manually in the HackerOne web UI.";

#[derive(Debug, Clone, Serialize)]
pub struct ValidationReport {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub request_body_preview: Value,
    pub disclaimer: &'static str,
}

fn blank(s: &Option<String>) -> bool {
    s.as_deref().is_none_or(|v| v.trim().is_empty())
}

pub fn validate(draft: &Draft, body: &str) -> ValidationReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    if blank(&draft.team_handle) {
        errors.push("team_handle is required".to_string());
    }
    if draft.title.trim().is_empty() {
        errors.push("title is required".to_string());
    }
    if body.trim().is_empty() {
        errors.push("vulnerability_information (draft body) is required".to_string());
    }
    if blank(&draft.impact) {
        errors.push("impact is required".to_string());
    }
    if check_body(body).is_err() {
        errors.push(format!(
            "vulnerability_information exceeds the {MAX_BODY_BYTES}-byte limit (or contains NUL) and cannot be saved by draft_update"
        ));
    }
    if let Err(e) = draft.validate_fields() {
        errors.push(e.to_string());
    }
    if draft.severity_rating.is_none() {
        warnings.push("severity_rating is not set".to_string());
    }
    if draft.weakness_id.is_none() {
        warnings.push("weakness_id is not set".to_string());
    }
    if draft.structured_scope_id.is_none() {
        warnings.push("structured_scope_id is not set".to_string());
    }
    if blank(&draft.cvss_vector) {
        warnings.push("cvss_vector is not set".to_string());
    }
    if draft.references.is_empty() {
        warnings.push("no references listed".to_string());
    }

    let mut attrs = serde_json::Map::new();
    attrs.insert("team_handle".into(), json!(draft.team_handle));
    attrs.insert("title".into(), json!(draft.title));
    attrs.insert("vulnerability_information".into(), json!(body));
    attrs.insert("impact".into(), json!(draft.impact));
    if let Some(s) = draft.severity_rating {
        attrs.insert("severity_rating".into(), json!(s));
    }
    if let Some(w) = draft.weakness_id {
        attrs.insert("weakness_id".into(), json!(w));
    }
    if let Some(s) = draft.structured_scope_id {
        attrs.insert("structured_scope_id".into(), json!(s));
    }
    ValidationReport {
        valid: errors.is_empty(),
        errors,
        warnings,
        request_body_preview: json!({
            "never_sent": true,
            "note": "This is the body that WOULD be sent to POST /hackers/reports. This server never sends it.",
            "body": {"data": {"type": "report", "attributes": attrs}},
        }),
        disclaimer: DISCLAIMER,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::draft::model::Severity;

    fn full() -> Draft {
        let mut d = Draft::new("a".into(), "T".into());
        d.team_handle = Some("acme".into());
        d.impact = Some("bad".into());
        d
    }

    #[test]
    fn valid_with_warnings() {
        let r = validate(&full(), "body");
        assert!(r.valid, "{:?}", r.errors);
        assert_eq!(r.warnings.len(), 5);
        assert_eq!(r.request_body_preview["never_sent"], true);
    }

    #[test]
    fn missing_required() {
        let r = validate(&Draft::new("a".into(), "T".into()), "  ");
        assert!(!r.valid);
        assert_eq!(r.errors.len(), 3);
    }

    #[test]
    fn preview_shape() {
        let mut d = full();
        d.severity_rating = Some(Severity::High);
        d.weakness_id = Some(18);
        d.structured_scope_id = Some(7);
        d.cwe = Some("cwe-79".into());
        let r = validate(&d, "b");
        let a = &r.request_body_preview["body"]["data"]["attributes"];
        assert_eq!(r.request_body_preview["body"]["data"]["type"], "report");
        assert_eq!(a["severity_rating"], "high");
        assert_eq!(a["weakness_id"], 18);
        assert_eq!(a["structured_scope_id"], 7);
        assert_eq!(a["vulnerability_information"], "b");
        assert!(a.get("cwe").is_none());
        assert!(r.warnings.iter().all(|w| !w.contains("severity")));
    }
}
