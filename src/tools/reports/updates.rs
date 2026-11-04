use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::client::validate_report_id;
use crate::error::{Error, Result};

const MAX_ACTIVITIES: usize = 1000;
const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const FIELDS: [&str; 12] = [
    "state",
    "created_at",
    "submitted_at",
    "triaged_at",
    "closed_at",
    "last_activity_at",
    "last_reporter_activity_at",
    "first_program_activity_at",
    "last_program_activity_at",
    "last_public_activity_at",
    "bounty_awarded_at",
    "disclosed_at",
];

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    schema_version: u32,
    account: String,
    report_id: String,
    revision: u64,
    fields: BTreeMap<String, Value>,
    activities: BTreeMap<String, Value>,
}

fn malformed() -> Error {
    Error::Http("malformed report response; local baseline was not advanced".into())
}

fn corrupt() -> Error {
    Error::Draft("invalid report snapshot; local baseline was not advanced".into())
}

fn activity_id(value: &Value) -> Result<&str> {
    let id = value
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(malformed)?;
    validate_report_id(id).map_err(|_| malformed())?;
    if !value.is_object()
        || value
            .get("type")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(malformed());
    }
    Ok(id)
}

fn read_snapshot(value: &Value, report_id: &str) -> Result<Snapshot> {
    let snapshot: Snapshot = serde_json::from_value(value.clone()).map_err(|_| corrupt())?;
    if snapshot.schema_version != 1
        || snapshot.account.is_empty()
        || snapshot.report_id != report_id
        || snapshot.revision == 0
        || snapshot.activities.len() > MAX_ACTIVITIES
    {
        return Err(corrupt());
    }
    for (name, value) in &snapshot.fields {
        if name == "bounties" {
            if !value.is_null() && !value.is_array() {
                return Err(corrupt());
            }
        } else if !FIELDS.contains(&name.as_str()) || (!value.is_null() && !value.is_string()) {
            return Err(corrupt());
        }
    }
    for (id, activity) in &snapshot.activities {
        if activity_id(activity).map_err(|_| corrupt())? != id {
            return Err(corrupt());
        }
    }
    Ok(snapshot)
}

fn relationship_data<'a>(data: &'a Value, name: &str) -> Result<Option<&'a Value>> {
    let relationships = match data.get("relationships") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Object(value)) => value,
        _ => return Err(malformed()),
    };
    match relationships.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(value)) => Ok(value.get("data")),
        _ => Err(malformed()),
    }
}

pub(super) fn compare(
    account: &str,
    report_id: &str,
    prior: Option<&Value>,
    raw: &Value,
) -> Result<(Value, Value)> {
    validate_report_id(report_id)?;
    let previous = prior
        .map(|value| read_snapshot(value, report_id))
        .transpose()?;
    let revision = previous
        .as_ref()
        .map_or(0, |s| s.revision)
        .checked_add(1)
        .ok_or_else(corrupt)?;
    let baseline = previous.as_ref().is_none_or(|s| s.account != account);
    let mut next = match previous {
        Some(snapshot) if !baseline => snapshot,
        _ => Snapshot {
            schema_version: 1,
            account: account.into(),
            report_id: report_id.into(),
            revision,
            fields: BTreeMap::new(),
            activities: BTreeMap::new(),
        },
    };
    next.revision = revision;
    let data = raw.get("data").ok_or_else(malformed)?;
    if data.get("id").and_then(Value::as_str) != Some(report_id)
        || data.get("type").and_then(Value::as_str) != Some("report")
    {
        return Err(malformed());
    }
    let attributes = data
        .get("attributes")
        .and_then(Value::as_object)
        .ok_or_else(malformed)?;
    let mut observed_fields = BTreeMap::new();
    let mut unavailable = Vec::new();
    for name in FIELDS {
        match attributes.get(name) {
            Some(value) if value.is_null() || value.is_string() => {
                observed_fields.insert(name.to_string(), value.clone());
            }
            Some(_) => return Err(malformed()),
            None => unavailable.push(name),
        }
    }
    match relationship_data(data, "bounties")? {
        Some(value) if value.is_array() || value.is_null() => {
            observed_fields.insert("bounties".into(), value.clone());
        }
        Some(_) => return Err(malformed()),
        None => unavailable.push("bounties"),
    }
    let mut field_changes = Vec::new();
    for (name, value) in &observed_fields {
        let previous = next.fields.get(name);
        if !baseline && previous != Some(value) {
            field_changes.push(json!({"field":name,"previous_available":previous.is_some(),
                "previous":previous,"current":value}));
        }
        next.fields.insert(name.clone(), value.clone());
    }
    let (observed, activities_observation) = match relationship_data(data, "activities")? {
        Some(Value::Array(values)) => (values.as_slice(), "available"),
        Some(Value::Null) => (&[][..], "null"),
        None => (&[][..], "unavailable"),
        Some(_) => return Err(malformed()),
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut new_activities = Vec::new();
    let mut edited_activities = Vec::new();
    for activity in observed {
        let id = activity_id(activity)?;
        if !seen.insert(id) {
            return Err(malformed());
        }
        if !baseline {
            match next.activities.get(id) {
                None => new_activities.push(activity.clone()),
                Some(old) if old != activity => edited_activities.push(activity.clone()),
                Some(_) => {}
            }
        }
        next.activities.insert(id.to_string(), activity.clone());
    }
    if next.activities.len() > MAX_ACTIVITIES {
        return Err(Error::Draft("report snapshot exceeds 1000 retained activities; baseline was not advanced; use report_get to inspect the report".into()));
    }
    let snapshot = serde_json::to_value(next).map_err(|_| corrupt())?;
    if serde_json::to_vec(&snapshot).map_err(|_| corrupt())?.len() > MAX_SNAPSHOT_BYTES {
        return Err(Error::Draft("report snapshot exceeds 8 MiB; baseline was not advanced; use report_get to inspect the report".into()));
    }
    let output = json!({
        "report_id":report_id, "report_url":format!("https://hackerone.com/reports/{report_id}"),
        "baseline":baseline, "observed_fields":observed_fields, "unavailable_fields":unavailable,
        "field_changes":field_changes, "observed_activities":observed,
        "activities_available":activities_observation == "available",
        "activities_observation":activities_observation,
        "new_activities":new_activities, "edited_activities":edited_activities,
        "coverage":"Only activities included in this HackerOne GET response were inspected; omitted older activities are not proven absent. Missing fields do not establish acceptance, triage or payment.",
    });
    Ok((snapshot, output))
}

pub(super) fn validate_prior(prior: Option<&Value>, report_id: &str) -> Result<()> {
    if let Some(value) = prior {
        read_snapshot(value, report_id)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn activity(id: &str, message: &str) -> Value {
        json!({"id": id, "type": "activity-comment", "attributes": {"message": message}})
    }
    fn report(state: Value, activities: Value) -> Value {
        json!({"data": {"id":"42", "type":"report", "attributes":{"state":state,"triaged_at":null},
            "relationships":{"activities":{"data":activities},"bounties":{"data":[]}}}})
    }

    #[test]
    fn first_observation_is_a_baseline_not_new_arrivals() {
        let (saved, output) = compare(
            "alice",
            "42",
            None,
            &report(json!("new"), json!([activity("7", "Hello")])),
        )
        .unwrap();
        assert_eq!(output["baseline"], true);
        assert_eq!(output["new_activities"], json!([]));
        assert_eq!(output["observed_activities"][0]["id"], "7");
        assert_eq!(saved["revision"], 1);
    }

    #[test]
    fn new_and_edited_activities_and_state_changes_are_distinct() {
        let (saved, _) = compare(
            "alice",
            "42",
            None,
            &report(json!("new"), json!([activity("7", "Hello")])),
        )
        .unwrap();
        let (next, output) = compare(
            "alice",
            "42",
            Some(&saved),
            &report(
                json!("triaged"),
                json!([activity("8", "New"), activity("7", "Edited")]),
            ),
        )
        .unwrap();
        assert_eq!(output["baseline"], false);
        assert_eq!(output["new_activities"], json!([activity("8", "New")]));
        assert_eq!(
            output["edited_activities"],
            json!([activity("7", "Edited")])
        );
        let state = output["field_changes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["field"] == "state")
            .unwrap();
        assert_eq!(state["previous"], "new");
        assert_eq!(state["current"], "triaged");
        assert_eq!(next["revision"], 2);
    }

    #[test]
    fn absent_fields_retain_prior_observations_but_explicit_null_changes() {
        let (saved, _) = compare("alice", "42", None, &report(json!("new"), json!([]))).unwrap();
        let missing = json!({"data":{"id":"42","type":"report","attributes":{}}});
        let (next, output) = compare("alice", "42", Some(&saved), &missing).unwrap();
        assert_eq!(next["fields"]["state"], "new");
        assert_eq!(output["field_changes"], json!([]));
        assert!(
            output["unavailable_fields"]
                .as_array()
                .unwrap()
                .contains(&json!("state"))
        );
        let (_, output) =
            compare("alice", "42", Some(&next), &report(Value::Null, json!([]))).unwrap();
        assert!(
            output["field_changes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|f| f["field"] == "state" && f["previous"] == "new" && f["current"].is_null())
        );
    }

    #[test]
    fn missing_and_empty_activity_pages_do_not_erase_history() {
        let (saved, _) = compare(
            "alice",
            "42",
            None,
            &report(json!("new"), json!([activity("7", "Hello")])),
        )
        .unwrap();
        let missing = json!({"data":{"id":"42","type":"report","attributes":{}}});
        let (next, output) = compare("alice", "42", Some(&saved), &missing).unwrap();
        assert_eq!(output["activities_available"], false);
        assert_eq!(next["activities"]["7"], activity("7", "Hello"));
        let (next, output) =
            compare("alice", "42", Some(&next), &report(json!("new"), json!([]))).unwrap();
        assert_eq!(output["activities_available"], true);
        assert_eq!(next["activities"]["7"], activity("7", "Hello"));
        let (_, output) = compare(
            "alice",
            "42",
            Some(&next),
            &report(json!("new"), json!([activity("7", "Hello")])),
        )
        .unwrap();
        assert_eq!(output["new_activities"], json!([]));
    }

    #[test]
    fn switching_accounts_creates_a_clean_baseline() {
        let (saved, _) = compare(
            "alice",
            "42",
            None,
            &report(json!("new"), json!([activity("7", "Private Alice text")])),
        )
        .unwrap();
        let (next, output) = compare(
            "bob",
            "42",
            Some(&saved),
            &report(json!("resolved"), json!([])),
        )
        .unwrap();
        assert_eq!(output["baseline"], true);
        assert_eq!(next["account"], "bob");
        assert!(
            !serde_json::to_string(&next)
                .unwrap()
                .contains("Private Alice text")
        );
        assert_eq!(next["revision"], 2);
    }

    #[test]
    fn malformed_api_and_corrupt_snapshots_fail_closed() {
        for bad in [
            json!({}),
            json!({"data":{"id":"43","type":"report","attributes":{}}}),
            report(json!("new"), json!([{"id":"../7"}])),
        ] {
            assert!(compare("alice", "42", None, &bad).is_err());
        }
        assert!(
            compare(
                "alice",
                "42",
                Some(&json!({"revision":1})),
                &report(json!("new"), json!([]))
            )
            .is_err()
        );
    }

    #[test]
    fn activity_bound_fails_without_evicting_previous_ids() {
        let activities: Vec<Value> = (1..=1000)
            .map(|id| activity(&id.to_string(), "x"))
            .collect();
        let (saved, _) = compare(
            "alice",
            "42",
            None,
            &report(json!("new"), json!(activities)),
        )
        .unwrap();
        let result = compare(
            "alice",
            "42",
            Some(&saved),
            &report(json!("new"), json!([activity("1001", "x")])),
        );
        assert!(result.unwrap_err().to_string().contains("1000"));
    }
}
