use super::model::Record;
use super::stats::{GROUPS, TOP, counts};
use serde_json::{Value, json};
use std::collections::BTreeSet;

fn percentage(current: usize, previous: usize, comparable: bool) -> Option<f64> {
    (comparable && previous != 0)
        .then(|| (current as f64 - previous as f64) / previous as f64 * 100.0)
}
fn share(n: usize, total: usize) -> Option<f64> {
    (total != 0).then(|| n as f64 / total as f64)
}

pub fn compare(current: &[Record], previous: &[Record], comparable: bool) -> Value {
    let mut groups = serde_json::Map::new();
    for kind in GROUPS {
        let current_counts = counts(current, kind);
        let previous_counts = counts(previous, kind);
        let current_missing_metadata = current.len() - current_counts.values().sum::<usize>();
        let previous_missing_metadata = previous.len() - previous_counts.values().sum::<usize>();
        let group_comparable =
            comparable && current_missing_metadata == 0 && previous_missing_metadata == 0;
        let reason = if !comparable {
            Some("incomplete_cohort")
        } else if !group_comparable {
            Some("incomplete_metadata")
        } else {
            None
        };
        let keys: BTreeSet<_> = current_counts
            .keys()
            .chain(previous_counts.keys())
            .cloned()
            .collect();
        let mut rows: Vec<_> = keys
            .into_iter()
            .map(|key| {
                let now = current_counts.get(&key).copied().unwrap_or(0);
                let then = previous_counts.get(&key).copied().unwrap_or(0);
                (key, now, then)
            })
            .collect();
        rows.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)).then(a.0.cmp(&b.0)));
        let omitted = rows.len().saturating_sub(TOP);
        let items: Vec<_> = rows
            .into_iter()
            .take(TOP)
            .map(|(key, now, then)| {
                json!({
                    "value": key,
                    "current_count": now,
                    "previous_count": then,
                    "current_share": share(now, current.len()),
                    "previous_share": share(then, previous.len()),
                    "count_change": group_comparable.then_some(now as i64 - then as i64),
                    "percentage_change": percentage(now, then, group_comparable)
                })
            })
            .collect();
        groups.insert(
            kind.into(),
            json!({
                "omitted_groups": omitted,
                "current_missing_metadata": current_missing_metadata,
                "previous_missing_metadata": previous_missing_metadata,
                "comparable": group_comparable,
                "reason": reason,
                "items": items
            }),
        );
    }
    json!({"cohort":"disclosed_only","all_findings_complete":false,"comparable":comparable,"reason":if comparable {None}else{Some("incomplete_cohort")},"current_reports_in_cohort":current.len(),"previous_reports_in_cohort":previous.len(),"count_change":comparable.then_some(current.len() as i64-previous.len() as i64),"percentage_change":percentage(current.len(),previous.len(),comparable),"groups":groups})
}

#[cfg(test)]
#[path = "trends_tests.rs"]
mod tests;
