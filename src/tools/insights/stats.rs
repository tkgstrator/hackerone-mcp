use super::model::{Amount, Record, decimal};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub(super) const GROUPS: [&str; 4] = ["cwe", "severity", "program", "reporter"];
pub(super) const TOP: usize = 10;

pub(super) fn counts(records: &[Record], kind: &str) -> BTreeMap<String, usize> {
    let mut out = BTreeMap::new();
    for r in records {
        let value = match kind {
            "cwe" => r.cwe.clone(),
            "severity" => r.severity_rating.clone(),
            "program" => r.program.as_ref().map(|v| v.handle.to_ascii_lowercase()),
            "reporter" => r.reporter.as_ref().map(|v| v.handle.to_ascii_lowercase()),
            _ => None,
        };
        if let Some(value) = value {
            *out.entry(value).or_default() += 1;
        }
    }
    out
}

fn groups(records: &[Record]) -> Value {
    let mut result = serde_json::Map::new();
    for kind in GROUPS {
        let mut values: Vec<_> = counts(records, kind).into_iter().collect();
        values.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let known: usize = values.iter().map(|(_, n)| n).sum();
        result.insert(kind.into(),json!({"omitted_groups":values.len().saturating_sub(TOP),"missing_metadata":records.len()-known,"items":values.into_iter().take(TOP).map(|(value,count)|json!({"value":value,"count":count})).collect::<Vec<_>>()}));
    }
    Value::Object(result)
}

#[derive(Default)]
struct Rewards {
    amounts: Vec<u128>,
    unknown: usize,
    invalid: usize,
}

fn rewards(records: &[Record]) -> Value {
    // Explicit currencies may be combined. An absent currency needs a validated program.
    let mut groups: BTreeMap<(Option<String>, Option<String>), Rewards> = BTreeMap::new();
    let (mut known, mut unknown, mut invalid) = (0usize, 0usize, 0usize);
    for r in records {
        let program = if r.currency.is_none() {
            r.program.as_ref().map(|p| p.handle.to_ascii_lowercase())
        } else {
            None
        };
        let bucket = groups.entry((r.currency.clone(), program)).or_default();
        match r.amount {
            Amount::Known(v) => {
                known += 1;
                bucket.amounts.push(v);
            }
            Amount::Unknown => {
                unknown += 1;
                bucket.unknown += 1;
            }
            Amount::Invalid => {
                invalid += 1;
                bucket.invalid += 1;
            }
        }
    }
    let mut buckets: Vec<_> = groups.into_iter().collect();
    buckets.sort_by(|a, b| {
        let n = |r: &Rewards| r.amounts.len() + r.unknown + r.invalid;
        n(&b.1).cmp(&n(&a.1)).then(a.0.cmp(&b.0))
    });
    let omitted = buckets.len().saturating_sub(TOP);
    let buckets:Vec<_>=buckets.into_iter().take(TOP).map(|((currency,program),mut r)|{
        r.amounts.sort_unstable();
        let usable=currency.is_some()||program.is_some();
        let sum=if usable&&!r.amounts.is_empty(){r.amounts.iter().try_fold(0u128,|a,b|a.checked_add(*b)).map(|v|decimal(v,6))}else{None};
        let median=if usable&&!r.amounts.is_empty(){
            let middle=r.amounts.len()/2;
            if r.amounts.len()%2==1{Some(decimal(r.amounts[middle],6))}
            else{r.amounts[middle-1].checked_add(r.amounts[middle]).and_then(|v|v.checked_mul(5)).map(|v|decimal(v,7))}
        }else{None};
        json!({"currency":currency,"program":program,"known_amounts":r.amounts.len(),"unknown_amounts":r.unknown,"invalid_amounts":r.invalid,"sum":sum,"median":median,"aggregation_available":usable})
    }).collect();
    json!({"scope":"report_level_published_amounts_in_cohort","personal_earnings_known":false,"known_amounts":known,"unknown_amounts":unknown,"invalid_amounts":invalid,"buckets":buckets,"omitted_groups":omitted})
}

fn cadence(records: &[Record]) -> Value {
    let mut dates: Vec<_> = records.iter().filter_map(|r| r.submitted).collect();
    dates.sort_unstable();
    let mut months: BTreeMap<String, usize> = BTreeMap::new();
    for date in &dates {
        *months.entry(date.format("%Y-%m").to_string()).or_default() += 1;
    }
    let mut gaps: Vec<f64> = dates
        .windows(2)
        .map(|w| (w[1] - w[0]).num_milliseconds() as f64 / 86_400_000.0)
        .collect();
    gaps.sort_by(f64::total_cmp);
    let median = if gaps.is_empty() {
        None
    } else {
        let mid = gaps.len() / 2;
        Some(if gaps.len() % 2 == 1 {
            gaps[mid]
        } else {
            (gaps[mid - 1] + gaps[mid]) / 2.0
        })
    };
    json!({"first_submission_in_cohort":dates.first().map(|d|d.to_rfc3339_opts(chrono::SecondsFormat::AutoSi,true)),"last_submission_in_cohort":dates.last().map(|d|d.to_rfc3339_opts(chrono::SecondsFormat::AutoSi,true)),"median_inter_submission_gap_days_in_cohort":median,"missing_submission_dates_in_cohort":records.len()-dates.len(),"monthly_submissions_in_cohort":months.into_iter().map(|(month,count)|json!({"month":month,"submissions_in_cohort":count,"all_findings_complete":false})).collect::<Vec<_>>()})
}

pub fn summarize(records: &[Record]) -> Value {
    let mut recent: Vec<_> = records.iter().collect();
    recent.sort_by(|a, b| b.disclosed.cmp(&a.disclosed).then(a.id.cmp(&b.id)));
    let missing = json!({"title":records.iter().filter(|r|r.title.is_none()).count(),"reporter":records.iter().filter(|r|r.reporter.is_none()).count(),"program":records.iter().filter(|r|r.program.is_none()).count(),"cwe":records.iter().filter(|r|r.cwe.is_none()).count(),"severity_rating":records.iter().filter(|r|r.severity_rating.is_none()).count(),"currency":records.iter().filter(|r|r.currency.is_none()).count()});
    json!({"missing_metadata":missing,"cohort":"disclosed_only","all_findings_complete":false,"reports_in_cohort":records.len(),"cadence":cadence(records),"groups":groups(records),"rewards":rewards(records),"recent_reports":recent.into_iter().take(TOP).collect::<Vec<_>>(),"omitted_reports":records.len().saturating_sub(TOP)})
}

#[cfg(test)]
#[path = "stats_tests.rs"]
mod tests;
