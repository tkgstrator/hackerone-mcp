use crate::client::{HacktivityFilters, validate_handle, validate_report_id};
use chrono::{DateTime, Datelike, NaiveDate, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Debug, Serialize)]
pub struct Identity {
    pub handle: String,
    pub url: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Record {
    pub id: String,
    pub url: String,
    pub title: Option<String>,
    pub submitted_at: Option<String>,
    pub disclosed_at: String,
    pub reporter: Option<Identity>,
    pub program: Option<Identity>,
    pub cwe: Option<String>,
    pub severity_rating: Option<String>,
    pub currency: Option<String>,
    pub total_awarded_amount: Option<String>,
    #[serde(skip)]
    pub(super) amount: Amount,
    #[serde(skip)]
    pub(super) submitted: Option<DateTime<Utc>>,
    #[serde(skip)]
    pub(super) disclosed: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Amount {
    Known(u128),
    Unknown,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SelectionError {
    Invalid,
    Excluded,
}

fn timestamp(value: &Value) -> Option<DateTime<Utc>> {
    let s = value.as_str()?;
    if s.len() > 64 {
        return None;
    }
    let date = DateTime::parse_from_rfc3339(s).ok()?.with_timezone(&Utc);
    (2000..=9999).contains(&date.year()).then_some(date)
}

fn text(value: &Value, max: usize) -> Option<String> {
    let s = value.as_str()?;
    (!s.trim().is_empty() && s.len() <= max && !s.chars().any(char::is_control))
        .then(|| s.to_owned())
}

fn identity(value: &Value, key: &str) -> Option<Identity> {
    let handle = value.get(key)?.as_str()?;
    validate_handle(handle).ok()?;
    Some(Identity {
        handle: handle.to_owned(),
        url: format!("https://hackerone.com/{handle}"),
    })
}

fn date_filter(s: &str) -> Option<NaiveDate> {
    if s.len() != 10 {
        return None;
    }
    let d = NaiveDate::parse_from_str(s, "%Y-%m-%d").ok()?;
    ((2000..=9999).contains(&d.year()) && d.format("%Y-%m-%d").to_string() == s).then_some(d)
}

pub fn select(raw: &Value, filters: &HacktivityFilters) -> Result<Record, SelectionError> {
    let a = raw
        .get("attributes")
        .and_then(Value::as_object)
        .ok_or(SelectionError::Invalid)?;
    let id = match &raw["id"] {
        Value::String(s) if s.len() <= 20 => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return Err(SelectionError::Invalid),
    };
    validate_report_id(&id).map_err(|_| SelectionError::Invalid)?;
    match a.get("disclosed").and_then(Value::as_bool) {
        Some(true) => {}
        Some(false) => return Err(SelectionError::Excluded),
        None => return Err(SelectionError::Invalid),
    }
    let disclosed = timestamp(&raw["attributes"]["disclosed_at"]).ok_or(SelectionError::Invalid)?;
    let reporter = identity(
        &raw["relationships"]["reporter"]["data"]["attributes"],
        "username",
    );
    let p = &raw["relationships"]["program"]["data"]["attributes"];
    let program = identity(p, "handle");
    let currency = p["currency"]
        .as_str()
        .filter(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_alphabetic()))
        .map(str::to_ascii_uppercase);
    let cwe = text(&raw["attributes"]["cwe"], 200);
    let severity_rating = raw["attributes"]["severity_rating"]
        .as_str()
        .filter(|s| s.len() <= 8)
        .map(str::to_ascii_lowercase)
        .filter(|s| matches!(s.as_str(), "none" | "low" | "medium" | "high" | "critical"));
    for (expected, actual) in [
        (
            &filters.username,
            reporter.as_ref().map(|v| v.handle.as_str()),
        ),
        (
            &filters.program,
            program.as_ref().map(|v| v.handle.as_str()),
        ),
    ] {
        if let Some(expected) = expected
            && !actual.is_some_and(|actual| actual.eq_ignore_ascii_case(expected))
        {
            return Err(SelectionError::Excluded);
        }
    }
    if filters
        .cwe
        .as_ref()
        .is_some_and(|expected| cwe.as_ref() != Some(expected))
        || filters.severity_rating.as_ref().is_some_and(|expected| {
            !severity_rating
                .as_ref()
                .is_some_and(|s| s.eq_ignore_ascii_case(expected))
        })
    {
        return Err(SelectionError::Excluded);
    }
    for (bound, after) in [
        (&filters.disclosed_after, true),
        (&filters.disclosed_before, false),
    ] {
        if let Some(bound) = bound {
            let bound = date_filter(bound).ok_or(SelectionError::Invalid)?;
            if (after && disclosed.date_naive() < bound)
                || (!after && disclosed.date_naive() >= bound)
            {
                return Err(SelectionError::Excluded);
            }
        }
    }
    let title = raw["attributes"]["title"]
        .as_str()
        .map(|s| {
            let mut out = String::new();
            for ch in s.chars().filter(|ch| !ch.is_control()) {
                if out.len() + ch.len_utf8() > 500 {
                    break;
                }
                out.push(ch);
            }
            out
        })
        .filter(|s| !s.trim().is_empty());
    let submitted = timestamp(&raw["attributes"]["submitted_at"]);
    let amount = match a.get("total_awarded_amount") {
        None | Some(Value::Null) => Amount::Unknown,
        Some(v) => parse_amount(v).map_or(Amount::Invalid, Amount::Known),
    };
    Ok(Record {
        url: format!("https://hackerone.com/reports/{id}"),
        id,
        title,
        submitted_at: submitted.map(|d| d.to_rfc3339_opts(SecondsFormat::AutoSi, true)),
        disclosed_at: disclosed.to_rfc3339_opts(SecondsFormat::AutoSi, true),
        reporter,
        program,
        cwe,
        severity_rating,
        currency,
        total_awarded_amount: match amount {
            Amount::Known(v) => Some(decimal(v, 6)),
            _ => None,
        },
        amount,
        submitted,
        disclosed,
    })
}

/// Keep decimal tokens exact, and reject excessive exponents before allocation or powers.
fn parse_amount(value: &Value) -> Option<u128> {
    let s = match value {
        Value::String(s) if s.len() <= 128 => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return None,
    };
    if s.is_empty() || s.len() > 128 {
        return None;
    }
    let (mantissa, exponent) = match s.find(['e', 'E']) {
        Some(i) => {
            let exp = &s[i + 1..];
            if exp.len() > 4 {
                return None;
            }
            let exp = exp.parse::<i32>().ok()?;
            if !(-24..=24).contains(&exp) {
                return None;
            }
            (&s[..i], exp)
        }
        None => (s.as_str(), 0),
    };
    let (integer, fraction) = match mantissa.split_once('.') {
        Some((i, f)) => (i, f),
        None => (mantissa, ""),
    };
    if integer.is_empty()
        || integer.len() + fraction.len() > 64
        || !integer
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
        || (mantissa.contains('.') && fraction.is_empty())
    {
        return None;
    }
    let digits = format!("{integer}{fraction}");
    let digits = digits.trim_start_matches('0');
    if digits.is_empty() {
        return Some(0);
    }
    let significant = digits.trim_end_matches('0');
    let fractional = i32::try_from(fraction.len())
        .ok()?
        .checked_sub(exponent)?
        .checked_sub(i32::try_from(digits.len() - significant.len()).ok()?)?;
    let integer_digits = i32::try_from(significant.len())
        .ok()?
        .checked_sub(fractional)?;
    if fractional > 6 || integer_digits > 18 {
        return None;
    }
    let scale = u32::try_from(6i32.checked_sub(fractional)?).ok()?;
    significant
        .parse::<u128>()
        .ok()?
        .checked_mul(10u128.checked_pow(scale)?)
}

pub(super) fn decimal(value: u128, scale: u32) -> String {
    let factor = 10u128.pow(scale);
    let whole = value / factor;
    let fractional = value % factor;
    if fractional == 0 {
        return whole.to_string();
    }
    format!("{whole}.{:0width$}", fractional, width = scale as usize)
        .trim_end_matches('0')
        .to_owned()
}

#[cfg(test)]
#[path = "model_tests.rs"]
mod tests;
