//! Draft data model: typed TOML frontmatter plus field validation.

use std::io::Read;
use std::time::{SystemTime, UNIX_EPOCH};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const MAX_ID_LEN: usize = 64;
pub const MAX_TITLE_CHARS: usize = 300;
pub const MAX_SHORT_CHARS: usize = 1_000;
pub const MAX_LONG_CHARS: usize = 20_000;
pub const MAX_REFERENCES: usize = 50;
pub const MAX_REFERENCE_CHARS: usize = 2_000;
pub const MAX_BODY_BYTES: usize = 200_000;
/// Maximum size of a whole draft file (metadata + body).
pub const MAX_FILE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// TOML frontmatter of a draft file. The Markdown body is stored separately
/// and is the report's `vulnerability_information`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Draft {
    pub id: String,
    pub revision: u64,
    pub created_at: u64,
    pub updated_at: u64,
    pub status: String,
    #[serde(default)]
    pub team_handle: Option<String>,
    pub title: String,
    #[serde(default)]
    pub impact: Option<String>,
    #[serde(default)]
    pub severity_rating: Option<Severity>,
    /// Integer weakness id as accepted by POST /hackers/reports.
    #[serde(default)]
    pub weakness_id: Option<u64>,
    #[serde(default)]
    pub structured_scope_id: Option<u64>,
    /// Local CWE label (e.g. `cwe-79`); never conflated with `weakness_id`.
    #[serde(default)]
    pub cwe: Option<String>,
    #[serde(default)]
    pub cvss_vector: Option<String>,
    #[serde(default)]
    pub affected_versions: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

/// A draft together with its Markdown body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub draft: Draft,
    pub body: String,
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Strict slug check: `[a-z0-9-]{1,64}`. Used for every id arriving from a tool call.
pub fn validate_id(id: &str) -> Result<()> {
    let ok = !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(Error::Validation(format!(
            "invalid draft id: must match [a-z0-9-]{{1,{MAX_ID_LEN}}}"
        )))
    }
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom")
        && f.read_exact(&mut buf).is_ok()
    {
        return buf;
    }
    use std::hash::{BuildHasher, Hasher, RandomState};
    for chunk in buf.chunks_mut(8) {
        let mut h = RandomState::new().build_hasher();
        h.write_u128(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        );
        let bytes = h.finish().to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    buf
}

/// `n` random characters from `[a-z0-9]`.
pub fn random_token(n: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    random_bytes(n)
        .into_iter()
        .map(|b| char::from(ALPHABET[usize::from(b) % ALPHABET.len()]))
        .collect()
}

pub fn generate_id(title: &str) -> String {
    let mut slug = String::new();
    for c in title.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    let mut slug: String = slug.trim_matches('-').chars().take(40).collect();
    slug = slug.trim_end_matches('-').to_string();
    if slug.is_empty() {
        slug.push_str("draft");
    }
    format!("{slug}-{}", random_token(6))
}

fn bad(msg: String) -> Error {
    Error::Validation(msg)
}

fn check_text(name: &str, s: &str, max_chars: usize, multiline: bool) -> Result<()> {
    if s.chars().count() > max_chars {
        return Err(bad(format!("{name} exceeds {max_chars} characters")));
    }
    if s.lines().any(|l| l == "+++") {
        return Err(bad(format!(
            "{name} must not contain a line consisting only of `+++`"
        )));
    }
    for c in s.chars() {
        let allowed_ws = multiline && matches!(c, '\n' | '\t');
        if c.is_control() && !allowed_ws {
            return Err(bad(if matches!(c, '\n' | '\r') {
                format!("{name} must be a single line")
            } else {
                format!("{name} contains a control character")
            }));
        }
    }
    Ok(())
}

fn check_opt(name: &str, v: &Option<String>, max: usize, multiline: bool) -> Result<()> {
    v.as_deref()
        .map_or(Ok(()), |s| check_text(name, s, max, multiline))
}

/// Check a Markdown body (free text; only size and NUL are restricted).
pub fn check_body(body: &str) -> Result<()> {
    if body.len() > MAX_BODY_BYTES {
        return Err(bad(format!(
            "vulnerability_information exceeds {MAX_BODY_BYTES} bytes"
        )));
    }
    if body.contains('\0') {
        return Err(bad("vulnerability_information contains NUL".into()));
    }
    Ok(())
}

impl Draft {
    pub fn new(id: String, title: String) -> Self {
        let now = now_secs();
        Self {
            id,
            revision: 1,
            created_at: now,
            updated_at: now,
            status: "draft".into(),
            team_handle: None,
            title,
            impact: None,
            severity_rating: None,
            weakness_id: None,
            structured_scope_id: None,
            cwe: None,
            cvss_vector: None,
            affected_versions: None,
            references: Vec::new(),
            notes: None,
        }
    }

    /// Validate every field's shape and bounds.
    pub fn validate_fields(&self) -> Result<()> {
        validate_id(&self.id)?;
        if self.status != "draft" {
            return Err(bad("status must be \"draft\"".into()));
        }
        if self.revision == 0 {
            return Err(bad("revision must be >= 1".into()));
        }
        if self.title.trim().is_empty() {
            return Err(bad("title must not be empty".into()));
        }
        check_text("title", &self.title, MAX_TITLE_CHARS, false)?;
        if let Some(t) = &self.team_handle
            && (t.is_empty()
                || t.len() > 100
                || !t
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')))
        {
            return Err(bad(
                "team_handle must be 1-100 chars of [A-Za-z0-9_.-]".into()
            ));
        }
        check_opt("impact", &self.impact, MAX_LONG_CHARS, true)?;
        check_opt("notes", &self.notes, MAX_LONG_CHARS, true)?;
        check_opt("cwe", &self.cwe, 100, false)?;
        check_opt("cvss_vector", &self.cvss_vector, 200, false)?;
        check_opt(
            "affected_versions",
            &self.affected_versions,
            MAX_SHORT_CHARS,
            false,
        )?;
        if self.references.len() > MAX_REFERENCES {
            return Err(bad(format!("references exceeds {MAX_REFERENCES} entries")));
        }
        for r in &self.references {
            check_text("reference", r, MAX_REFERENCE_CHARS, false)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_strict() {
        for ok in ["a", "abc-123", &"a".repeat(64)] {
            assert!(validate_id(ok).is_ok(), "{ok}");
        }
        let long = "a".repeat(65);
        for bad in [
            "../x", "a/b", ".", "..", "", "ABC", "a_b", "a b", "é", "a\0", "a\n", &long,
        ] {
            assert!(validate_id(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn generated_ids_are_valid() {
        for t in ["XSS in /login?x=1", "日本語", "", "---", &"w".repeat(500)] {
            let id = generate_id(t);
            validate_id(&id).unwrap();
        }
        assert!(generate_id("Hello World").starts_with("hello-world-"));
    }

    #[test]
    fn rejects_hostile_fields() {
        let mut d = Draft::new("x".into(), "ok".into());
        d.validate_fields().unwrap();
        d.title = "a\n+++\nstatus = \"x\"".into();
        assert!(d.validate_fields().is_err());
        d.title = "a\r".into();
        assert!(d.validate_fields().is_err());
        d.title = "t".repeat(301);
        assert!(d.validate_fields().is_err());
        d.title = "t".into();
        d.references = vec!["x".into(); 51];
        assert!(d.validate_fields().is_err());
        d.references = vec!["a\nb".into()];
        assert!(d.validate_fields().is_err());
        d.references.clear();
        d.team_handle = Some("a b".into());
        assert!(d.validate_fields().is_err());
    }
}
