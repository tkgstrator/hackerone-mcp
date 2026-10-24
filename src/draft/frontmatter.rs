//! Draft file format: `+++` TOML frontmatter `+++` then an opaque Markdown body.

use super::model::{Draft, MAX_FILE_BYTES, Stored, check_body};
use crate::error::{Error, Result};

const DELIM: &str = "+++";

fn malformed(msg: impl std::fmt::Display) -> Error {
    Error::Draft(format!("malformed draft file: {msg}"))
}

/// Serialize with `toml::to_string` of the typed struct only.
pub fn render(draft: &Draft, body: &str) -> Result<String> {
    draft.validate_fields()?;
    check_body(body)?;
    let meta = toml::to_string(draft).map_err(|e| Error::Draft(format!("serialize: {e}")))?;
    let out = format!("{DELIM}\n{meta}{DELIM}\n{body}");
    if out.len() > MAX_FILE_BYTES {
        return Err(Error::Validation(format!(
            "draft exceeds the {MAX_FILE_BYTES}-byte file limit"
        )));
    }
    Ok(out)
}

/// Parse a draft file. CRLF line endings are normalised to LF first.
pub fn parse(text: &str) -> Result<Stored> {
    if text.len() > MAX_FILE_BYTES {
        return Err(malformed("file too large"));
    }
    let text = text.replace("\r\n", "\n");
    let rest = text
        .strip_prefix("+++\n")
        .ok_or_else(|| malformed("missing opening `+++` line"))?;
    let mut offset = 0;
    let mut close = None;
    for line in rest.split_inclusive('\n') {
        if line == "+++\n" || line == DELIM {
            close = Some((offset, offset + line.len()));
            break;
        }
        offset += line.len();
    }
    let (meta_end, body_start) = close.ok_or_else(|| malformed("missing closing `+++` line"))?;
    let draft: Draft = toml::from_str(&rest[..meta_end]).map_err(malformed)?;
    draft
        .validate_fields()
        .map_err(|e| malformed(e.to_string()))?;
    let body = rest[body_start..].to_string();
    // Size is bounded by the file limit; hand-edited bodies above the write
    // limit stay readable (tools report truncation) but cannot be re-saved.
    if body.contains('\0') {
        return Err(malformed("body contains NUL"));
    }
    Ok(Stored { draft, body })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Draft {
        let mut d = Draft::new(
            "my-draft".into(),
            "Title with \"quotes\" and = signs".into(),
        );
        d.team_handle = Some("acme".into());
        d.impact = Some("line1\nline2\n++ +\n".into());
        d.references = vec!["https://example.com/?a=b".into()];
        d.weakness_id = Some(18);
        d.cwe = Some("cwe-79".into());
        d
    }

    #[test]
    fn round_trip() {
        let d = sample();
        let body = "# Body\n";
        let s = parse(&render(&d, body).unwrap()).unwrap();
        assert_eq!(s.draft, d);
        assert_eq!(s.body, body);
    }

    #[test]
    fn body_with_delimiter_and_toml_text() {
        let body = "text\n+++\nid = \"evil\"\nstatus = \"x\"\n+++\n[table]\n";
        let s = parse(&render(&sample(), body).unwrap()).unwrap();
        assert_eq!(s.body, body);
        assert_eq!(s.draft.id, "my-draft");
        let empty = parse(&render(&sample(), "").unwrap()).unwrap();
        assert_eq!(empty.body, "");
    }

    #[test]
    fn delimiter_line_in_metadata_rejected() {
        let mut d = sample();
        d.impact = Some("a\n+++\nb".into());
        assert!(render(&d, "b").is_err());
        d.impact = Some("a\r\n+++\r\nb".into());
        assert!(render(&d, "b").is_err());
    }

    #[test]
    fn hostile_title_rejected_on_render() {
        let mut d = sample();
        d.title = "x\n+++\nid = \"evil\"".into();
        assert!(render(&d, "b").is_err());
    }

    #[test]
    fn hostile_title_in_file_rejected() {
        let t = "+++\nid = \"a\"\nrevision = 1\ncreated_at = 1\nupdated_at = 1\nstatus = \"draft\"\ntitle = \"\"\"x\ny\"\"\"\n+++\nbody";
        assert!(parse(t).is_err());
    }

    #[test]
    fn malformed_files() {
        let good = render(&sample(), "b\n").unwrap();
        let no_close = good.replacen("\n+++\nb\n", "\n", 1);
        for bad in [
            "",
            "+++",
            "+++\n",
            "hello",
            " +++\nid=\"a\"\n+++\n",
            "+++\nnot toml [[\n+++\nb",
            "+++\nid = \"a\"\n+++\nb",
            no_close.as_str(),
            &good[..good.len() / 2],
            &good.replace("revision = 1", "revision = 1\nbogus = 2"),
            &good.replace("status = \"draft\"", "status = \"submitted\""),
            &good.replace("my-draft", "../x"),
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn crlf_input() {
        let crlf = render(&sample(), "a\nb\n").unwrap().replace('\n', "\r\n");
        let s = parse(&crlf).unwrap();
        assert_eq!(s.draft, sample());
        assert_eq!(s.body, "a\nb\n");
    }

    #[test]
    fn closing_without_trailing_newline() {
        let d = sample();
        let text = render(&d, "").unwrap();
        let text = text.trim_end_matches('\n');
        assert_eq!(parse(text).unwrap().body, "");
    }

    #[test]
    fn oversize_rejected() {
        let big = "x".repeat(MAX_FILE_BYTES);
        assert!(parse(&big).is_err());
        assert!(render(&sample(), &big).is_err());
    }
}
