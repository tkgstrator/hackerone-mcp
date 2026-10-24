use std::fmt;
use std::path::PathBuf;

use crate::error::{Error, Result};

pub struct Credentials {
    pub username: String,
    pub api_key: String,
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

#[derive(Debug)]
pub struct Config {
    pub credentials: Option<Credentials>,
    pub drafts_dir: PathBuf,
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.is_empty())
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let credentials = match (non_empty(get("H1_USERNAME")), non_empty(get("H1_API_KEY"))) {
            (Some(username), Some(api_key)) => Some(Credentials { username, api_key }),
            (None, None) => None,
            _ => {
                return Err(Error::Config(
                    "H1_USERNAME and H1_API_KEY must be set together".into(),
                ));
            }
        };
        let drafts_dir = match non_empty(get("H1_MCP_DRAFTS_DIR")) {
            Some(d) => PathBuf::from(d),
            None => {
                let home = non_empty(get("HOME")).ok_or_else(|| {
                    Error::Config("HOME is not set and H1_MCP_DRAFTS_DIR is not provided".into())
                })?;
                PathBuf::from(home).join(".config/hackerone-mcp/drafts")
            }
        };
        Ok(Self {
            credentials,
            drafts_dir,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        Config::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn both_set() {
        let c = cfg(&[("H1_USERNAME", "u"), ("H1_API_KEY", "k"), ("HOME", "/h")]).unwrap();
        let cr = c.credentials.unwrap();
        assert_eq!((cr.username.as_str(), cr.api_key.as_str()), ("u", "k"));
        assert_eq!(
            c.drafts_dir,
            PathBuf::from("/h/.config/hackerone-mcp/drafts")
        );
    }

    #[test]
    fn none_set() {
        assert!(cfg(&[("HOME", "/h")]).unwrap().credentials.is_none());
        let c = cfg(&[("H1_USERNAME", ""), ("H1_API_KEY", ""), ("HOME", "/h")]).unwrap();
        assert!(c.credentials.is_none());
    }

    #[test]
    fn exactly_one_is_error() {
        assert!(matches!(
            cfg(&[("H1_USERNAME", "u"), ("HOME", "/h")]),
            Err(Error::Config(_))
        ));
        assert!(matches!(
            cfg(&[("H1_API_KEY", "k"), ("HOME", "/h")]),
            Err(Error::Config(_))
        ));
    }

    #[test]
    fn drafts_dir_override_and_missing_home() {
        let c = cfg(&[("H1_MCP_DRAFTS_DIR", "/d")]).unwrap();
        assert_eq!(c.drafts_dir, PathBuf::from("/d"));
        assert!(matches!(cfg(&[]), Err(Error::Config(_))));
    }

    #[test]
    fn debug_does_not_leak_key() {
        let c = Credentials {
            username: "alice".into(),
            api_key: "SECRET-KEY-123".into(),
        };
        let s = format!("{c:?}");
        assert!(!s.contains("SECRET-KEY-123"));
        assert!(s.contains("alice"));
        let e = cfg(&[("H1_USERNAME", "u"), ("H1_API_KEY", "")]).unwrap_err();
        assert!(!format!("{e} {e:?}").contains("SECRET"));
    }
}
