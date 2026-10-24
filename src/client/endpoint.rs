//! Typed, GET-only HackerOne hacker-API endpoints. URLs are built only from
//! validated local parameters; nothing here accepts a path, URL or method.

use reqwest::Url;

use crate::error::{Error, Result};

const MAX_HANDLE_LEN: usize = 64;
pub const MAX_PAGE_SIZE: u32 = 100;
pub const MAX_PAGE_NUMBER: u32 = 1000;

/// Optional pagination parameters (`page[number]`, `page[size]`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PageParams {
    pub number: Option<u32>,
    pub size: Option<u32>,
}

impl PageParams {
    fn validate(&self) -> Result<()> {
        if let Some(n) = self.number
            && !(1..=MAX_PAGE_NUMBER).contains(&n)
        {
            return Err(Error::Validation(format!(
                "page must be between 1 and {MAX_PAGE_NUMBER}"
            )));
        }
        if let Some(s) = self.size
            && !(1..=MAX_PAGE_SIZE).contains(&s)
        {
            return Err(Error::Validation(format!(
                "page_size must be between 1 and {MAX_PAGE_SIZE}"
            )));
        }
        Ok(())
    }
}

/// Optional filters supported by the structured_scopes endpoint.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeFilters {
    pub id_gt: Option<u64>,
    pub created_at_gt: Option<String>,
    pub updated_at_gt: Option<String>,
}

fn validate_timestamp(name: &str, v: &str) -> Result<()> {
    let ok_chars = v
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'T' | b'Z' | b':' | b'+' | b'.' | b'-'));
    let b = v.as_bytes();
    let shape = b.len() >= 10 && b[..4].iter().all(u8::is_ascii_digit) && b[4] == b'-';
    if !(10..=40).contains(&v.len()) || !ok_chars || !shape {
        return Err(Error::Validation(format!(
            "{name} must be an RFC3339 timestamp such as 2024-01-31T00:00:00Z"
        )));
    }
    Ok(())
}

impl ScopeFilters {
    fn validate(&self) -> Result<()> {
        if let Some(v) = &self.created_at_gt {
            validate_timestamp("created_at_gt", v)?;
        }
        if let Some(v) = &self.updated_at_gt {
            validate_timestamp("updated_at_gt", v)?;
        }
        Ok(())
    }
}

pub fn validate_handle(handle: &str) -> Result<()> {
    let ok = (1..=MAX_HANDLE_LEN).contains(&handle.len())
        && handle
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(Error::Validation(
            "handle must match [A-Za-z0-9_-]{1,64}".into(),
        ))
    }
}

#[derive(Debug, Clone)]
pub(super) enum Endpoint<'a> {
    Programs {
        page: PageParams,
    },
    Program {
        handle: &'a str,
    },
    StructuredScopes {
        handle: &'a str,
        page: PageParams,
        filters: &'a ScopeFilters,
    },
    Weaknesses {
        handle: &'a str,
        page: PageParams,
    },
    ScopeExclusions {
        handle: &'a str,
    },
}

impl Endpoint<'_> {
    /// Build the request URL below `origin` (scheme+host only is expected).
    pub(super) fn url(&self, origin: &Url) -> Result<Url> {
        let mut url = origin.clone();
        let (handle, tail, page): (Option<&str>, &str, PageParams) = match self {
            Self::Programs { page } => (None, "", *page),
            Self::Program { handle } => (Some(handle), "", PageParams::default()),
            Self::StructuredScopes {
                handle,
                page,
                filters,
            } => {
                filters.validate()?;
                (Some(handle), "structured_scopes", *page)
            }
            Self::Weaknesses { handle, page } => (Some(handle), "weaknesses", *page),
            Self::ScopeExclusions { handle } => {
                (Some(handle), "scope_exclusions", PageParams::default())
            }
        };
        if let Some(h) = handle {
            validate_handle(h)?;
        }
        page.validate()?;
        {
            let mut seg = url
                .path_segments_mut()
                .map_err(|()| Error::Config("invalid base URL".into()))?;
            seg.pop_if_empty().extend(["v1", "hackers", "programs"]);
            if let Some(h) = handle {
                seg.push(h);
            }
            if !tail.is_empty() {
                seg.push(tail);
            }
        }
        {
            let mut q = url.query_pairs_mut();
            if let Some(n) = page.number {
                q.append_pair("page[number]", &n.to_string());
            }
            if let Some(s) = page.size {
                q.append_pair("page[size]", &s.to_string());
            }
            if let Self::StructuredScopes { filters, .. } = self {
                if let Some(v) = filters.id_gt {
                    q.append_pair("filter[id__gt]", &v.to_string());
                }
                if let Some(v) = &filters.created_at_gt {
                    q.append_pair("filter[created_at__gt]", v);
                }
                if let Some(v) = &filters.updated_at_gt {
                    q.append_pair("filter[updated_at__gt]", v);
                }
            }
        }
        if url.query() == Some("") {
            url.set_query(None);
        }
        Ok(url)
    }
}
