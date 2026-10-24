//! The only module that builds or sends HTTP requests. GET only, fixed origin,
//! typed endpoints, bounded retries/pagination/response sizes.

mod endpoint;
mod retry;
#[cfg(test)]
mod tests;

use std::time::{Duration, Instant};

use reqwest::redirect::Policy;
use reqwest::{StatusCode, Url};
use serde_json::Value;

use crate::config::Credentials;
use crate::error::{Error, Result};
use endpoint::{Endpoint, MAX_PAGE_SIZE};
pub use endpoint::{PageParams, ScopeFilters};
use retry::{RetryPolicy, parse_retry_after};

const ORIGIN: &str = "https://api.hackerone.com";
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
const MAX_PAGES: usize = 20;
const MAX_TOTAL_BYTES: usize = 5 * 1024 * 1024;
const MIN_ATTEMPT_BUDGET: Duration = Duration::from_millis(5);
const SNIPPET_CHARS: usize = 200;

#[derive(Debug, Clone, Copy)]
struct Limits {
    response_bytes: usize,
    pages: usize,
    total_bytes: usize,
}

/// Items gathered across pages; `truncated` is set when a bound stopped paging.
#[derive(Debug)]
pub struct Paged {
    pub items: Vec<Value>,
    pub truncated: bool,
}

pub struct H1Client {
    http: reqwest::Client,
    username: String,
    api_key: String,
    origin: Url,
    retry: RetryPolicy,
    limits: Limits,
}

impl std::fmt::Debug for H1Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H1Client")
            .field("origin", &self.origin.as_str())
            .finish_non_exhaustive()
    }
}

impl H1Client {
    pub fn new(creds: &Credentials) -> Result<Self> {
        let origin = Url::parse(ORIGIN).map_err(|e| Error::Config(e.to_string()))?;
        Self::build(creds, origin, RetryPolicy::default(), Limits::production())
    }

    fn build(creds: &Credentials, origin: Url, retry: RetryPolicy, limits: Limits) -> Result<Self> {
        let http = reqwest::Client::builder()
            .user_agent(concat!("hackerone-mcp/", env!("CARGO_PKG_VERSION")))
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(retry.request_timeout)
            .build()
            .map_err(|_| Error::Config("failed to build HTTP client".into()))?;
        Ok(Self {
            http,
            username: creds.username.clone(),
            api_key: creds.api_key.clone(),
            origin,
            retry,
            limits,
        })
    }

    /// Test-only: point the client at a mock server with fast retries.
    #[cfg(test)]
    pub(crate) fn with_base_url(creds: &Credentials, base: &str) -> Result<Self> {
        let origin = Url::parse(base).map_err(|e| Error::Config(e.to_string()))?;
        let retry = RetryPolicy {
            backoff_base: Duration::from_millis(1),
            retry_after_cap: Duration::from_millis(50),
            ..RetryPolicy::default()
        };
        Self::build(creds, origin, retry, Limits::production())
    }

    pub async fn programs(&self, page: PageParams) -> Result<Value> {
        self.get_json(&Endpoint::Programs { page })
            .await
            .map(|r| r.0)
    }

    pub async fn program(&self, handle: &str) -> Result<Value> {
        self.get_json(&Endpoint::Program { handle })
            .await
            .map(|r| r.0)
    }

    pub async fn structured_scopes(
        &self,
        handle: &str,
        page: PageParams,
        filters: &ScopeFilters,
    ) -> Result<Value> {
        self.get_json(&Endpoint::StructuredScopes {
            handle,
            page,
            filters,
        })
        .await
        .map(|r| r.0)
    }

    pub async fn weaknesses(&self, handle: &str, page: PageParams) -> Result<Value> {
        self.get_json(&Endpoint::Weaknesses { handle, page })
            .await
            .map(|r| r.0)
    }

    pub async fn scope_exclusions(&self, handle: &str) -> Result<Value> {
        self.get_json(&Endpoint::ScopeExclusions { handle })
            .await
            .map(|r| r.0)
    }

    /// All structured scopes, bounded by page and byte limits. `links.next` is never followed.
    pub async fn structured_scopes_all(&self, handle: &str) -> Result<Paged> {
        let filters = ScopeFilters::default();
        self.collect_pages(|number| Endpoint::StructuredScopes {
            handle,
            page: PageParams {
                number: Some(number),
                size: Some(MAX_PAGE_SIZE),
            },
            filters: &filters,
        })
        .await
    }

    /// All weaknesses, bounded by page and byte limits.
    pub async fn weaknesses_all(&self, handle: &str) -> Result<Paged> {
        self.collect_pages(|number| Endpoint::Weaknesses {
            handle,
            page: PageParams {
                number: Some(number),
                size: Some(MAX_PAGE_SIZE),
            },
        })
        .await
    }

    async fn collect_pages<'a>(&self, make: impl Fn(u32) -> Endpoint<'a>) -> Result<Paged> {
        let mut items = Vec::new();
        let mut total = 0usize;
        let mut truncated = false;
        for i in 0..self.limits.pages {
            let number = u32::try_from(i + 1).unwrap_or(u32::MAX);
            let (body, len) = self.get_json(&make(number)).await?;
            total += len;
            if total > self.limits.total_bytes {
                truncated = true;
                break;
            }
            let page_items = body
                .get("data")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let n = page_items.len();
            items.extend(page_items);
            if n < MAX_PAGE_SIZE as usize {
                return Ok(Paged { items, truncated });
            }
            if i + 1 == self.limits.pages {
                truncated = true;
            }
        }
        Ok(Paged { items, truncated })
    }

    /// GET with bounded retries. Returns parsed JSON and the body size.
    async fn get_json(&self, ep: &Endpoint<'_>) -> Result<(Value, usize)> {
        let url = ep.url(&self.origin)?;
        let started = Instant::now();
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let remaining = self.retry.total_cap.saturating_sub(started.elapsed());
            if remaining < MIN_ATTEMPT_BUDGET {
                return Err(budget_exhausted());
            }
            let budget = remaining.min(self.retry.request_timeout);
            let outcome = match tokio::time::timeout(budget, self.attempt(&url)).await {
                Ok(o) => o,
                Err(_) if budget == remaining => return Err(budget_exhausted()),
                Err(_) => Err(Failure::Retryable(
                    Error::Http("request timed out".into()),
                    None,
                )),
            };
            let (err, retry_after) = match outcome {
                Ok(v) => return Ok(v),
                Err(Failure::Fatal(e)) => return Err(e),
                Err(Failure::Retryable(e, ra)) => (e, ra),
            };
            if attempt >= self.retry.max_attempts {
                return Err(err);
            }
            let delay = self.retry.delay(attempt, retry_after);
            if started.elapsed() + delay >= self.retry.total_cap {
                return Err(err);
            }
            tokio::time::sleep(delay).await;
        }
    }

    async fn attempt(&self, url: &Url) -> std::result::Result<(Value, usize), Failure> {
        let resp = self
            .http
            .get(url.clone())
            .basic_auth(&self.username, Some(&self.api_key))
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| {
                let what = if e.is_timeout() {
                    "request timed out"
                } else if e.is_connect() {
                    "connection failed"
                } else {
                    "request failed"
                };
                let err = Error::Http(what.into());
                if e.is_timeout() || e.is_connect() {
                    Failure::Retryable(err, None)
                } else {
                    Failure::Fatal(err)
                }
            })?;
        let status = resp.status();
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(parse_retry_after);
        let body = self.read_body(resp).await.map_err(Failure::Fatal)?;
        if status.is_success() {
            let value = serde_json::from_slice(&body)
                .map_err(|_| Failure::Fatal(Error::Http("response was not valid JSON".into())))?;
            return Ok((value, body.len()));
        }
        let err = Error::Http(format!(
            "status {} {}",
            status.as_u16(),
            self.snippet(&body)
        ));
        if status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            Err(Failure::Retryable(err, retry_after))
        } else {
            Err(Failure::Fatal(err))
        }
    }

    async fn read_body(&self, mut resp: reqwest::Response) -> Result<Vec<u8>> {
        let cap = self.limits.response_bytes;
        let too_big = || Error::Http(format!("response exceeded {cap} bytes"));
        if resp.content_length().is_some_and(|l| l > cap as u64) {
            return Err(too_big());
        }
        let mut buf = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|_| Error::Http("failed reading response body".into()))?
        {
            if buf.len() + chunk.len() > cap {
                return Err(too_big());
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(buf)
    }

    /// Short body excerpt with credentials removed and control characters stripped.
    fn snippet(&self, body: &[u8]) -> String {
        let mut text = String::from_utf8_lossy(body).into_owned();
        for secret in [&self.api_key, &self.username] {
            if !secret.is_empty() {
                text = text.replace(secret.as_str(), "<redacted>");
            }
        }
        text.chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .take(SNIPPET_CHARS)
            .collect()
    }
}

fn budget_exhausted() -> Error {
    Error::Http("request budget exhausted (total time cap reached)".into())
}

enum Failure {
    Retryable(Error, Option<Duration>),
    Fatal(Error),
}

impl Limits {
    const fn production() -> Self {
        Self {
            response_bytes: MAX_RESPONSE_BYTES,
            pages: MAX_PAGES,
            total_bytes: MAX_TOTAL_BYTES,
        }
    }
}
