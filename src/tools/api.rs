//! Helpers shared by every tool that calls the HackerOne API.

use rmcp::ErrorData;
use serde_json::{Value, json};

use super::HackerOneServer;
use crate::client::{H1Client, PageParams};
use crate::error::Error;

pub fn render(v: &Value) -> Result<String, ErrorData> {
    serde_json::to_string(v).map_err(|e| ErrorData::internal_error(e.to_string(), None))
}

/// Wrap API-derived data. Server-generated guidance must go outside `data`.
pub fn envelope(endpoint: &str, data: Value) -> Value {
    json!({
        "source": "hackerone_api",
        "untrusted_content": true,
        "endpoint": endpoint,
        "data": data,
    })
}

pub fn page(number: Option<u32>, size: Option<u32>) -> PageParams {
    PageParams { number, size }
}

impl HackerOneServer {
    pub(super) fn h1(&self) -> Result<&H1Client, ErrorData> {
        self.client.as_deref().ok_or_else(|| {
            Error::Config("H1_USERNAME and H1_API_KEY must be set to use API tools".into()).into()
        })
    }
}
