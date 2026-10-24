#![forbid(unsafe_code)]
#[cfg(not(unix))]
compile_error!("hackerone-mcp supports Unix (macOS, Linux) only");

mod client;
mod config;
mod draft;
mod error;
mod tools;

use std::sync::Arc;

use rmcp::ServiceExt;
use rmcp::transport::stdio;

use crate::client::H1Client;
use crate::config::Config;
use crate::draft::DraftStore;
use crate::error::{Error, Result};
use crate::tools::HackerOneServer;

async fn run() -> Result<()> {
    let config = Config::from_env()?;
    let client = match &config.credentials {
        Some(c) => Some(Arc::new(H1Client::new(c)?)),
        None => {
            eprintln!("hackerone-mcp: no H1_USERNAME/H1_API_KEY set; API tools are disabled");
            None
        }
    };
    let drafts = Arc::new(DraftStore::open(config.drafts_dir)?);
    let service = HackerOneServer::new(client, drafts)
        .serve(stdio())
        .await
        .map_err(|e| Error::Config(format!("failed to start MCP server: {e}")))?;
    service
        .waiting()
        .await
        .map_err(|e| Error::Config(format!("MCP server terminated abnormally: {e}")))?;
    Ok(())
}

#[tokio::main]
async fn main() {
    if std::env::args()
        .skip(1)
        .any(|a| a == "--version" || a == "-V")
    {
        println!("hackerone-mcp {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if let Err(e) = run().await {
        eprintln!("hackerone-mcp: {e}");
        std::process::exit(1);
    }
}
