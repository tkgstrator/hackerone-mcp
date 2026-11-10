//! Reviewed local previews and one-shot public report comments (researcher GraphQL).

use super::HackerOneServer;
use crate::client::{graphql, validate_report_id};
use crate::draft::model::{MAX_BODY_BYTES, now_secs, random_token};
use crate::error::{Error, Result as H1Result};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

const GUIDANCE: &str = "This posts a PUBLIC (internal=false) comment within the report's existing audience through the HackerOne GraphQL API (https://hackerone.com/graphql) using your personal researcher API token. Only call report_comment_submit after showing the exact preview and receiving explicit user approval; a preview token is not proof of approval. Each comment_id is a single attempt, never retried; if uncertain, inspect HackerOne before preparing a new comment.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum State {
    Prepared,
    Attempting,
    Submitted,
    Unknown,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Comment {
    schema_version: u32,
    comment_id: String,
    account: String,
    state: State,
    report_id: String,
    message: String,
    request_body: String,
    confirmation_token: String,
    prepared_at: u64,
    attempted_at: Option<u64>,
    activity_id: Option<String>,
    failure: Option<String>,
}

fn validate_comment_id(id: &str) -> H1Result<()> {
    let ok = id.len() == 32
        && id.strip_prefix("comment-").is_some_and(|t| {
            t.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        });
    if ok {
        Ok(())
    } else {
        Err(Error::Validation("invalid comment_id".into()))
    }
}

/// Exact schema-1 (retired Customer REST) payload, kept to validate old ledgers.
fn legacy_request_body(message: &str) -> H1Result<String> {
    serde_json::to_string(
        &json!({"data":{"type":"activity-comment","attributes":{"message":message,"internal":false}}}),
    )
    .map_err(|_| Error::Draft("cannot serialize comment preview".into()))
}

const SCHEMA: u32 = 2;
const LEGACY_SCHEMA: u32 = 1;

fn expected_body(record: &Comment) -> H1Result<String> {
    match record.schema_version {
        SCHEMA => graphql::request_body(&record.report_id, &record.message),
        LEGACY_SCHEMA => legacy_request_body(&record.message),
        _ => Err(Error::Draft("unsupported comment ledger version".into())),
    }
}

fn transport(record: &Comment) -> &'static str {
    if record.schema_version == SCHEMA {
        "graphql"
    } else {
        "customer_rest_legacy"
    }
}

fn check_message(message: &str) -> H1Result<()> {
    if message.trim().is_empty() {
        return Err(Error::Validation("message must not be blank".into()));
    }
    if message.len() > MAX_BODY_BYTES {
        return Err(Error::Validation(format!(
            "message exceeds {MAX_BODY_BYTES} bytes"
        )));
    }
    if message.contains('\0') {
        return Err(Error::Validation("message contains NUL".into()));
    }
    Ok(())
}

fn decode(value: Value, id: &str) -> H1Result<Comment> {
    let bad = || Error::Draft("inconsistent comment ledger; refusing to reset it".into());
    let record: Comment = serde_json::from_value(value)
        .map_err(|_| Error::Draft("corrupt comment ledger; refusing to reset it".into()))?;
    let valid_token = record.confirmation_token.len() == 64
        && record
            .confirmation_token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !matches!(record.schema_version, SCHEMA | LEGACY_SCHEMA)
        || record.comment_id != id
        || record.account.is_empty()
        || !valid_token
        || check_message(&record.message).is_err()
        || (record.state == State::Prepared) != record.attempted_at.is_none()
        || (record.state == State::Submitted) != record.activity_id.is_some()
    {
        return Err(bad());
    }
    validate_report_id(&record.report_id)?;
    if record.request_body != expected_body(&record)? {
        return Err(bad());
    }
    if let Some(activity) = &record.activity_id {
        validate_report_id(activity)?;
    }
    Ok(record)
}

fn encode(record: &Comment) -> H1Result<Value> {
    serde_json::to_value(record).map_err(|_| Error::Draft("cannot serialize comment ledger".into()))
}

fn receipt(record: &Comment) -> Value {
    json!({"source":"local_comment", "untrusted_content":true, "guidance":GUIDANCE,
        "comment": {"comment_id":record.comment_id,"account":record.account,"state":record.state,"transport":transport(record),
            "report_id":record.report_id,"public":true,"prepared_at":record.prepared_at,"attempted_at":record.attempted_at,
            "activity_id":record.activity_id,"report_url":format!("https://hackerone.com/reports/{}", record.report_id),
            "outcome_uncertain":matches!(record.state, State::Attempting | State::Unknown),"failure":record.failure}})
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommentPrepareParams {
    /// Decimal report ID, no leading zeros.
    pub report_id: String,
    /// Exact public comment text (nonblank, no NUL, up to 200,000 UTF-8 bytes).
    pub message: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommentSubmitParams {
    pub comment_id: String,
    pub confirmation_token: String,
    /// Must be true only after the user explicitly approves the displayed preview.
    pub confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CommentGetParams {
    pub comment_id: String,
}

impl HackerOneServer {
    async fn comment_once(&self, p: CommentSubmitParams) -> H1Result<String> {
        let client = self.client.as_ref().ok_or_else(|| {
            Error::Config("H1_USERNAME and H1_API_KEY must be set to use API tools".into())
        })?;
        validate_comment_id(&p.comment_id)?;
        let account = client.account_username().to_owned();
        let id = p.comment_id.clone();
        let mut record = self.drafts.workflow_transaction(&id.clone(), None, move |old, _| {
            let mut record = decode(old.ok_or_else(|| Error::Validation("prepare a comment preview first".into()))?, &id)?;
            if record.schema_version != SCHEMA && record.state == State::Prepared {
                return Err(Error::Validation("this is a legacy Customer REST preview and cannot be sent over GraphQL; inspect report_comment_get and HackerOne, then prepare a new comment preview".into()));
            }
            if record.state != State::Prepared {
                return Err(Error::Validation("this comment_id already has a consumed attempt; inspect report_comment_get and HackerOne; never retry automatically".into()));
            }
            if record.account != account || record.confirmation_token != p.confirmation_token {
                return Err(Error::Validation("preview does not match the account or confirmation token; prepare and review again".into()));
            }
            record.state = State::Attempting;
            record.attempted_at = Some(now_secs());
            Ok((Some(encode(&record)?), record))
        }).await?;
        // A durable consumed claim exists now; no error path below can replay it.
        match client
            .post_report_comment(&record.report_id, record.request_body.clone())
            .await
        {
            Ok(response) => {
                record.activity_id = Some(
                    response["data"]["id"]
                        .as_str()
                        .ok_or_else(|| {
                            Error::Http("comment outcome uncertain; inspect HackerOne".into())
                        })?
                        .to_owned(),
                );
                record.state = State::Submitted;
            }
            Err(error) => {
                record.state = State::Unknown;
                record.failure = Some(error.to_string());
            }
        }
        let final_record = record.clone();
        let id = record.comment_id.clone();
        let saved = self
            .drafts
            .workflow_transaction(&id.clone(), None, move |old, _| {
                let previous = decode(
                    old.ok_or_else(|| {
                        Error::Draft("comment claim is missing; do not retry".into())
                    })?,
                    &id,
                )?;
                if previous.state != State::Attempting
                    || previous.confirmation_token != final_record.confirmation_token
                    || previous.account != final_record.account
                {
                    return Err(Error::Draft("comment claim changed; do not retry".into()));
                }
                Ok((Some(encode(&final_record)?), ()))
            })
            .await;
        if saved.is_err() {
            let known = record
                .activity_id
                .as_ref()
                .map(|id| format!(" Accepted activity ID: {id}."))
                .unwrap_or_default();
            return Err(Error::Draft(format!(
                "comment receipt could not be persisted; attempt remains consumed.{known} Inspect HackerOne before preparing a new comment."
            )));
        }
        serde_json::to_string(&receipt(&record))
            .map_err(|_| Error::Draft("cannot render comment receipt; do not retry".into()))
    }
}

#[tool_router(router = comment_router, vis = "pub(super)")]
impl HackerOneServer {
    #[tool(
        description = "Prepare a LOCAL exact preview of a PUBLIC (internal=false) report comment via researcher GraphQL, bound to this account. No request is sent. Show the complete message to the user and get explicit approval before report_comment_submit. Sending uses your personal researcher API token through GraphQL."
    )]
    pub async fn report_comment_prepare(
        &self,
        Parameters(p): Parameters<CommentPrepareParams>,
    ) -> Result<String, ErrorData> {
        validate_report_id(&p.report_id)?;
        check_message(&p.message)?;
        let account = self.h1()?.account_username().to_owned();
        let body = graphql::request_body(&p.report_id, &p.message)?;
        let token = super::submissions::token()?;
        let id = format!("comment-{}", random_token(24));
        let record = Comment {
            schema_version: SCHEMA,
            comment_id: id.clone(),
            account,
            state: State::Prepared,
            report_id: p.report_id,
            message: p.message,
            request_body: body,
            confirmation_token: token,
            prepared_at: now_secs(),
            attempted_at: None,
            activity_id: None,
            failure: None,
        };
        let value = encode(&record)?;
        self.drafts
            .workflow_transaction(&id, None, move |old, _| {
                if old.is_some() {
                    return Err(Error::Draft("comment ID collision; try again".into()));
                }
                Ok((Some(value), ()))
            })
            .await?;
        let body: Value = serde_json::from_str(&record.request_body)
            .map_err(|_| Error::Draft("cannot render preview".into()))?;
        super::api::render(
            &json!({"source":"local_comment_preview","untrusted_content":true,"never_sent":true,
            "guidance":GUIDANCE,"submission_enabled":self.allow_submit,"comment_id":record.comment_id,
            "account":record.account,"report_id":record.report_id,"public":true,"method":"POST","transport":"graphql","operation":graphql::OPERATION,
            "endpoint":graphql::ENDPOINT,
            "confirmation_token":record.confirmation_token,"request_body":body,"request_body_json":record.request_body}),
        )
    }

    #[tool(
        description = "Post an approved PUBLIC comment preview once, after explicit user approval. Requires H1_MCP_ALLOW_SUBMIT=true; uses researcher GraphQL. Legacy schema-1 previews are refused; prepare a new one.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    pub async fn report_comment_submit(
        &self,
        Parameters(p): Parameters<CommentSubmitParams>,
    ) -> Result<String, ErrorData> {
        if !self.allow_submit {
            return Err(Error::Config(
                "report comments are disabled; set H1_MCP_ALLOW_SUBMIT=true explicitly".into(),
            )
            .into());
        }
        if !p.confirm {
            return Err(Error::Validation(
                "confirm must be true after explicit user approval of the preview".into(),
            )
            .into());
        }
        self.h1()?;
        validate_comment_id(&p.comment_id)?;
        let server = self.clone();
        // Once authorized, keep recording the result even if the waiter is cancelled.
        let result = tokio::spawn(async move { server.comment_once(p).await })
            .await
            .map_err(|_| {
                Error::Draft("comment task interrupted; inspect receipt and HackerOne before preparing a new comment".into())
            })??;
        Ok(result)
    }

    #[tool(description = "Read a local report comment receipt without sending anything.")]
    pub async fn report_comment_get(
        &self,
        Parameters(p): Parameters<CommentGetParams>,
    ) -> Result<String, ErrorData> {
        validate_comment_id(&p.comment_id)?;
        let value = self
            .drafts
            .workflow_read(&p.comment_id)
            .await?
            .ok_or_else(|| {
                Error::Draft("no local comment preview or attempt for this ID".into())
            })?;
        super::api::render(&receipt(&decode(value, &p.comment_id)?))
    }
}

#[cfg(test)]
mod tests;
