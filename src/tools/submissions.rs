//! Reviewed local previews and one-shot report submission.

use super::HackerOneServer;
use crate::draft::model::{Stored, check_body, now_secs, validate_id};
use crate::draft::validate::validate;
use crate::error::{Error, Result as H1Result};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{ErrorData, tool, tool_router};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::Read;

const GUIDANCE: &str = "Only call report_submit after showing the exact preview and receiving explicit user approval. A preview token is not proof of human approval. Submission is a single attempt per draft ID. If an attempt is uncertain, inspect HackerOne before any new submission; copying to a different draft ID bypasses this local guard and can create duplicates.";

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
struct Submission {
    schema_version: u32,
    draft_id: String,
    account: String,
    state: State,
    stored: Stored,
    request_body: String,
    confirmation_token: String,
    prepared_at: u64,
    attempted_at: Option<u64>,
    report_id: Option<String>,
    failure: Option<String>,
}

fn key(id: &str) -> H1Result<String> {
    validate_id(id)?;
    Ok(format!("submit-{id}"))
}

fn payload(stored: &Stored) -> H1Result<(String, Vec<String>)> {
    check_body(&stored.body)?;
    stored.draft.validate_fields()?;
    let report = validate(&stored.draft, &stored.body);
    if !report.valid {
        return Err(Error::Validation(format!(
            "draft is incomplete: {}",
            report.errors.join("; ")
        )));
    }
    crate::client::validate_handle(stored.draft.team_handle.as_deref().unwrap_or(""))?;
    let body = serde_json::to_string(&report.request_body_preview["body"])
        .map_err(|_| Error::Draft("cannot serialize submission preview".into()))?;
    Ok((body, report.warnings))
}

fn decode(value: Value, id: &str) -> H1Result<Submission> {
    let record: Submission = serde_json::from_value(value)
        .map_err(|_| Error::Draft("corrupt submission ledger; refusing to reset it".into()))?;
    let valid_token = record.confirmation_token.len() == 64
        && record
            .confirmation_token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if record.schema_version != 1
        || record.draft_id != id
        || record.stored.draft.id != id
        || record.account.is_empty()
        || !valid_token
        || (record.state == State::Prepared && record.request_body != payload(&record.stored)?.0)
        || (record.state == State::Prepared) != record.attempted_at.is_none()
        || (record.state == State::Submitted) != record.report_id.is_some()
    {
        return Err(Error::Draft(
            "inconsistent submission ledger; refusing to reset it".into(),
        ));
    }
    if let Some(report_id) = &record.report_id {
        crate::client::validate_report_id(report_id)?;
    }
    Ok(record)
}

fn encode(record: &Submission) -> H1Result<Value> {
    serde_json::to_value(record)
        .map_err(|_| Error::Draft("cannot serialize submission ledger".into()))
}

fn token() -> H1Result<String> {
    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| Error::Draft("cannot obtain secure preview identifier".into()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn receipt(record: &Submission) -> Value {
    json!({"source":"local_submission", "untrusted_content":true, "guidance":GUIDANCE,
        "submission": {"draft_id":record.draft_id,"account":record.account,"state":record.state,
            "revision":record.stored.draft.revision,"prepared_at":record.prepared_at,"attempted_at":record.attempted_at,
            "report_id":record.report_id,"report_url":record.report_id.as_ref().map(|id|format!("https://hackerone.com/reports/{id}")),
            "outcome_uncertain":matches!(record.state, State::Attempting | State::Unknown),"failure":record.failure}})
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrepareParams {
    /// Local draft ID to preview.
    pub draft_id: String,
    /// Exact current draft revision, required to prevent stale approvals.
    pub expected_revision: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SubmitParams {
    pub draft_id: String,
    pub expected_revision: u64,
    pub confirmation_token: String,
    /// Must be true only after the user explicitly approves the displayed preview.
    pub confirm: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StatusParams {
    pub draft_id: String,
}

impl HackerOneServer {
    async fn submit_once(&self, p: SubmitParams) -> H1Result<String> {
        let client = self.client.as_ref().ok_or_else(|| {
            Error::Config("H1_USERNAME and H1_API_KEY must be set to use API tools".into())
        })?;
        let account = client.account_username().to_owned();
        let ledger_key = key(&p.draft_id)?;
        let id = p.draft_id.clone();
        let mut record = self.drafts.workflow_transaction(&ledger_key, Some(&p.draft_id), move |old, stored| {
            let mut record = decode(old.ok_or_else(||Error::Validation("prepare a report preview first".into()))?, &id)?;
            if record.state != State::Prepared {
                return Err(Error::Validation("this draft ID already has a consumed submission attempt; inspect report_submission_get and HackerOne; never retry automatically".into()));
            }
            let stored = stored.ok_or_else(||Error::Draft("draft is missing".into()))?;
            if record.account != account || record.stored != stored || record.stored.draft.revision != p.expected_revision || record.confirmation_token != p.confirmation_token {
                return Err(Error::Validation("preview no longer matches the account, draft, revision or confirmation token; prepare and review again".into()));
            }
            payload(&stored)?;
            record.state = State::Attempting;
            record.attempted_at = Some(now_secs());
            Ok((Some(encode(&record)?), record))
        }).await?;
        // A durable consumed claim exists now; no error path below can replay it.
        let outcome = client.submit_report(record.request_body.clone()).await;
        match outcome {
            Ok(response) => {
                record.report_id = Some(
                    response["data"]["id"]
                        .as_str()
                        .ok_or_else(|| {
                            Error::Http("submission outcome uncertain; inspect HackerOne".into())
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
        let id = record.draft_id.clone();
        let saved = self
            .drafts
            .workflow_transaction(&ledger_key, None, move |old, _| {
                let previous = decode(
                    old.ok_or_else(|| {
                        Error::Draft("submission claim is missing; do not retry".into())
                    })?,
                    &id,
                )?;
                if previous.state != State::Attempting
                    || previous.confirmation_token != final_record.confirmation_token
                    || previous.account != final_record.account
                {
                    return Err(Error::Draft(
                        "submission claim changed; do not retry".into(),
                    ));
                }
                Ok((Some(encode(&final_record)?), ()))
            })
            .await;
        if saved.is_err() {
            let known = record
                .report_id
                .as_ref()
                .map(|id| format!(" Accepted report: https://hackerone.com/reports/{id}."))
                .unwrap_or_default();
            return Err(Error::Draft(format!(
                "submission receipt could not be persisted; attempt remains consumed.{known} Inspect HackerOne before any new submission."
            )));
        }
        serde_json::to_string(&receipt(&record))
            .map_err(|_| Error::Draft("cannot render submission receipt; do not retry".into()))
    }
}

#[tool_router(router = submission_router, vis = "pub(super)")]
impl HackerOneServer {
    #[tool(
        description = "Prepare a LOCAL exact request preview for an existing draft/revision, bound to this HackerOne account. No POST occurs. Show recipient and complete body to the user and receive explicit approval before report_submit. A preview token does not prove approval."
    )]
    pub async fn report_submit_prepare(
        &self,
        Parameters(p): Parameters<PrepareParams>,
    ) -> Result<String, ErrorData> {
        let account = self.h1()?.account_username().to_owned();
        let ledger_key = key(&p.draft_id)?;
        let id = p.draft_id.clone();
        let record = self.drafts.workflow_transaction(&ledger_key, Some(&p.draft_id), move |old, stored| {
            if let Some(old) = old {
                let previous = decode(old, &id)?;
                if previous.state != State::Prepared {
                    return Err(Error::Validation("this draft ID already has a consumed attempt; inspect HackerOne before any new submission".into()));
                }
            }
            let stored = stored.ok_or_else(||Error::Draft("draft is missing".into()))?;
            if stored.draft.revision != p.expected_revision { return Err(Error::Validation("draft revision changed; review the current draft".into())); }
            let request_body = payload(&stored)?.0;
            let record = Submission {schema_version:1,draft_id:id,account,state:State::Prepared,stored,request_body,
                confirmation_token:token()?,prepared_at:now_secs(),attempted_at:None,report_id:None,failure:None};
            Ok((Some(encode(&record)?), record))
        }).await?;
        let body: Value = serde_json::from_str(&record.request_body)
            .map_err(|_| Error::Draft("cannot render preview".into()))?;
        super::api::render(
            &json!({"source":"local_submission_preview","untrusted_content":true,"never_sent":true,
            "guidance":GUIDANCE,"submission_enabled":self.allow_submit,"draft_id":record.draft_id,"revision":record.stored.draft.revision,
            "account":record.account,"team_handle":record.stored.draft.team_handle,"method":"POST","endpoint":"https://api.hackerone.com/v1/hackers/reports",
            "confirmation_token":record.confirmation_token,"request_body":body,"request_body_json":record.request_body,
            "warnings":payload(&record.stored)?.1}),
        )
    }

    #[tool(
        description = "Submit an approved preview once, after explicit user approval.",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    pub async fn report_submit(
        &self,
        Parameters(p): Parameters<SubmitParams>,
    ) -> Result<String, ErrorData> {
        if !self.allow_submit {
            return Err(Error::Config(
                "report submission is disabled; set H1_MCP_ALLOW_SUBMIT=true explicitly".into(),
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
        key(&p.draft_id)?;
        let server = self.clone();
        // Once authorized, keep recording the result even if the waiter is cancelled.
        let result = tokio::spawn(async move {server.submit_once(p).await}).await.map_err(|_|Error::Draft("submission task interrupted; inspect receipt and HackerOne before any new submission".into()))??;
        Ok(result)
    }

    #[tool(description = "Read a local submission receipt without sending anything.")]
    pub async fn report_submission_get(
        &self,
        Parameters(p): Parameters<StatusParams>,
    ) -> Result<String, ErrorData> {
        let value = self
            .drafts
            .workflow_read(&key(&p.draft_id)?)
            .await?
            .ok_or_else(|| {
                Error::Draft("no local submission preview or attempt for this draft ID".into())
            })?;
        super::api::render(&receipt(&decode(value, &p.draft_id)?))
    }
}

#[cfg(test)]
mod tests;
