# Report comments

Add public report comments through the documented Customer API endpoint
`POST /v1/reports/{id}/activities`. The endpoint requires Customer API credentials
with Report Management permission. A working Hacker API token does not establish
that permission; a safe customer-report GET returned HTTP 401 with the currently
configured token. Do not invent a Hacker API comment endpoint or silently use
browser cookies.

Expose `report_comment_prepare(report_id, message)` for an account-bound local
preview, `report_comment_submit(comment_id, confirmation_token, confirm)` for one
attempt, and `report_comment_get(comment_id)` for its durable receipt. Public
means `internal: false` within the existing report audience, not disclosure of the
report. Preserve existing local reply drafts and report submission behavior.

Keep the exact prepared request bytes and account together with a random local
comment ID/token. Persist a consumed claim before sending; never automatically
retry a POST, including redirects, 401/403/429/5xx and transport failures. A waiting
handler cancellation must not lose receipt recording. Do not add dependencies or
accept arbitrary endpoints, methods, internal comments, or attachments. Reuse the
existing explicit remote-write opt-in instead of a second configuration flag.

Validate nonblank bounded messages without NUL, canonical report IDs and receipts.
Keep credentials and raw failed API bodies out of errors. Clearly report
authentication/permission failures; do not claim a comment was posted from a mock
test or a local preview. Successful results require a valid activity-comment ID.

The requested real comment is a short clarification that WAVE1 Rush also has an
enemy spawn direction that is never selected for its initial spawn. Do not add
unverified code offsets, direction names, empirical sample counts, or derivations.

Use the existing Rust client, workflow storage and MCP patterns. This dedicated
checkout was created for this task and has no unrelated changes. No API writes
belong in automated tests. Main agent verifies edits and handles live deployment
and the authorized real send. No additional external review is required for this
routine feature.
