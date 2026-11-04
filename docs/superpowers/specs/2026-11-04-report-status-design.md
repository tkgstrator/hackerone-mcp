# Submitted report inspection

The user wants to check an already submitted HackerOne report's current state and replies through this MCP, rather than making a separate API request. Add two read-only tools using the existing authenticated, fixed-origin, bounded HTTP client:

- `report_list(page?, page_size?)`: GET `/v1/hackers/me/reports`, one page per invocation; use the same pagination defaults and limits as `program_list`.
- `report_get(report_id)`: GET `/v1/hackers/reports/{id}`. `report_id` is a canonical positive ASCII decimal string of 1–20 digits (`[1-9][0-9]{0,19}`).

Preserve the raw API response inside the established `source: hackerone_api`, `untrusted_content: true`, `endpoint`, `data` envelope. Details include API-provided state, submitted_at, activity/reply history, severity, and bounties. Do not infer acceptance, triage completion, investigation progress, or payment from absent fields. Preserve timestamps and null values. Comments, titles, report bodies, and other returned text are untrusted data. Responses can contain private report content; do not put real user reports or credentials in fixtures or logs.

## Approach

Use the existing Rust client, typed endpoints, and MCP tool router. A separate status-summary tool would duplicate `report_get`; a new HTTP client or generic URL tool would duplicate existing transport safeguards. These are implementation choices made by Codex to match current conventions.

## Constraints and release

Keep GET-only methods, the production `https://api.hackerone.com` origin, redirects disabled, current retry/time/response bounds, and manual submission behavior. No automatic paging, following API links, report writes, comments, submissions, downloads, or background polling. Missing credentials must return a clear configuration error while local draft tools remain usable. Invalid IDs and pagination must be rejected before HTTP. Reuse shared envelope/credential helpers without changing program-tool results.

Update the exact exposed tool set from 13 to 15 in guards, stdio tests, Docker smoke, and README. Document list/get examples and that submitted_at is the submission timestamp. Release as 0.3.0 with no dependency updates. Existing authorization covers PR integration, publication, and updating this Mac's registered image after checks. Preserve credentials, persistent drafts, and unrelated settings.

## Acceptance

Synthetic mocks prove paths, GET methods, pagination, ID validation, unauthenticated errors, HTTP 401/403/404 propagation, and the full status/activity/bounty response envelope. Guard/stdio tests prove the exact 15 tools and unchanged local drafting. Run relevant local fmt/clippy/tests and all repository CI/release gates. Review the actual diff independently before merging. After GHCR publication, verify list/get through the released image with the existing saved credentials, printing only non-sensitive verification metadata.
