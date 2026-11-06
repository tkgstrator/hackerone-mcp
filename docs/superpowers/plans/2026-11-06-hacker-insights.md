# Public activity insights implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded public-user activity analysis and disclosure trends to the MCP server.
**Architecture:** One typed Hacktivity endpoint feeds sanitized selected report metadata and pure cohort aggregations, exposed by three read-only MCP tools. Existing report submission and draft storage are unchanged.
**Tech Stack:** Rust 2024, rmcp 3.8, reqwest 0.13, serde_json, chrono 0.4.
**Spec:** docs/superpowers/specs/2026-11-06-hacker-insights-design.md

## Global constraints

- Rust floor 1.89; release 0.5.0; 24 tools total; official fixed-origin GET only.
- Per cohort max 10 pages / 500 items; trends max 20 pages / 1000 items. A SHARED 5 MiB input budget and 45-second deadline cover the whole tool; output 1 MiB.
- Partial/filtered/invalid data must disclose coverage; incomplete trend comparisons are null.
- Rewards are exact decimal report amounts, currency-aware or separated per unknown-currency program; never personal earnings.
- No commits by delegates. Codex owns guarded commits, integration, immutable-source verification and release.
- The spec's reviewed contract rulings are binding: arbitrary_precision JSON, all-filter local validation, terminal pagination rules, exact decimal bounds, unknown-program no sums, 10-group caps, explicit cohort labels and injectable limits/clock.

## Review focus

- API filters may be ignored/returned rows drift: local exact username/program/public/date eligibility.
- Public rewards may be missing, malformed, zero, shared or lack currency: explicit evidence and exact arithmetic.
- API dates may include offsets and invalid calendars: parse/normalize and distinguish submission from disclosure.
- Pagination may duplicate, overrun budget or fail late: bounded, no external links, incomplete comparisons suppressed.
- New metadata may contain huge/untrusted report text: selected fields only and output cap, unchanged POST boundary.

### Task 1: Typed Hacktivity client and query contract

Prerequisite by Codex: add chrono std and serde_json arbitrary_precision before delegation; observe RED then GREEN exact numeric-token test and run existing complete stdio/unit suites to rule out rmcp feature-unification regressions. Outer trend orchestration owns detailed comparison_unavailable_reasons; pure compare(false) emits generic incomplete_cohort.

Files: src/client/endpoint.rs, src/client/mod.rs, new src/client/hacktivity_tests.rs.
Interface: validated public `HacktivityFilters { username, program, cwe, severity_rating, disclosed_after, disclosed_before: Option<String> }`, `HacktivitySort` enum, `H1Client::hacktivity(page: PageParams, filters: &HacktivityFilters, sort: HacktivitySort) -> Result<(Value, usize)>` (crate-visible); no change to existing public operations. Filters expose `validate() -> Result<()>` and query construction in client, dates via shared crate-visible `parse_date(&str) -> Result<chrono::NaiveDate>`.

- [ ] Write mock URL/auth/filter/escaping/page/sort/validation tests, run RED.
- [ ] Implement typed endpoint/client method, exact encoded queryString and date/handle limits.
- [ ] Run focused tests GREEN; existing no-HTTP-outside-client guard remains intact.

### Task 2: Selected metadata and pure exact insights

Files: new src/tools/insights/{params.rs,model.rs,stats.rs,trends.rs,tests.rs}; Cargo.toml/Cargo.lock chrono addition coordinated by Codex.
Interface: `model::select(raw: &Value, filters: &HacktivityFilters) -> Result<Record, SelectionError>`; SelectionError distinguishes invalid vs excluded. `Record` is Serialize with bounded public fields; helpers `stats::summarize(records: &[Record]) -> Value` and `trends::compare(current: &[Record], previous: &[Record], comparable: bool) -> Value`. Pure helpers handle date/selection, monthly UTC cadence, exact grouped rewards and cohort-qualified group comparisons. Codex owns collector dedup/coverage. Record interface is defined before parallel work. Money can be kept private to the model/stats modules.

- [ ] Fixture tests RED for all review focus cases, including exact decimal median and unknown currency isolation.
- [ ] Implement minimal date/selection/aggregation helpers; do not implement guessed profile metrics.
- [ ] Run focused fixtures GREEN. Return concrete evidence and changed paths to coordinator.

### Task 3: MCP orchestration and integration

Files: new src/tools/insights/mod.rs and collect.rs; src/tools/mod.rs, src/tools/guard_tests.rs, tests/stdio_e2e.rs, scripts/docker-smoke.sh, README.md, Cargo.toml/Cargo.lock.
Interface: the three named tools and bounds in spec, read-only annotations and API envelopes. Collector uses monotonically generated page numbers and shared deadline with explicit coverage; source requests and retrieved time included.

`InsightLimits` permits deadline/input/output/now injection in private helpers. All-filter mismatch, inconsistent short-page-next, later window failure, output trimming and decimal JSON lexeme cases are mandatory regression fixtures.

- [ ] Stdio registration/missing-credential and mock partial/deadline/byte/output tests RED.
- [ ] Implement collection/tools and update exact tool lists, docs and 0.5.0 version.
- [ ] Native fmt/test/strict clippy, inspect actual diff, freeze source manifest.
- [ ] Fresh independent actual-files reviews and material fixes; revalidate affected behavior.

### Task 4: PR and release

- [ ] Guarded local commits and actual OID validation; native online push preflight; create and attach PR.
- [ ] Verify actual CI on immutable head; merge authorized PR normally, preserve GitHub merge object.
- [ ] Await successful release CI; verify v0.5.0 archives/checksums, multiarch GHCR digest and OCI revision.
- [ ] Pull immutable image, update only registered image reference, verify 24 tools/new GET operations and prior local operations. No POST.
- [ ] Clean owned cache/worktree and disposable verification resources; retain evidence. Current chat reload is distinct from installed-runtime verification.
