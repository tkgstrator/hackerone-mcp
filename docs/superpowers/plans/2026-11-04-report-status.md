# Submitted report inspection implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Inspect submitted reports, their states, replies, and bounty records through two read-only MCP tools.

**Architecture:** Extend the typed endpoint/client layer and add a reports tool router. Share the existing API envelope and credential check; preserve existing behavior.

**Tech Stack:** Rust 2024 (MSRV 1.89), reqwest, rmcp, wiremock; existing locked dependencies.

**Spec:** `docs/superpowers/specs/2026-11-04-report-status-design.md`

## Global constraints

- GET-only, fixed production origin `https://api.hackerone.com`, existing limits and redirect policy.
- `report_id`: string matching `[1-9][0-9]{0,19}`; page 1–1000 and page_size 1–100.
- Preserve API data, nulls and timestamps inside the existing untrusted-content envelope.
- Exactly 15 tools; no writes/submission or new dependencies; version 0.3.0.
- No real report contents, credentials, or private account data in tracked fixtures.

## Review focus

- Report routes must not accidentally inherit the `/programs` path prefix.
- Empty, zero, leading-zero, signed, non-ASCII, overlong, and path-like IDs must fail without requests.
- Missing credentials and 401/403/404 must remain errors, never empty successful status results.
- Null timestamps, unknown states, and absent replies/bounties must not create implied outcomes.
- Existing program requests, local drafts, and Docker/stdin tool discovery must remain compatible.

### Task 1: Endpoint, tools, and release wiring

**Files:** `src/client/{endpoint.rs,mod.rs,tests.rs}`, new `src/tools/reports/{mod.rs,tests.rs}`, shared tool helper location under `src/tools/`, `src/tools/{mod.rs,guard_tests.rs}`, affected program helper imports, `tests/stdio_e2e.rs`, `scripts/docker-smoke.sh`, README, Cargo.toml/Cargo.lock.

**Interfaces:** `H1Client::reports(PageParams) -> Result<Value>`, `H1Client::report(&str) -> Result<Value>`; `report_list` and `report_get` JSON tools as specified. Endpoint labels `reports` and `report` follow existing plural/singular conventions.

**Integration decisions:** Make the endpoint base segments variant-specific: reports list uses `[v1,hackers,me,reports]`, individual report uses `[v1,hackers,reports]` plus the validated ID; existing program paths remain unchanged. Validate report IDs in the typed client endpoint, before transport. Move shared credentials/envelope/render/pagination helpers into `src/tools/api.rs` (or the parent tools module where simpler), retaining the existing credential-error substring `H1_USERNAME and H1_API_KEY` and generalizing it to all API tools. Do not import reports through a private program-only helper. Extend exact GET-path coverage and prove invalid report input generates zero mock requests. Both report tools need no-credentials stdio coverage; Docker smoke should verify their names as well as the count. Test the existing response-size limit on a report response. HackerOne's report reference explicitly documents `submitted_at` as authoritative (https://api.hackerone.com/hacker-reference/#report).

- [ ] Add failing client/tool/stdio tests first. Fixtures use synthetic reports with state, submitted_at, null triaged_at, one comment, and bounties. Assert the raw fields survive the envelope, invalid input makes no HTTP request, missing credentials fails, and 401/403/404 propagate. Add exact 15-tool discovery expectations.
- [ ] Codex runs the new targeted tests on the Mac and records the expected failing result before implementation. Claude's container has source access but no Rust toolchain; do not install one there.
- [ ] Implement the two typed GET endpoints, validation, client methods and reports router, sharing credential/envelope helpers with program tools. Update server instructions for untrusted report/comment text.
- [ ] Update smoke/README tool count, examples and 0.3.0 package version/own lock entry. Do not update dependencies or unrelated lock entries.
- [ ] Codex runs `cargo fmt --all -- --check`, targeted/full `cargo test --all-features --workspace --locked`, and `cargo clippy --all-targets --all-features --locked -- -D warnings`. Use one owned native target directory and retain bounded logs tied to a source manifest.
- [ ] Independent read-only Claude reviewer inspects the actual diff and current files against this spec and relevant gates. Resolve material findings and rerun affected checks.
- [ ] Commit through installed guarded Git with verified identity and native checker; create and attach PR, inspect every CI gate, merge under standing authorization, and await the release workflow.
- [ ] Verify release 0.3.0/tag, GHCR digest/platforms, released tool discovery, `report_list` and `report_get` using saved credentials; print metadata only. Update the registered Docker image without exposing keys. Record setup state and clean owned temporary containers/builds/worktree after integration.
