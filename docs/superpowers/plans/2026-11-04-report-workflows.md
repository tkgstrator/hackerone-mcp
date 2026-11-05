# Report Workflows Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Add persistent report updates, local reply drafts, and preview-bound single-attempt report submission, release 0.4.0 and install its immutable image.

**Architecture:** Reuse the private DraftStore and its filesystem lock for bounded workflow records. Extend H1Client with one typed non-retrying POST; separate preview, claim, send and receipt phases. Keep report updates and reply storage independent of submission.

**Tech Stack:** Rust 2024, rmcp 3.8.0, reqwest, serde, wiremock. No new dependencies.

**Spec:** docs/superpowers/specs/2026-11-04-report-workflows-design.md

## Global Constraints

- Fixed https://api.hackerone.com origin; HTTP only in src/client. One POST attempt, no redirects or automatic retries.
- 0700 directory, 0600 bounded regular records, no symlink traversal, existing cross-process lock, durable claim before network.
- Explicit H1_MCP_ALLOW_SUBMIT=true; preview tokens never substitute for user approval.
- Version 0.4.0; exact 21 tools; do not send a real report/comment during development or installation.

## Review Focus

- Crash or ambiguous response after send must consume the attempt permanently, with actionable unknown status.
- Concurrent preparation, draft edits, repeated calls and multiple processes must never bypass preview binding or double-send a draft ID.
- Missing/partial activities must not erase previous observations or claim no response; baseline changes must be account-bound.
- Files manually edited into symlinks, oversized/nonregular/private-mode violations or corrupted ledgers must fail closed.
- Existing README/tool descriptions/guard tests must stop promising globally read-only behavior while retaining truthful local-only draft semantics.

### Task 1: Contract tests first

Files: tests/stdio_e2e.rs; additional tests colocated with the modules below.

- [ ] Add behavioral stdio assertions that compile against the existing binary and fail on missing report_updates, reply draft round trip and submission preview/status tools. Isolate H1_MCP_ALLOW_SUBMIT from inherited environment. Do not change production code yet.
- [ ] Codex runs the tests on studio and records the expected missing-tool failures.

### Task 2: Persistent follow-up and single-attempt submission

Files: src/draft/store.rs and a focused workflow persistence module; src/tools/reports plus focused updates/replies/submission modules; src/client/mod.rs and typed endpoint/helper module; src/config.rs; src/main.rs; src/tools/mod.rs; src/draft/validate.rs; src/tools/drafts/envelope.rs; existing/new tests.

Interfaces: DraftStore owns private record reads/atomic updates with closures under the same lock as draft mutation; server constructors retain a default-disabled constructor for tests and add explicit submission configuration. H1Client exposes the account username for local binding and one typed submit method returning a validated report response or sanitized uncertain error. Tool names/parameters and response guarantees follow the spec exactly.

- [ ] Add focused failing unit/mock tests for each boundary before its implementation; where Claude has no Rust toolchain, stop for Codex to run them or implement against the already observed behavioral red tests and report this limitation accurately.
- [ ] Implement report_updates snapshot and reply draft storage, preserving missing fields and account isolation. Compare activity objects by stable ID, with bounded storage.
- [ ] Implement prepare/claim/receipt ledger with atomic locking and strict record I/O. Claim rereads the draft and matches exact stored content/account/revision/token before durable consumption.
- [ ] Add configured submit capability and exactly-one POST method with sanitized errors. Valid successful response IDs are checked with existing validator.
- [ ] Add tool annotations, updated instructions and 21-tool guard/stdin/smoke coverage. Correct previous unconditional read-only promises everywhere relevant.
- [ ] Bump version to 0.4.0 and update README/Docker metadata. Keep dependencies unchanged.

### Task 3: Independent review, integration and release

Files: README.md, Cargo.toml/Cargo.lock, Dockerfile, scripts/docker-smoke.sh, .github/workflows/integration.yaml only where necessary; retained verification manifests outside tracked source.

- [ ] Codex runs cargo fmt --all -- --check, cargo test --locked and cargo clippy --all-targets --all-features --locked -- -D warnings; tie results to a source manifest.
- [ ] Fresh read-only Claude review of the actual diff + files (separate from implementer). Resolve and revalidate material findings. LocalGPT unavailable is disclosed; native independent review is the authorized alternate.
- [ ] Use canonical gh identity and guarded Git/checker, create/attach PR, wait for actual required CI passes, merge the reviewed head and publish v0.4.0 through the existing release workflow.
- [ ] Verify release artifacts, image digests and architectures. Atomically replace only the owned MCP image setting and add explicit submission opt-in; preserve secret file and draft volume.
- [ ] Verify real Docker stdio initialize/tool set/local workflow round trip/default submission preconditions and read-only Hacker API calls. No real POST. Report any client restart requirement based on observed current MCP tools.
- [ ] Save evidence and remove only the owned clean merged worktree/build outputs/test resources; preserve receipts, credentials, persistent drafts and shared images.
