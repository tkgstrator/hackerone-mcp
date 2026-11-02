# iOS Program Discovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Discover iOS programs using published eligibility data with bounded pagination and explicit uncertainty.

**Architecture:** Add one derived MCP tool over the existing Hacker API client. Keep filtering and JSON projection in a focused discovery module; retain all HTTP construction inside the client.

**Tech Stack:** Rust 2024, existing rmcp, serde_json, tokio and wiremock; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-11-02-ios-program-discovery-design.md`

## Global Constraints

- Fixed-origin GET requests only; no redirects or response-provided URL following.
- No remote reports, asset probing, weakness scores, new dependencies or credentials.
- Preserve existing interfaces and mark returned source text untrusted.
- iOS types: `APPLE_STORE_APP_ID`, `TESTFLIGHT`, `OTHER_IPA`.
- Defaults: page 1, page_size 5; ranges: 1..=1000 and 1..=10. Three boolean filters default true.
- Scope budget: 3 pages of 100 per program, sequential requests, 45-second overall deadline, 5 MiB aggregate-output ceiling.
- `bounty_amount_status=not_available_in_hacker_api`; no inferred numeric amounts.

## Review Focus

- Empty filtered results must retain source pagination.
- Missing flags remain unknown and cannot satisfy true eligibility filters.
- iOS assets after scope page one must be found; unvisited pages remain incomplete.
- Failed/timed-out programs must not erase successes or masquerade as having no iOS assets.
- Malformed collections, remote handles and source text cannot alter request origin or become valid complete data.

## Task 1: Implement bounded iOS discovery

**Files:**
- Create `src/tools/programs/discovery.rs` and focused discovery tests (a separate test module is permitted).
- Modify `src/tools/programs/params.rs`, `src/tools/programs/mod.rs`, and `src/client/mod.rs` with relevant client tests for a smaller scope-page budget.
- Modify `src/tools/guard_tests.rs`, `tests/stdio_e2e.rs`, `README.md` and other explicit tool-count assertions.

**Interfaces:**
- `DiscoverParams`: optional page/page_size and public_only/accepting_submissions_only/bounty_only.
- `HackerOneServer::program_discover(Parameters<DiscoverParams>) -> Result<String, ErrorData>`.
- Reuse `H1Client::programs`, validated scope endpoints and `Paged`; add a bounded-scope helper without changing existing callers' limits.
- Derived envelope includes timestamp, sources, filters, source-page continuation, candidates and incomplete-program reasons. Scope projection retains instruction, updated_at and both flags. Internal helper names are implementation choices.

- [x] Write and run a focused failing test for default filters and all three iOS types; record the expected failure before implementation.
- [x] Implement validation before requests, local program/scope filtering, and null preservation.
- [x] Test relaxed filters, missing flags, no credentials, invalid input, invalid upstream handles and malformed collections.
- [x] Test full source pages with no candidates retaining continuation, short last pages stopping, iOS only on scope page two, and scope limits yielding incomplete data without following supplied links.
- [x] Test partial results on one program error, deadline exhaustion and output limit; keep successes and explicit reasons.
- [x] Assert source/timestamp/unknown-bounty fields and preserve malicious-looking source text as data.
- [x] Register the tool, update router/stdio assertions and README examples including continuation and eligibility-versus-price limitations.
- [x] Run focused tests while iterating; finish with `cargo test --all-features --workspace --locked`, `cargo fmt --all -- --check`, and `cargo clippy --all-targets --all-features --locked -- -D warnings`.
- [x] Self-review and commit with a Conventional Commit message. Write a report with red/green evidence and limitations.
