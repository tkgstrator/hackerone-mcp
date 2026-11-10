# GraphQL Comments Implementation Plan

> **For agentic workers:** Use existing client/workflow patterns. Main runs native Mac checks because the Claude container has no Rust toolchain. Main handles commit, runtime deployment and the authorized live send.

**Goal:** Post the requested Rush clarification using researcher-token GraphQL.

**Architecture:** Fixed GraphQL comment mutation with Bearer credentials; offline exact previews and schema-2 ledgers; preserved read-only schema-1 receipts.

**Tech Stack:** Existing Rust/reqwest/rmcp, locked base64 crate, wiremock.

**Spec:** `docs/superpowers/specs/2026-11-10-graphql-comments-design.md`

## Global Constraints

- Fixed origins, fixed mutation, no cookies or Customer REST fallback.
- Preserve no-retry durable claims, opt-in, confirmation, and old receipts.
- Never expose credential values or raw API/GraphQL errors.

## Review Focus

- GraphQL HTTP 200 errors cannot count as success.
- The mutation uses the actual report global-ID convention and exact public text.
- REST Basic auth remains unchanged while GraphQL uses Bearer base64 credentials.
- Old previews cannot be silently submitted over a new transport.
- Concurrent requests/cancellation/storage failures cannot create retries or lose known accepted activity IDs.

### Task 1: Correct the comment transport

**Files:** `src/client/mod.rs`, focused GraphQL client code/tests under `src/client/`, `src/tools/comments.rs` and its tests, MCP descriptions/README, Cargo package metadata.

- [x] Worker writes only test changes first; preserve current production code.
- [x] Main runs native tests and records expected GraphQL transport/preview failures (202 passed, 11 failed; compiled successfully). Corrected fixture requirements use actual Base64 node IDs instead of raw gid URIs.
- [x] Worker implements the fixed mutation, authentication, receipt validation and legacy-ledger compatibility. The implementation job ended with a WebFetch permission denial; main inspected the actual saved changes, ran native checks, and delegated two focused validation fixes. Final native tests: 214 unit + 7 stdio passed; fmt and Clippy passed.
- [x] Main runs cargo test --all-features --workspace --locked, cargo fmt --all -- --check, cargo clippy --all-targets --all-features --locked -- -D warnings, Docker build and smoke. Final result: 214 unit + 7 stdio tests passed; Docker smoke exposed all 27 tools.
- [ ] Inspect actual final diff, commit with CommitGuard, replace only the HackerOne MCP container and verify existing state/security settings.
- [ ] Inspect complete current report activities, prepare the exact new GraphQL preview, send once through MCP, and verify the returned activity in a fresh report query.
