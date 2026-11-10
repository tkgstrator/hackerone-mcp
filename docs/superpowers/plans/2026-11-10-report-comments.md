# Report Comments Implementation Plan

> **For agentic workers:** Use the existing Rust client and workflow patterns to implement this bounded task. Follow test-driven-development; the main agent owns live deployment and real API calls.

**Goal:** Prepare and post public report comments once, with durable receipts.

**Architecture:** Typed Customer API comment POST; account-bound local preview and claim using existing workflow storage. Preserve existing Hacker API tools and write opt-in.

**Tech Stack:** Rust, rmcp, reqwest, existing Tokio and wiremock tests.

**Spec:** `docs/superpowers/specs/2026-11-10-report-comments-design.md`

## Global Constraints

- No new dependencies, browser cookies, guessed endpoints, or automated live writes.
- Preserve unrelated files, existing local draft behavior and report submission.
- Official Customer API permissions may prevent the currently configured reporter token from sending.

## Review Focus

- Invalid IDs and blank/oversize/NUL messages fail before any network call.
- Exact preview/account/token matching prevents a different comment being sent.
- Concurrent calls, restarts and handler cancellation cannot resend a consumed attempt.
- Failed/ambiguous HTTP and invalid receipts retain a durable consumed state without quoting secrets.
- Documentation and tool inventory distinguish customer comments from researcher API compatibility.

### Task 1: Public comment tools

**Files:** Extend typed client endpoint/client POST modules and add focused client tests. Add a comments tool module plus tests, register it, and update tool inventories, README and package metadata if appropriate.

**Interfaces:** `report_comment_prepare(report_id, message)` returns the exact request preview, comment_id and confirmation_token. `report_comment_submit(comment_id, confirmation_token, confirm)` returns a durable receipt. `report_comment_get(comment_id)` reads that receipt without sending.

- [ ] Observe failing tests before implementation. Tests were written, but the Claude container had no Rust toolchain, so no RED run was observed. Do not claim a completed TDD cycle.
- [x] Implement the minimum typed POST and persistent workflow using existing patterns.
- [x] Run `cargo test --all-features --workspace --locked`, `cargo fmt --all -- --check` and `cargo clippy --all-targets --all-features --locked -- -D warnings` on the native Mac. All 206 unit tests and 7 stdio tests passed; formatting and Clippy passed after final fixes.
- [x] Update MCP guidance and stdio/smoke tool inventory. Explain Customer API permission requirements without implying Hacker API compatibility.
- [x] Report exact changed paths and verification outputs. Workers did not commit, push, deploy or send real API comments; the main agent handles those after evidence checks.
