# iOS program discovery

## Intent and approach

The user requested a PR to make comparing HackerOne iOS programs easier. Existing tools already read programs and scopes. Add one bounded discovery tool using the existing Rust/rmcp server and official Hacker API. Inspect a small source-program page per invocation and report continuation and incomplete coverage.

Alternatives considered: browser scraping couples the server to sessions and unstable markup; another raw list leaves scope filtering to every caller. Reusing the current fixed-origin GET client provides structured eligibility data without new credentials. This choice is the implementer's judgment within the user's request to proceed.

## Contract

- Add `program_discover` for the iOS asset types `APPLE_STORE_APP_ID`, `TESTFLIGHT`, and `OTHER_IPA`.
- `page` defaults to 1, range 1..=1000; `page_size` defaults to 5, range 1..=10. `public_only`, `accepting_submissions_only`, and `bounty_only` default to true. Filters are local, not undocumented upstream query parameters.
- Defaults require `state=public_mode`, `submission_state=open`, `offers_bounties=true`, and at least one iOS scope with both eligibility flags explicitly true. Disabling a boolean filter removes that requirement. A qualifying scope always requires `eligible_for_submission=true`.
- Preserve iOS identifiers, types, scope instructions, `updated_at` and both eligibility flags. Missing values remain null. Candidate records may retain other iOS scopes, clearly distinguishing the scopes that satisfy the filter.
- Return program metadata, source URLs, a server-generated Unix-seconds retrieval timestamp, and untrusted-source marking. State that API flags do not override current policy or prove permission to test.
- Return `bounty_amount_status=not_available_in_hacker_api`; never infer an amount from severity, earnings or policy headlines. The researcher API does not document a bounty-table endpoint; the Customer API requires separate program-management access.
- Pagination applies to the source program page before filtering. Empty candidates can still have `next_page`. Never follow response-provided links. Mark a full last permitted source page truncated.
- Fetch scopes sequentially, at most 3 pages of 100 per candidate program, retaining existing byte and retry limits. Apply a 45-second overall tool deadline and a 5 MiB aggregate-output ceiling. Preserve successes and return handles/reasons for incomplete or uninspected programs on scope limits, errors or deadline. Initial program-list errors may fail the call.
- Malformed API collection shapes must not become empty, complete results.

## Constraints

Keep the existing fixed-origin GET-only transport, credential redaction, no redirects and local-draft-only behavior. Add no dependencies or credential types. Existing tools keep their interfaces. No Customer API calls, web scraping, remote reports, asset probing or inferred vulnerability/weakness rankings.

## Sources

- https://api.hackerone.com/hacker-resources/
- https://api.hackerone.com/hacker-reference/
- https://api.hackerone.com/customer-resources/

## Verification

Use synthetic fixtures, wiremock and stdio integration tests. Verify eligibility versus payment, all iOS types, pagination, incomplete results, malformed data and fixed-origin GET behavior. Run full tests, formatting and Clippy before the PR.
