# Public HackerOne activity insights

The user requested user-level submission cadence, public rewards and specialties, plus trends. This extends the already authorized PR/CI/merge/GHCR/local-image workflow. Use the existing Rust stdio server and official Hacker API only. The exact names and bounds below are implementation choices, not user-selected parameters.

## Approaches

1. Official Hacktivity API (chosen): stable documented filters and bounded authenticated GETs; supports only the activity visible to the configured account.
2. Website/undocumented GraphQL scraping: could add profile/leaderboard data, but introduces undocumented contracts and browser/session dependencies. Excluded.
3. Persistent full-platform warehouse: richer historical analysis, but unnecessary storage, backfill and scheduling for this request. Excluded.

## Surface

Add three read-only tools (24 tools total), release 0.5.0:

- `hacktivity_search`: one page, default page 1 / size 25, max 50; structured optional `username`, `program`, `cwe`, `severity_rating`, `disclosed_after`, `disclosed_before`; documented sort enum. Always constrain to disclosed reports. Dates are ISO YYYY-MM-DD; after inclusive and before exclusive in UTC. Canonical numeric report IDs and safe canonical report/profile links. Return selected public metadata, never vulnerability_information or generated summaries.
- `hacker_activity`: exact `username` required and `max_pages` 1..=10 (default 3). Query disclosed reports for this username, newest disclosure first; no directory/profile-existence assertion. Deduplicate by report ID. Return retrieved-cohort monthly submission counts from submitted_at, first/last submission, median inter-submission gap in days, counts by CWE/program/severity and public report reward statistics. No time-based discovery/earnings efficiency claim. Empty results mean no matching visible activity, not nonexistent user.
- `hacktivity_trends`: `days` 1..=90 (default 30), `end_date` UTC YYYY-MM-DD (default today's UTC date, exclusive), optional `program`, `cwe`, `severity_rating`, `max_pages` 1..=10 (default 3 per window). Compare [end-days,end) with [end-2*days,end-days), using disclosed_at, not submitted_at. Return both windows and top CWE, severity, program and reporter counts; observed report shares. Compute count changes/percentage changes only if both cohorts fully paginated and usable; otherwise comparisons null with explicit reason. Previous zero -> percentage null, never infinity.

## API and validation

Only add typed `GET /v1/hackers/hacktivity` through H1Client. Existing GET auth, retry, no-redirect and response limits remain. No arbitrary method, URL or links.next following. The official queryString parameter is URL query encoded; generate quoted/escaped Lucene filters from validated handles and bounded strings. Sort uses documented whitelist. Validate calendar dates and RFC3339 timestamps with chrono 0.4 (minimal features), not a home-grown calendar. No other dependency is needed.

2026-11-06 live probes proved `reporter:"jobert"` and `disclosed_at:[2026-10-07 TO 2026-11-06}` work. Numeric JSON report IDs, nullable reward values, and absent program.currency were observed. Both probe queries are 200; selected metadata evidence is outside the repo. Do not commit real report content or credentials.

## Coverage and bounded execution

Each aggregate: maximum 10 pages x 50 items, 5 MiB aggregate input; 45-second whole-tool deadline (shared across both trend windows), maximum 1 MiB serialized output. One search is max 50 items and bounded output. Never follow response URLs. Full page with no trustworthy terminal evidence remains possibly truncated; a short page or explicit null/absent next plus a short page establishes source exhaustion. Use conservative pagination, not total counts as proof of completeness. Report pages fetched, raw items, unique eligible reports, duplicate/invalid/excluded items, bounds, source exhaustion, truncated status and stop reason. Return useful partial aggregates on later-page/deadline/budget failure with incomplete coverage; initial authentication/fetch failure returns a sanitized normal tool error. A truncated or malformed cohort must not yield definitive comparative growth figures. Concurrent API changes mean even exhausted results are an observed API cohort, never all platform findings.

Locally verify disclosed=true, exact username/program when requested and valid disclosed timestamps within trend bounds. Invalid/ineligible rows counted and excluded; duplicates never inflate counts. API text is untrusted data. Metadata fields absent/invalid are tracked; timestamps with offsets normalize to UTC before monthly grouping. Limits apply before retaining/reporting oversized metadata.

## Rewards

`total_awarded_amount` is a report-level published amount, not personal earnings, payout, profit or total income. Null/missing is unknown, not zero. Zero is known zero. No floating point money accumulation: parse nonnegative JSON numbers/decimal strings with a bounded exact decimal representation; return decimal strings for sum/median. Group by explicit currency if present. Without currency, group separately by program (currency null); never silently assume USD or mix unknown currencies across programs. Missing program/currency yields a separate clearly unknown bucket. Count known/unknown/invalid amounts. Collaborator splits and nonpublic reports are unknown. No inferred Signal/Impact/reputation or true validity ratio from public reports.

## Acceptance

- New mock tests prove wire filters/encoding/sort/pages/auth and validation before network.
- Fixtures cover duplicates, malformed rows, missing/zero rewards, absent/mixed currencies, exact sum/median, offset timestamps, disclosure vs submission, empty cohorts, zero denominator, partial paging, API errors/deadline/byte budgets, query-escaping, no-link-follow and no private text in outputs.
- Stdio tests pin 24 tools, read-only annotations, missing-credential behavior, schema registration and local tools still working. Existing submission safeguards unchanged.
- Native fmt/test/strict clippy; normal PR CI; fresh independent actual-files Claude review. LocalGPT currently unavailable (browser_disconnected); use an independent native reviewer as the disclosed alternative.
- Verify real GETs via the source binary, then published image, preserving credential file, drafts volume and unrelated MCP config. No real POST. Reuse existing release workflow and checksums/platform verification.

## Reviewed contract rulings (supersede ambiguous wording above)

- Limits: each cohort up to 10 pages x 50 rows; trends up to 20 pages / 1000 rows total, with one SHARED 5 MiB input budget and 45-second deadline. Injectable `InsightLimits { deadline, input_bytes, output_bytes, now }` supports deterministic bounded tests. `now` is a SystemTime-derived UTC DateTime; chrono uses default-features=false, features=["std"].
- All tools locally verify every supplied filter: disclosed=true, handle comparisons case-insensitive ASCII, CWE exact API weakness label (not a CWE-ID lookup), severity exact normalized enum, UTC disclosure date range. Missing/invalid required filter values exclude the row and make aggregate comparisons incomplete. CWE input 1..=200 UTF-8 bytes, nonblank, no control chars; handles use existing 1..=64 ASCII handle grammar. Escape Lucene quotes and backslashes. No raw Lucene input.
- Date inputs exactly YYYY-MM-DD and valid calendar dates in 2000-01-01..=9999-12-31. Search after < before if both set. Trends end cannot be future UTC day; subtract 2*days with checked arithmetic and require start >= 2000-01-01. Dates and timestamps use chrono parsing and UTC normalization.
- Exact documented sort strings: latest_disclosable_activity_at, -latest_disclosable_activity_at, disclosed_at, -disclosed_at, total_awarded_amount, -total_awarded_amount, votes, -votes. Search defaults -latest_disclosable_activity_at; aggregates -disclosed_at. Evidence: official Hacker Resources / Hacktivity parameters (2026-09-23 revision).
- Pagination: a short/empty page WITHOUT a nonempty next hint is terminal. A full page remains possibly incomplete even when links.next is absent; use another generated page number if within cap. A short page WITH next keeps paging generated numbers; mark pagination inconsistent and suppress definitive growth even if later exhausted. Malformed page/oversized requested page is an initial error or a partial stop; never follow next URLs. Duplicate rows are counted, retained only once. Filter mismatches/malformed rows also prevent definitive comparison.
- An initial error means the first fetch of the WHOLE tool, not the first fetch of a second trend window. Preserve a completed first window when the second is unavailable; second coverage states the stop reason and comparison figures are null.
- Enable serde_json features=["arbitrary_precision"] so JSON numeric reward tokens reach the decimal parser without f64 conversion. Reward input bounds: up to 18 integer digits and 6 fractional digits after exponent normalization (bounded signed exponent); larger/negative/non-decimal inputs are invalid and counted. Checked u128 arithmetic; median allows a seventh fractional digit. No f64 money operations.
- When neither currency nor a valid program identity is available, report amount counts but sum/median=null. Known explicit currencies can be grouped; unknown currency is grouped only within the same validated program. Never combine anonymous unknown currencies.
- Fixed top-N = 10 for CWE/severity/program/reporter groups, reward buckets and recent report examples, with omitted_groups/omitted_reports counts. Monthly submission counts may span the retrieved historical cohort (<=500 rows); bound retained date/string metadata. Search items <=50. On output pressure, deterministically trim optional lists and flag output_truncated; if even mandatory metadata exceeds a test-injected limit, return a bounded error.
- Cadence fields explicitly end `_in_cohort`; `cohort="disclosed_only"` and `all_findings_complete=false` are mandatory. Monthly rows also mark all_findings_complete=false. All cadence and reward results describe the retrieved cohort even when pagination exhausts. Missing dates/metadata have explicit counts. Empty activity does not prove username nonexistent.

- Input budget means admitted response bytes. The existing client can receive one bounded (max 4 MiB) response before the shared 5 MiB admission check rejects it; received/admitted byte counts are separate. The budget is not represented as a strict network-wire byte cap.
- Pure compare(false) emits incomplete_cohort; outer orchestration carries detailed per-window coverage and comparison_unavailable_reasons. JSON arbitrary_precision compatibility was proven by all existing 130 unit/6 stdio tests after the exact numeric-token RED regression.

- Live pagination correction (2026-11-06): requested100 returned50 and offset100 skipped10 older results; requested50 gave50+10 and requested25 gave25+25+10. Hacktivity-specific maximum is50, while unrelated endpoint PageParams stays100. All aggregate requests and reported page sizes use50; per-cohort500 and per-trends1000 maximum rows. Full pages continue without trusting a missing next link. Requests >50 are rejected before HTTP, never clamped. This ruling supersedes all original 100-item Hacktivity bounds.
