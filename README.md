# hackerone-mcp

A stdio [MCP](https://modelcontextprotocol.io) server that helps a bug-bounty hacker prepare
[HackerOne](https://hackerone.com) report **drafts locally**. It reads program information from the
HackerOne Hacker API, tracks submitted reports and stores drafts as files on your machine.

## Submission is explicitly enabled

Remote submission is disabled by default. Enable `H1_MCP_ALLOW_SUBMIT=true` to use
`report_submit` after reviewing a prepared preview and explicitly approving its recipient and body.
Preparation, validation and all other draft operations send nothing to HackerOne. Reply drafts
(`report_reply_draft`) remain local for manual sending in the HackerOne web UI. Public report comments
are separate: `report_comment_submit` posts one approved comment through the optional Customer API,
only with `H1_MCP_ALLOW_SUBMIT=true` and Customer API credentials that have Report Management permission.

HTTP code stays in `src/client/`, with a fixed `https://api.hackerone.com` origin and redirects
disabled. Reads retain bounded retries; report submission uses a separate client with retries
disabled and a persistent single-attempt ledger. Guard tests pin all 27 tools and submission annotations.

## Tools

| Tool                         | Description                                                     | Parameters                                                                                                                                                                                     |
| ---------------------------- | --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hacktivity_search`          | Search one page of selected public disclosed report metadata | `username`, `program`, `cwe`, `severity_rating`, `disclosed_after`, `disclosed_before`, `sort`, `page`, `page_size` |
| `hacker_activity`           | Bounded public report cohort: cadence, specialties, report rewards | `username`, `max_pages` (default 3, max 10) |
| `hacktivity_trends`         | Compare two UTC disclosure windows by weakness, severity, program and reporter | `days` (default 30, max 90), `end_date`, `program`, `cwe`, `severity_rating`, `max_pages` per window |
| `report_list`                | List one page of your submitted reports (needs credentials)     | `page`, `page_size`                                                                                                                                                                            |
| `report_get`                 | Get one submitted report: state, `submitted_at`, activities, bounties | `report_id` (decimal string, no leading zeros)                                                                                                                                           |
| `report_updates`             | Compare returned status and activities with a local baseline | `report_id`, `mark_seen` (default true) |
| `report_reply_draft`         | Save a local reply and manual-send report URL | `report_id`, `message` |
| `report_reply_draft_get`     | Read the saved local reply | `report_id` |
| `report_submit_prepare`      | Validate and persist an exact submission preview; no POST | `draft_id`, `expected_revision` |
| `report_submit`              | Submit the explicitly approved preview once; requires opt-in | `draft_id`, `expected_revision`, `confirmation_token`, `confirm` |
| `report_submission_get`      | Read the local submission receipt or uncertain status | `draft_id` |
| `report_comment_prepare`     | Preview an exact PUBLIC report comment (Customer API); no POST | `report_id`, `message` |
| `report_comment_submit`      | Post the approved comment once; requires opt-in and Customer API permission | `comment_id`, `confirmation_token`, `confirm` |
| `report_comment_get`         | Read the local comment receipt or uncertain status | `comment_id` |
| `program_discover`           | Discover eligible iOS programs from a bounded source page       | `page`, `page_size`, `public_only`, `accepting_submissions_only`, `bounty_only` |
| `program_list`               | List programs visible to your account (needs credentials)       | `page`, `page_size`                                                                                                                                                                            |
| `program_get`                | Get one program incl. policy and submission state               | `handle`                                                                                                                                                                                       |
| `program_scope`              | List a program's structured scopes (assets)                     | `handle`, `page`, `page_size`, `id_gt`, `created_at_gt`, `updated_at_gt`                                                                                                                       |
| `program_scope_exclusions`   | List scope exclusions (report categories excluded from rewards) | `handle`                                                                                                                                                                                       |
| `program_weaknesses`         | List weaknesses (CWE types) the program accepts                 | `handle`, `page`, `page_size`                                                                                                                                                                  |
| `program_submission_options` | Derived summary: submission state, scopes, accepted weaknesses  | `handle`                                                                                                                                                                                       |
| `draft_create`               | Create a local draft                                            | `title`, `vulnerability_information`, `team_handle`, `impact`, `severity_rating`, `weakness_id`, `structured_scope_id`, `cwe`, `cvss_vector`, `affected_versions`, `references`, `notes`, `id` |
| `draft_get`                  | Read a draft                                                    | `id`                                                                                                                                                                                           |
| `draft_update`               | Update fields; optimistic locking and field clearing            | `id`, `expected_revision`, any create field, `clear`                                                                                                                                           |
| `draft_list`                 | List draft summaries, newest first                              | `limit` (default 50, max 200)                                                                                                                                                                  |
| `draft_delete`               | Delete a local draft file                                       | `id`, `expected_revision`                                                                                                                                                                      |
| `draft_validate`             | Offline validation plus a request-body preview (never sent)     | `id`                                                                                                                                                                                           |

API reads, submission preparation and submission need HackerOne credentials. Local draft tools,
reply draft save/get and submission receipt lookup work without credentials.
`weakness_id` and `structured_scope_id` are HackerOne's integer ids (take them from
`program_submission_options`), not CWE numbers.

## Public activity and trends

These tools use the official `GET /v1/hackers/hacktivity` endpoint and require API credentials.
They select only publicly disclosed report metadata and omit vulnerability bodies/generated summaries.
They do not search a user directory, retrieve private profiles or provide an official leaderboard.
An empty username result means no matching visible activity, not that the account does not exist.

```json
{"name":"hacktivity_search","arguments":{"username":"jobert","page_size":10}}
{"name":"hacker_activity","arguments":{"username":"jobert","max_pages":3}}
{"name":"hacktivity_trends","arguments":{"days":30,"max_pages":3}}
{"name":"hacktivity_trends","arguments":{"days":30,"program":"security","cwe":"Information Disclosure"}}
```

`cwe` is the API's exact weakness **label**, not a CWE-number lookup. Handles, calendar dates,
severity and sort values are validated before network access. Search dates are UTC `YYYY-MM-DD`:
`disclosed_after` is inclusive and `disclosed_before` exclusive. Search supports the documented
ascending/descending sorts for `latest_disclosable_activity_at`, `disclosed_at`,
`total_awarded_amount` and `votes` (prefix `-` for descending).

`hacker_activity` describes the **retrieved disclosure cohort**. Monthly submission counts and
median gaps use `submitted_at` normalized to UTC; they do not establish the person's full finding
cadence, validity rate, investigation hours or hourly efficiency. Nonpublic/undisclosed reports
are absent. Trend windows use `disclosed_at`, so they describe disclosure activity, not discovery.
The default end is today's UTC midnight (exclusive), comparing the preceding 30 days with the
30 days before that. No scheduler or full-platform historical database is created.

Published rewards are **report-level amounts**, not a person's total income, profit, payout or
collaborator share. Missing amounts stay unknown; known zero stays zero. Sums and medians use
exact decimal arithmetic and return decimal strings. Explicit currencies are grouped separately;
missing currency is grouped only within the same known program. Amounts with neither currency nor
a program identity have counts but no monetary sum/median. There is no assumed USD conversion.

The live API silently caps results at 50 while calculating offsets from the requested size.
Hacktivity requests therefore reject sizes above 50; the default search size remains 25.
Each cohort reads up to `max_pages` of 50 reports. A shared 45-second deadline and 5 MiB admitted
response budget cover the whole call, including both trend windows. The existing client may read
one additional bounded response (up to 4 MiB) before rejecting that page at the admission budget;
received and admitted bytes are reported separately. Returned pagination URLs are never followed.
Coverage reports duplicates, excluded/invalid rows, source exhaustion and stop reasons. Late
errors preserve prior results. Incomplete cohorts suppress comparative growth figures. Even an
exhausted API result is an observed public cohort, not proof of all platform activity.

Group/reward/recent-report lists have at most 10 entries with omission counts; search pages have
at most 50. Responses are capped at 1 MiB; optional lists are trimmed if necessary and
`output_truncated` / `output_omitted_entries` expose that extra trimming. API-derived text stays
inside an untrusted-data envelope.

## Checking submitted reports

`report_list` and `report_get` are read-only GETs (`/v1/hackers/me/reports` and
`/v1/hackers/reports/{id}`). Each call returns one page or one report; nothing is paged, polled or
followed automatically.

```json
{"name": "report_list", "arguments": {"page": 1, "page_size": 25}}
{"name": "report_get", "arguments": {"report_id": "1234567"}}
```

`report_id` must be a positive decimal string of 1–20 digits without leading zeros. The raw API
response is returned inside the usual `source` / `untrusted_content` / `endpoint` / `data` envelope,
including state, activities (replies), severity and bounties as the API provides them. `submitted_at`
is the submission timestamp. Absent fields or `null` values (for example `triaged_at`) are not
evidence of acceptance, triage, investigation or payment. Report titles, bodies and comments are
untrusted data and may contain private content.

## Report updates and replies

`report_updates` fetches one report and compares status/time fields, bounties and returned activities
with a private local snapshot. The first observation is labelled a baseline, not new arrivals.
New activities and edits are separate; missing fields or an unavailable activity relationship do not
erase prior observations. An empty activity page does not prove the entire report has no comments.
Coverage is limited to what the API returns. `mark_seen=false` previews the difference without
advancing the snapshot. Concurrent changes fail clearly instead of overwriting a newer baseline.
One baseline is retained per report in a volume; switching API accounts starts a fresh baseline.

```json
{"name":"report_updates","arguments":{"report_id":"1234567","mark_seen":false}}
{"name":"report_reply_draft","arguments":{"report_id":"1234567","message":"Thank you. I can provide more details."}}
{"name":"report_reply_draft_get","arguments":{"report_id":"1234567"}}
```

Reply text is stored locally (nonblank, no NUL, up to 200,000 UTF-8 bytes). The returned fixed report
URL is for manually sending it in the web UI. The public [Hacker API](https://api.hackerone.com/hacker-resources/)
does not document comment creation; replies stay local drafts. Customer API comments use the separate `report_comment_*` tools.
Snapshots retain at most 1000 observed activity IDs and 8 MiB of private JSON. Exceeding a bound fails
without advancing; use `report_get` to inspect the current API response directly.

## Public report comments (Customer API)

`report_comment_prepare` stores an account-bound exact preview of
`POST /v1/reports/{id}/activities` with `internal: false` (public within the report's existing
audience; this does not disclose the report). `report_comment_submit` (needs `H1_MCP_ALLOW_SUBMIT=true`,
`confirm=true`, `comment_id` and token) consumes the attempt durably before one POST, with no retries.
`report_comment_get` reads the receipt. A success requires an `activity-comment` ID.

This is the documented **Customer API** endpoint and needs credentials with Report Management
permission. A Hacker API token that works for `report_get` may get HTTP 401/403 here; the failure is
recorded as an uncertain consumed attempt (inspect HackerOne, then prepare a new comment). The public
Hacker API documents no comment endpoint, so none is guessed; browser cookies and attachments are unsupported.
## Preparing and submitting a report

1. Create and validate a complete local draft, including `team_handle`, title, body and `impact`.
2. Call `report_submit_prepare` with its `draft_id` and exact `expected_revision`. This saves a preview,
   not a remote report. Review the returned account, program, complete `request_body` and warnings.
3. Only after explicit user approval, call `report_submit` with the same draft ID/revision,
   `confirmation_token` and `confirm=true`. A token is a consistency check, not proof of human approval.
4. Read `report_submission_get` for the saved result. A successful receipt contains the report ID and URL.

Enable submission explicitly in the server process. For Docker, add `-e H1_MCP_ALLOW_SUBMIT=true`
before the image argument, alongside the existing `--env-file` and persistent volume. Unset, empty
or `false` keeps submission disabled; other strings, including `1` and `TRUE`, fail configuration.

Preparation binds the account, full draft content, revision and exact serialized request bytes. A
new preparation invalidates the previous token; a draft edit before claim rejects the old preview.
Only the documented API fields are posted: local notes, CWE/CVSS labels, affected versions and
references are not silently appended. Offline validation does not establish program eligibility.

Before POST, the server durably consumes the attempt under the draft lock. It makes one POST to
`/v1/hackers/reports`, with no retry on any HTTP status or connection failure. A cancelled waiting
tool call still allows the receipt task to finish while the server is alive. A crash, timeout,
malformed response or receipt failure may leave `attempting`/`unknown`; **inspect HackerOne before
any new submission**. HTTP failures also consume the attempt. Only after confirming non-creation
should a user deliberately fix/copy the draft to a new ID. No retry/reset tool is provided.

The guard is local and per draft ID, not server-side or cross-ID idempotency. Copying a draft to a
different ID or deleting the ledger/volume bypasses it and can duplicate reports. Editing/deleting
the original draft does not remove the ledger. Keep the same volume across upgrades. Workflow
records use reserved dot-prefixed 0600 files inside the private drafts directory; corrupt or
insecure records fail closed rather than resetting history.

## Discovering iOS programs

Call `program_discover` with `{}` to inspect the first five programs visible to your account.
The default local filters require `state=public_mode`, `submission_state=open`, and
`offers_bounties=true`. A candidate needs at least one scope whose type is
`APPLE_STORE_APP_ID`, `TESTFLIGHT`, or `OTHER_IPA`, with both `eligible_for_submission`
and `eligible_for_bounty` explicitly true. Missing flags stay `null` and cannot satisfy a
required eligibility check.

Pagination applies to the **source program list before filtering**. For example:

```json
{"page": 1, "page_size": 5}
```

Read `data.source_page.next_page` and pass that number as `page` in the next call, keeping
the same `page_size` and filters. An empty `data.candidates` array can still have a next page.
Pages range from 1 to 1000 and page sizes from 1 to 10. A full page 1000 is marked
`truncated`; a short page stops continuation. Response-provided pagination links are never followed.

To include private programs, paused programs, and programs or scopes without bounty eligibility:

```json
{"public_only": false, "accepting_submissions_only": false, "bounty_only": false}
```

A qualifying scope always needs `eligible_for_submission=true`. Each candidate retains its
published iOS scopes, including their identifiers, instructions, update times and eligibility
flags. `matches_filters` identifies the scopes that qualify under the selected filters.

Discovery reads scopes sequentially, at most three pages of 100 per candidate program, within
one 45-second tool deadline and a 5 MiB output ceiling. Existing response-byte and retry limits
also apply. `data.incomplete_programs` gives source indexes, handles and reasons when a program
cannot be fully inspected, including scope limits, malformed data, request errors, deadline
exhaustion or the output limit. Earlier successful candidates are retained. `scopes_complete`
marks each returned candidate's scope coverage; `data.source_page_complete` describes inspection
of this source page, not coverage of every program or subsequent source pages. Unvisited scope
pages may contain additional qualifying assets.

The response includes source URLs, `retrieved_at_unix` and an untrusted-source marker. Read the
current program policy before testing: published API flags do not override policy or prove
permission. Bounty eligibility describes eligibility, not a payment amount. The response sets
`bounty_amount_status=not_available_in_hacker_api`; it does not infer numeric rewards from
severity, earnings or policy headlines. The Hacker API does not document a bounty-table endpoint;
the separate Customer API requires program-management access and is not used here.

## Running with Docker

The server is distributed as a container image and is started over stdio, so the MCP client runs
`docker run -i`.

Image: `ghcr.io/tkgstrator/hackerone-mcp`, platforms `linux/amd64` and `linux/arm64`. Tags per release:
`X.Y.Z`, `vX.Y.Z`, `latest` and `sha-<full commit SHA>`. Pin an explicit version in your client config rather
than `latest`.

> The first push to GHCR creates the package as private. Until the owner has made it public once
> (manually, in the package settings), pull it after `docker login ghcr.io` with a token that has
> `read:packages`.

```sh
docker pull ghcr.io/tkgstrator/hackerone-mcp:<version>
docker run -i --rm -v hackerone-mcp-drafts:/data/drafts ghcr.io/tkgstrator/hackerone-mcp:<version>
```

The command above is local-only (no credentials). To enable API-backed tools pass credentials
as described under [Configuration](#configuration).

### Image details

- Runtime is `gcr.io/distroless/cc-debian12` (no shell); the entrypoint is the binary.
- It runs as non-root uid/gid `10001`. `/data/drafts` is pre-created with mode `0700`, owned by
  `10001`, declared as a `VOLUME`, and `H1_MCP_DRAFTS_DIR=/data/drafts` is preset.
- **Named volumes** (`-v hackerone-mcp-drafts:/data/drafts`) need no setup: they inherit the right
  owner and mode.
- **Bind mounts** must satisfy the same rules, because the server refuses a drafts directory that is
  accessible by group/other (`drafts directory is accessible by group/other (expected mode 0700)`)
  or not owned by the container user (`cannot stat drafts directory: Permission denied`). Prepare the
  host directory first:

  ```sh
  mkdir -p "$HOME/hackerone-drafts"
  chown 10001:10001 "$HOME/hackerone-drafts" && chmod 700 "$HOME/hackerone-drafts"   # may need sudo
  docker run -i --rm -v "$HOME/hackerone-drafts:/data/drafts" ghcr.io/tkgstrator/hackerone-mcp:<version>
  ```

  Running with `--user "$(id -u):$(id -g)"` instead is not verified and did not work on Docker
  Desktop / OrbStack because of ownership mapping.
- The filesystem behind `/data/drafts` must support hard links (named volumes do).

## Configuration

Environment variables:

| Variable            | Meaning                                                                                          |
| ------------------- | ------------------------------------------------------------------------------------------------ |
| `H1_USERNAME`       | HackerOne API username. Needed for API reads and submission preparation/execution.                                       |
| `H1_API_KEY`        | HackerOne API token. Needed for API reads and submission preparation/execution. Must be set together with `H1_USERNAME`. |
| `H1_MCP_DRAFTS_DIR` | Directory for drafts. Preset to `/data/drafts` in the image.                                     |
| `H1_MCP_ALLOW_SUBMIT` | Exact `true` enables separately approved report submission. Defaults to disabled. |

Without credentials the server still starts and local draft/reply/receipt tools work; API-backed tools return a
clear configuration error.

## Registering with an MCP client

Do **not** put the token in command-line arguments or in a config file that is world-readable:
arguments are visible to other local users via `ps`, and client config files are often synced or
committed. Keep the secrets in a file only you can read and hand it to Docker with `--env-file`
(Docker reads it; the values never appear in the command line). Alternatively use value-less
`-e H1_USERNAME -e H1_API_KEY`, which copies the variables from the environment of the launching
process, so the values are still not in argv.

```sh
# secrets file, readable only by you
mkdir -p ~/.config/hackerone-mcp
install -m 600 /dev/null ~/.config/hackerone-mcp/env
$EDITOR ~/.config/hackerone-mcp/env     # add the two lines below
#   H1_USERNAME=your-username
#   H1_API_KEY=your-token
```

Claude Code:

```sh
claude mcp add hackerone -- docker run -i --rm \
  -v hackerone-mcp-drafts:/data/drafts \
  --env-file "$HOME/.config/hackerone-mcp/env" \
  ghcr.io/tkgstrator/hackerone-mcp:<version>
```

Claude Desktop (`claude_desktop_config.json`; use an absolute path, `$HOME` is not expanded):

```json
{
	"mcpServers": {
		"hackerone": {
			"command": "docker",
			"args": [
				"run", "-i", "--rm",
				"-v", "hackerone-mcp-drafts:/data/drafts",
				"--env-file", "/Users/you/.config/hackerone-mcp/env",
				"ghcr.io/tkgstrator/hackerone-mcp:<version>"
			]
		}
	}
}
```

For draft-only use, drop the `--env-file` option; no credentials are needed.

## Release archives

Each GitHub release also carries `hackerone-mcp-vX.Y.Z-<target>.tar.gz` archives (binary, `LICENSE`,
`README.md`) for `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu`, plus `SHA256SUMS`. They are attested; verify with:

```sh
gh attestation verify <archive> --repo tkgstrator/hackerone-mcp
shasum -a 256 -c SHA256SUMS
```

The Linux archives are built in the Debian bookworm toolchain; the binary's highest required glibc
symbol version is 2.34 (measured). Docker is the documented way to run the server.

## Draft file format

Each draft is `<id>.md` in the drafts directory: TOML frontmatter between `+++` lines, then the
Markdown body (the report's `vulnerability_information`). Ids match `[a-z0-9-]{1,64}`.

```
+++
id = "example-xss"
revision = 1
created_at = 1792838334
updated_at = 1792838334
status = "draft"
team_handle = "acme"
title = "Stored XSS in profile bio"
impact = "Account takeover"
severity_rating = "high"
cwe = "cwe-79"
cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N"
affected_versions = "< 2.4.1"
references = ["https://example.com/advisory"]
+++
## Steps
1. Open profile
```

`revision` increases on every update; pass `expected_revision` to `draft_update`/`draft_delete` to
avoid overwriting concurrent edits.

Draft tool outputs return the full body, up to the 200,000-byte body limit. Only a hand-edited file whose body exceeds that limit is returned truncated; the result then carries a server-generated top-level `body_truncation` object (`truncated`, `returned_bytes`, `total_bytes`, `warning`) outside the `draft` fields, and such a body must not be written back with `draft_update`.

## Workflow

1. `program_submission_options` for the target program (submission state, scope ids, weakness ids).
2. `draft_create`, then refine with `draft_update`.
3. `draft_validate` for an offline check of the required fields and a preview of the request body.
   It does not prove you are allowed to submit to the program.
4. Submit manually in the HackerOne web UI, or use the reviewed prepare/submit sequence above when enabled.

For CVE preparation the drafts carry `cwe`, `cvss_vector` and `affected_versions`. These are local
notes only. CVE IDs are assigned by a CNA (the vendor, a CNA-of-last-resort, or MITRE), never by this tool.

## Security notes

- **Token handling**: the API key is read from the environment, redacted in `Debug` output, and is
  not written to stdout or stderr (checked by `tests/stdio_e2e.rs`). Use a `0600` env file as above.
- **Data flows to your LLM client**: tool results, including draft contents and program data, are
  sent to whatever model your MCP client uses. Do not store secrets in drafts.
- **Untrusted text**: program policies, scope descriptions and other API-derived text are
  attacker-influenced. Responses are labelled as untrusted, but a model can still be prompt-injected
  by such text; review what the model does and writes.
- **Files**: Unix only. The drafts directory is created with mode `0700` and draft files with
  `0600`. New drafts are created atomically using `hard_link`, so the drafts directory must be on a
  filesystem that supports hard links.
- **Dependencies**: HTTP is `reqwest` with rustls only (no OpenSSL / native-tls). `deny.toml` bans
  alternative HTTP clients and TLS stacks, restricts licenses and sources. CI also checks that no
  direct dependency on `hyper` or other HTTP client crates is declared.

## Development

Building from source requires Rust 1.89 or newer (edition 2024). Unix only (macOS, Linux).

```sh
cargo build --release           # binary at target/release/hackerone-mcp
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
cargo audit
docker build -t hackerone-mcp:local .
scripts/docker-smoke.sh hackerone-mcp:local   # needs docker and jq
bun install --frozen-lockfile --ignore-scripts && bunx commitlint --last --verbose
```

`tests/stdio_e2e.rs` spawns the real binary and talks JSON-RPC over stdio. `scripts/docker-smoke.sh`
starts the image, checks `initialize`, that `tools/list` returns 27 tools, and a `draft_create` /
`draft_get` round trip.

### Commits

Use [Conventional Commits](https://www.conventionalcommits.org). CI commitlint checks PR commits and
non-`master` branch push tips; it skips normal GitHub merge commits on `master`. Configuration is in
`.commitlintrc.yaml`, with dependencies pinned in `bun.lock`. Allowed types: `build`, `ui`,
`ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `format`, `test`, `chore`; header up to
128 characters.

### CI (`.github/workflows/integration.yaml`)

Runs on pull requests, branch pushes, `master` pushes, and manual dispatch. On `master`, all checks
must pass before it calls the reusable Deployment workflow for the same commit:

- `Integration / Commit Lint`
- `Integration / rustfmt`
- `Integration / Clippy (ubuntu-latest)` and `Integration / Clippy (macos-latest)`
- `Integration / Test (ubuntu-latest)` and `Integration / Test (macos-latest)`
- `Integration / Supply chain`: `cargo deny`, `cargo audit`, and a guard against direct HTTP-client
  dependencies
- `Integration / Docker (amd64)` and `Integration / Docker (arm64)`: build each native-platform image
  (no push) and run `scripts/docker-smoke.sh`

Branch protection on `master` is expected to require these checks to pass before merge and to
disallow direct and force pushes (a repository setting, not enforced by files in this repo).

All third-party GitHub Actions are pinned to commit SHAs. Dependabot
(`.github/dependabot.yml`) proposes weekly updates for GitHub Actions, Cargo, Docker and Bun (`package.json` / `bun.lock`).

### Releasing (`.github/workflows/deployment.yaml`)

1. For the first release, merge the release workflow to `master`. For subsequent releases, bump
   `version` in `Cargo.toml` and merge to `master` through a pull request. The version must be plain
   `MAJOR.MINOR.PATCH`; prerelease and build suffixes (`-rc.1`, `+build`) are not supported.
2. Successful Integration checks call Deployment at that same commit. Deployment builds the four
   archives, then pushes the multi-arch image under a commit-SHA tag. After verifying the archives,
   checksums and draft release, and generating attestations, it points the version and `latest`
   tags at the exact image digest and publishes the GitHub release.

Behaviour to know about:

- Deployment checks that its tested commit is still the `master` head before the image push, before
  moving version tags, and before publishing the release. A new push between a check and publication
  can still race; check the final tag and image after release.
- A push that does not change the version is a green no-op once a release for that version is
  published.
- A tag `vX.Y.Z` that exists at another commit without a published release fails the run visibly;
  fix or delete the tag manually.
- Version and `latest` image tags are updated only after the draft assets are verified. GHCR and
  GitHub Releases are separate services: a failure after tag promotion can leave image tags before
  the release appears. Inspect the state before retrying Integration on `master`.
- A failed upload or publication can leave a draft release. A retry refuses to overwrite any draft
  with the same tag, including one written by a person. Inspect its assets and notes, then remove
  that draft manually before retrying. The workflow never deletes a draft automatically.
- `[skip ci]` / `[ci skip]` suppresses the automatic run; dispatch Integration on `master` manually
  to run all checks and publish. The first GHCR push creates a private package; make it public in
  the package settings if anonymous pulls are required, then verify without Docker credentials.

## License

MIT, see [LICENSE](LICENSE).
