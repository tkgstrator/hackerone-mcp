# hackerone-mcp

A stdio [MCP](https://modelcontextprotocol.io) server that helps a bug-bounty hacker prepare
[HackerOne](https://hackerone.com) report **drafts locally**. It reads program information from the
HackerOne Hacker API (read-only) and stores drafts as files on your machine.

## Non-goal: it never submits anything

This server does **not** submit, send, or publish reports, and it is built so that it cannot:
- The only HTTP client code lives in `src/client/` and only issues `GET` requests to the fixed origin
  `https://api.hackerone.com`.
- There is no submit tool. A test (`src/tools/guard_tests.rs`) pins the exact set of 12 tools and
  asserts no tool name contains `submit`, `send`, `post`, `publish`, `upload` or `report_remote`.
- `draft_validate` only shows a preview of the request body that _would_ be sent; it is marked
  `never_sent`.

You review the draft and submit it yourself in the HackerOne web UI.

## Tools

| Tool                         | Description                                                     | Parameters                                                                                                                                                                                     |
| ---------------------------- | --------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
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

The `program_*` tools need HackerOne credentials; the `draft_*` tools work without them.
`weakness_id` and `structured_scope_id` are HackerOne's integer ids (take them from
`program_submission_options`), not CWE numbers.

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

The command above is draft-only (no credentials). To enable the `program_*` tools pass credentials
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
| `H1_USERNAME`       | HackerOne API username. Only needed for `program_*` tools.                                       |
| `H1_API_KEY`        | HackerOne API token. Only needed for `program_*` tools. Must be set together with `H1_USERNAME`. |
| `H1_MCP_DRAFTS_DIR` | Directory for drafts. Preset to `/data/drafts` in the image.                                     |

Without credentials the server still starts and the draft tools work; `program_*` tools return a
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
4. Copy the draft into the HackerOne web UI and submit it there, manually.

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
starts the image, checks `initialize`, that `tools/list` returns 12 tools, and a `draft_create` /
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
