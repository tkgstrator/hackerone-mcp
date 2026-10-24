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

## Install / build

Requires Rust 1.89 or newer (edition 2024). Unix only (macOS, Linux).

```sh
cargo install --path .          # installs hackerone-mcp into ~/.cargo/bin
# or
cargo build --release           # binary at target/release/hackerone-mcp
```

## Configuration

Environment variables:

| Variable            | Meaning                                                                                          |
| ------------------- | ------------------------------------------------------------------------------------------------ |
| `H1_USERNAME`       | HackerOne API username. Only needed for `program_*` tools.                                       |
| `H1_API_KEY`        | HackerOne API token. Only needed for `program_*` tools. Must be set together with `H1_USERNAME`. |
| `H1_MCP_DRAFTS_DIR` | Directory for drafts. Default `~/.config/hackerone-mcp/drafts`.                                  |

Without credentials the server still starts and the draft tools work; `program_*` tools return a
clear configuration error.

## Registering with an MCP client

Do **not** put the token in command-line arguments or in a config file that is world-readable:
arguments are visible to other local users via `ps`, and client config files are often synced or
committed. Instead keep the secrets in a file only you can read and source it from a launcher
script.

```sh
# 1. secrets file, readable only by you
mkdir -p ~/.config/hackerone-mcp
install -m 600 /dev/null ~/.config/hackerone-mcp/env
$EDITOR ~/.config/hackerone-mcp/env     # add the two lines below
#   H1_USERNAME=your-username
#   H1_API_KEY=your-token

# 2. launcher script
cat > ~/.config/hackerone-mcp/run.sh <<'EOF'
#!/bin/sh
set -a
. "$HOME/.config/hackerone-mcp/env"
set +a
exec /absolute/path/to/hackerone-mcp
EOF
chmod 700 ~/.config/hackerone-mcp/run.sh
```

Claude Code:

```sh
claude mcp add hackerone -- "$HOME/.config/hackerone-mcp/run.sh"
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
	"mcpServers": {
		"hackerone": {
			"command": "/Users/you/.config/hackerone-mcp/run.sh"
		}
	}
}
```

For draft-only use, point `command` straight at the binary; no credentials are needed.

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

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo deny check
cargo audit
```

`tests/stdio_e2e.rs` spawns the real binary and talks JSON-RPC over stdio.

## License

MIT, see [LICENSE](LICENSE).
