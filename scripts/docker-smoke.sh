#!/usr/bin/env bash
# Smoke-test a built hackerone-mcp image over stdio JSON-RPC.
# Usage: scripts/docker-smoke.sh <image>
set -euo pipefail

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: $0 <image>" >&2
  exit 2
fi
image="$1"
expected_tools=12
step_timeout=60

command -v jq >/dev/null || { echo "smoke: jq is required" >&2; exit 2; }

work="$(mktemp -d)"
volume="h1-mcp-smoke-$$-$(date +%s)"
server_pid=""

cleanup() {
  exec 3>&- 2>/dev/null || true
  if [ -n "$server_pid" ]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  docker volume rm -f "$volume" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

fail() {
  echo "SMOKE FAIL: $*" >&2
  if [ -s "$work/stderr" ]; then
    echo "--- server stderr ---" >&2
    cat "$work/stderr" >&2
  fi
  if [ -s "$work/stdout" ]; then
    echo "--- server stdout ---" >&2
    cat "$work/stdout" >&2
  fi
  exit 1
}

docker volume create "$volume" >/dev/null

mkfifo "$work/in"
: >"$work/stdout"
: >"$work/stderr"
docker run -i --rm -v "$volume:/data/drafts" "$image" \
  <"$work/in" >"$work/stdout" 2>"$work/stderr" &
server_pid=$!
exec 3>"$work/in"

send() { printf '%s\n' "$1" >&3; }

# Waits for the JSON-RPC response with the given id; prints it on stdout.
await() {
  local id="$1" waited=0 line
  while [ "$waited" -lt $((step_timeout * 10)) ]; do
    line="$(jq -c --argjson id "$id" 'select(.id == $id)' "$work/stdout" 2>/dev/null | head -n 1 || true)"
    if [ -n "$line" ]; then
      printf '%s\n' "$line"
      return 0
    fi
    kill -0 "$server_pid" 2>/dev/null || fail "server exited before answering request $id"
    sleep 0.1
    waited=$((waited + 1))
  done
  fail "timed out after ${step_timeout}s waiting for response $id"
}

send '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
init="$(await 1)"
echo "$init" | jq -e '.error == null and .result != null' >/dev/null || fail "initialize failed: $init"

send '{"jsonrpc":"2.0","method":"notifications/initialized"}'

send '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
list="$(await 2)"
count="$(echo "$list" | jq '.result.tools | length')" || fail "tools/list malformed: $list"
[ "$count" = "$expected_tools" ] || fail "expected $expected_tools tools, got $count"

send '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"draft_create","arguments":{"title":"smoke test"}}}'
created="$(await 3)"
echo "$created" | jq -e '.error == null and (.result.isError // false) == false' >/dev/null \
  || fail "draft_create failed: $created"
created_text="$(echo "$created" | jq -r '.result.content[0].text')"
draft_id="$(echo "$created_text" | jq -r '.. | objects | select(has("id")) | .id' 2>/dev/null | head -n 1 || true)"
[ -n "$draft_id" ] && [ "$draft_id" != "null" ] || fail "draft_create returned no id: $created_text"

req="$(jq -cn --arg id "$draft_id" '{jsonrpc:"2.0",id:4,method:"tools/call",params:{name:"draft_get",arguments:{id:$id}}}')"
send "$req"
got="$(await 4)"
echo "$got" | jq -e '.error == null and (.result.isError // false) == false' >/dev/null \
  || fail "draft_get failed: $got"
echo "$got" | jq -e '.result.content[0].text | contains("smoke test")' >/dev/null \
  || fail "draft_get did not return the title: $got"

echo "SMOKE OK: $image ($count tools, draft '$draft_id' round-tripped)"
