//! End-to-end test: spawns the real binary and speaks newline-delimited JSON-RPC.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use serde_json::{Value, json};

const TIMEOUT: Duration = Duration::from_secs(20);

struct Server {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
    stderr: Receiver<String>,
    seen: Vec<String>,
    next_id: u64,
}

impl Server {
    fn spawn(dir: &std::path::Path, creds: Option<(&str, &str)>) -> Self {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_hackerone-mcp"));
        cmd.env_remove("H1_USERNAME");
        cmd.env_remove("H1_API_KEY");
        cmd.env("H1_MCP_DRAFTS_DIR", dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some((u, k)) = creds {
            cmd.env("H1_USERNAME", u).env("H1_API_KEY", k);
        }
        let mut child = cmd.spawn().expect("spawn binary");
        let stdin = child.stdin.take();
        let out = child.stdout.take().unwrap();
        let mut err = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        thread::spawn(move || {
            for l in BufReader::new(out).lines().map_while(Result::ok) {
                if tx.send(l).is_err() {
                    break;
                }
            }
        });
        let (etx, stderr) = mpsc::channel();
        thread::spawn(move || {
            let mut s = String::new();
            let _ = err.read_to_string(&mut s);
            let _ = etx.send(s);
        });
        Self {
            child,
            stdin,
            lines,
            stderr,
            seen: Vec::new(),
            next_id: 1,
        }
    }

    fn send(&mut self, v: &Value) {
        let w = self.stdin.as_mut().unwrap();
        writeln!(w, "{v}").unwrap();
        w.flush().unwrap();
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}));
        loop {
            let line = self
                .lines
                .recv_timeout(TIMEOUT)
                .expect("timed out waiting for a response (server hung or exited)");
            self.seen.push(line.clone());
            let v: Value = serde_json::from_str(&line).expect("stdout line is not JSON");
            assert_eq!(v["jsonrpc"], "2.0", "not a JSON-RPC message: {line}");
            if v["id"] == json!(id) {
                return v;
            }
        }
    }

    /// Calls a tool; Ok(parsed JSON text) or Err(error message).
    fn call(&mut self, name: &str, args: Value) -> Result<Value, String> {
        let r = self.request("tools/call", json!({"name":name,"arguments":args}));
        if let Some(e) = r.get("error") {
            return Err(e["message"].as_str().unwrap_or("").to_string());
        }
        let res = &r["result"];
        let text = res["content"][0]["text"].as_str().unwrap_or("").to_string();
        if res["isError"] == json!(true) {
            return Err(text);
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }

    fn handshake(&mut self) {
        let r = self.request(
            "initialize",
            json!({"protocolVersion":"2025-06-18","capabilities":{},
                "clientInfo":{"name":"e2e","version":"0"}}),
        );
        assert!(r.get("error").is_none(), "initialize failed: {r}");
        self.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}));
    }

    /// Closes stdin, waits for exit, returns (all stdout lines, stderr).
    fn finish(mut self) -> (Vec<String>, String) {
        drop(self.stdin.take());
        let start = std::time::Instant::now();
        while self.child.try_wait().unwrap().is_none() {
            if start.elapsed() > TIMEOUT {
                let _ = self.child.kill();
                panic!("server did not exit after stdin closed");
            }
            thread::sleep(Duration::from_millis(20));
        }
        while let Ok(l) = self.lines.recv_timeout(Duration::from_millis(500)) {
            self.seen.push(l);
        }
        let err = self.stderr.recv_timeout(TIMEOUT).unwrap_or_default();
        (std::mem::take(&mut self.seen), err)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

fn private_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

const EXPECTED: [&str; 12] = [
    "program_list",
    "program_get",
    "program_scope",
    "program_scope_exclusions",
    "program_weaknesses",
    "program_submission_options",
    "draft_create",
    "draft_get",
    "draft_update",
    "draft_list",
    "draft_delete",
    "draft_validate",
];

#[test]
fn draft_lifecycle_over_stdio_without_credentials() {
    let dir = private_dir();
    let mut s = Server::spawn(dir.path(), None);
    s.handshake();

    let tools = s.request("tools/list", json!({}));
    let names: BTreeSet<String> = tools["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    let want: BTreeSet<String> = EXPECTED.iter().map(|s| s.to_string()).collect();
    assert_eq!(names, want);

    let c = s
        .call(
            "draft_create",
            json!({"id":"e2e-xss","title":"Stored XSS","team_handle":"acme",
                "impact":"account takeover","vulnerability_information":"1. do it"}),
        )
        .unwrap();
    assert_eq!(c["draft"]["revision"], 1);

    let g = s.call("draft_get", json!({"id":"e2e-xss"})).unwrap();
    assert_eq!(g["draft"]["title"], "Stored XSS");

    let v = s.call("draft_validate", json!({"id":"e2e-xss"})).unwrap();
    assert_eq!(v["report"]["valid"], true);
    assert_eq!(v["report"]["request_body_preview"]["never_sent"], true);

    let l = s.call("draft_list", json!({})).unwrap();
    assert_eq!(l["count"], 1);

    let u = s
        .call(
            "draft_update",
            json!({"id":"e2e-xss","expected_revision":1,"cwe":"cwe-79"}),
        )
        .unwrap();
    assert_eq!(u["draft"]["revision"], 2);
    let stale = s.call(
        "draft_update",
        json!({"id":"e2e-xss","expected_revision":1,"notes":"x"}),
    );
    assert!(stale.is_err(), "stale revision must be rejected");

    let d = s.call("draft_delete", json!({"id":"e2e-xss"}));
    assert!(d.is_ok(), "delete failed: {d:?}");
    assert!(s.call("draft_get", json!({"id":"e2e-xss"})).is_err());

    let (lines, _err) = s.finish();
    for l in &lines {
        let v: Value = serde_json::from_str(l).expect("non-JSON on stdout");
        assert_eq!(v["jsonrpc"], "2.0");
    }
}

#[test]
fn program_tool_without_credentials_is_a_clear_error() {
    let dir = private_dir();
    let mut s = Server::spawn(dir.path(), None);
    s.handshake();
    let e = s.call("program_list", json!({})).unwrap_err();
    assert!(e.contains("H1_USERNAME") && e.contains("H1_API_KEY"), "{e}");
    // The server must still be alive afterwards.
    assert!(s.call("draft_list", json!({})).is_ok());
    let (_lines, err) = s.finish();
    assert!(err.contains("API tools are disabled"), "{err}");
}

#[test]
fn credentials_never_appear_on_stdout_or_stderr() {
    const USER: &str = "e2e-user-7f3a91";
    const KEY: &str = "e2e-key-SECRET-5c2d84";
    let dir = private_dir();
    let mut s = Server::spawn(dir.path(), Some((USER, KEY)));
    s.handshake();
    // Only local tools: the production origin is fixed, so no network use here.
    s.call("draft_create", json!({"id":"c","title":"t"}))
        .unwrap();
    s.call("draft_get", json!({"id":"c"})).unwrap();
    let (lines, err) = s.finish();
    let out = lines.join("\n");
    for secret in [USER, KEY] {
        assert!(!out.contains(secret), "secret leaked on stdout");
        assert!(!err.contains(secret), "secret leaked on stderr");
    }
}
