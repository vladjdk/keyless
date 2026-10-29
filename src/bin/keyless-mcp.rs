//! Dogfood server: the broker as an MCP stdio server, so an agent such as Claude Code can drive
//! real logins. Development profile only: it runs as your user, so an agent with a shell can
//! still read its memory and the Keychain item. See docs/DOGFOOD.md.
//!
//! Config: $KEYLESS_CONFIG or ~/.config/keyless/dogfood.json. Passwords: macOS Keychain,
//! service "keyless", account = credential id. Owner prompts: a macOS dialog.
use keyless::{
    broker::{Approver, Boxed, Broker, Credential, Gate, Summary},
    fixture::Proxy,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, Write},
    path::PathBuf,
    process::Command,
    sync::Arc,
};
use url::Url;

fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_default())
}
fn config_path() -> PathBuf {
    std::env::var_os("KEYLESS_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".config/keyless/dogfood.json"))
}
fn keychain(id: &str) -> Result<String, String> {
    let out = Command::new("security")
        .args(["find-generic-password", "-s", "keyless", "-a", id, "-w"])
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("no Keychain item: service keyless, account {id}"));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .trim_end_matches('\n')
        .to_owned())
}

/// Asks the owner with a native dialog. Times out to Block after 60 seconds.
/// KEYLESS_OWNER=deny blocks everything without asking, for unattended runs.
struct Dialog;
impl Approver for Dialog {
    fn approve<'a>(&'a self, s: &'a Summary, reason: &'a str) -> Boxed<'a, bool> {
        Box::pin(async move {
            if std::env::var("KEYLESS_OWNER").as_deref() == Ok("deny") {
                audit(json!({"owner": "blocked", "reason": reason, "request": s.to_json()}));
                return false;
            }
            let fields = if s.fields.is_empty() {
                "none".into()
            } else {
                s.fields.join(", ")
            };
            let query = if s.query.is_empty() {
                String::new()
            } else {
                format!("?{}", s.query.join("&"))
            };
            // Facts first. The label and title are the site's words, so they come last and quoted.
            let message = format!(
                "An agent's browser wants to send:\n\n{} {}{}{}\nForm fields: {}\nWhy keyless stopped it: {}\n\nClicked: \u{201c}{}\u{201d}\nPage: \u{201c}{}\u{201d}",
                s.method, s.origin, s.path, query, fields, reason, s.clicked, s.title
            );
            let script = "on run argv\n display dialog (item 1 of argv) with title \"keyless\" buttons {\"Block\", \"Allow once\"} default button \"Block\" cancel button \"Block\" with icon caution giving up after 60\n return button returned of result\nend run";
            let out = tokio::task::spawn_blocking(move || {
                Command::new("osascript")
                    .args(["-e", script, &message])
                    .output()
            })
            .await;
            let allowed = matches!(out, Ok(Ok(o)) if String::from_utf8_lossy(&o.stdout).trim() == "Allow once");
            audit(
                json!({"owner": if allowed {"allowed"} else {"blocked"}, "reason": reason, "request": s.to_json()}),
            );
            allowed
        })
    }
}
fn audit(entry: Value) {
    let path = config_path().with_file_name("audit.jsonl");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "{entry}");
    }
}

/// The broker, the egress proxy it uses (kept alive by the caller) and startup notes.
type Loaded = (Arc<Broker>, Option<Proxy>, Vec<String>);
fn load() -> Result<Loaded, String> {
    let path = config_path();
    let raw = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let cfg: Value = serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
    let chrome = cfg["chrome"]
        .as_str()
        .unwrap_or("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
        .to_owned();
    let mut creds = BTreeMap::new();
    let mut allowed = BTreeSet::new();
    let mut notes = vec![];
    for (id, c) in cfg["credentials"].as_object().into_iter().flatten() {
        let login =
            Url::parse(c["login_url"].as_str().unwrap_or("")).map_err(|e| format!("{id}: {e}"))?;
        allowed.insert(login[url::Position::BeforeHost..url::Position::AfterPort].to_owned());
        creds.insert(
            id.clone(),
            Credential {
                username: c["username"].as_str().unwrap_or("").into(),
                password: keychain(id)?,
                login_url: login.to_string(),
                post_login_url: c["post_login_url"]
                    .as_str()
                    .unwrap_or(login.as_str())
                    .into(),
                success: c["success"].clone(),
                username_selector: c["username_selector"].as_str().map(Into::into),
                writes: c["writes"].as_bool().unwrap_or(false),
            },
        );
    }
    // The fixture proxy speaks plain HTTP only; HTTPS sites run on request interception alone.
    let all_http = cfg["credentials"]
        .as_object()
        .into_iter()
        .flatten()
        .all(|(_, c)| {
            c["login_url"]
                .as_str()
                .is_some_and(|u| u.starts_with("http://"))
        });
    let proxy = if all_http {
        Some(Proxy::start(allowed.clone()).map_err(|e| e.to_string())?)
    } else {
        notes.push("HTTPS credential present: running without the egress proxy".into());
        None
    };
    let classifier = keyless::jev::Jev::from_env().map(|j| Arc::new(j) as _);
    notes.push(
        if classifier.is_some() {
            "classifier: Jev"
        } else {
            "classifier: none (set TYPESAFE_API_KEY)"
        }
        .into(),
    );
    let gate = Gate {
        classifier,
        approver: Some(Arc::new(Dialog)),
        ..Default::default()
    };
    let broker = Broker::with_gate(
        chrome,
        creds,
        allowed,
        proxy.as_ref().map(|p| p.server.port),
        gate,
    );
    Ok((broker, proxy, notes))
}

fn tools() -> Value {
    let session = json!({"type":"string","description":"Session id from keyless_open"});
    json!([
        {"name":"keyless_credentials","description":"List the logins keyless can open for you. You never see or handle the passwords: keyless types them itself. Never ask the user for a password, one-time code or recovery code.","inputSchema":{"type":"object","properties":{}}},
        {"name":"keyless_open","description":"Open a logged-in browser session for a credential id. keyless logs in by itself and returns once the session is active or failed.","inputSchema":{"type":"object","properties":{"credential_id":{"type":"string"}},"required":["credential_id"]}},
        {"name":"keyless_observe","description":"Get a text snapshot of the current page: a list of elements with refs. Secrets show as [withheld].","inputSchema":{"type":"object","properties":{"session":session},"required":["session"]}},
        {"name":"keyless_act","description":"Act on the page. action is click, type (ref + text), key (key, e.g. Enter) or navigate (url). click and type need the snapshot number and a ref from the latest keyless_observe. If the result has refused: [\"needs_owner\"], the owner declined or has not approved that request; do not retry it or try another route to the same thing, tell the user instead.","inputSchema":{"type":"object","properties":{"session":session,"action":{"type":"string","enum":["click","type","key","navigate"]},"snapshot":{"type":"integer"},"ref":{"type":"string"},"text":{"type":"string"},"key":{"type":"string"},"url":{"type":"string"}},"required":["session","action"]}},
        {"name":"keyless_close","description":"Close a session and its browser.","inputSchema":{"type":"object","properties":{"session":session},"required":["session"]}}
    ])
}

async fn call(b: &Arc<Broker>, name: &str, args: Value) -> Value {
    match name {
        "keyless_credentials" => b.handle("credentials.list", json!({})).await,
        "keyless_open" => {
            let opened = b.handle("session.open", args).await;
            if opened["session"].is_null() {
                return opened;
            }
            let mut status = json!({});
            for _ in 0..120 {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                status = b
                    .handle("session.status", json!({"session":opened["session"]}))
                    .await;
                if !["opening", "sealed"].contains(&status["state"].as_str().unwrap_or("")) {
                    break;
                }
            }
            json!({"session":opened["session"],"state":status["state"],"result":status["result"]})
        }
        "keyless_observe" => b.handle("session.observe", args).await,
        "keyless_act" => b.handle("session.act", args).await,
        "keyless_close" => b.handle("session.close", args).await,
        _ => json!({"error":{"code":"unknown_tool"}}),
    }
}

#[tokio::main]
async fn main() {
    let (broker, _proxy, notes) = match load() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("keyless-mcp: {e}");
            std::process::exit(2);
        }
    };
    for n in &notes {
        eprintln!("keyless-mcp: {n}");
    }
    let mut seen_audit = 0;
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some(id) = msg.get("id").cloned() else {
            continue;
        }; // notifications need no reply
        let p = &msg["params"];
        let result = match msg["method"].as_str().unwrap_or("") {
            "initialize" => json!({
                "protocolVersion": p["protocolVersion"].as_str().unwrap_or("2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "keyless", "version": env!("CARGO_PKG_VERSION")},
            }),
            "ping" => json!({}),
            "tools/list" => json!({"tools": tools()}),
            "tools/call" => {
                let out = call(
                    &broker,
                    p["name"].as_str().unwrap_or(""),
                    p["arguments"].clone(),
                )
                .await;
                json!({"content":[{"type":"text","text":out.to_string()}],"isError":!out["error"].is_null()})
            }
            _ => {
                let reply = json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"method not found"}});
                let _ = writeln!(stdout, "{reply}");
                let _ = stdout.flush();
                continue;
            }
        };
        // Every gate decision lands in audit.jsonl next to the config.
        {
            let diag = broker.diag.lock().unwrap();
            for a in &diag.audit[seen_audit..] {
                if !a["reason"].is_null() || a["decision"] == "forbid" {
                    audit(a.clone());
                }
            }
            seen_audit = diag.audit.len();
        }
        let _ = writeln!(
            stdout,
            "{}",
            json!({"jsonrpc":"2.0","id":id,"result":result})
        );
        let _ = stdout.flush();
    }
    broker.shutdown();
}
