use crate::{
    Error, Result,
    broker::{Broker, Credential},
    fixture::{Attacker, BAD, Fixture, GOOD, Proxy, USER},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
// Independent of the broker matcher: this scanner sees only serialized agent output and fixture canaries.
fn encodings(secret: &str) -> BTreeMap<String, String> {
    use base64::Engine as _;
    let bytes = secret.as_bytes();
    let mut escaped = String::new();
    let mut hex = String::new();
    for b in bytes {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(b) {
            escaped.push(*b as char);
        } else {
            escaped.push_str(&format!("%{b:02X}"));
        }
        hex.push_str(&format!("{b:02x}"));
    }
    let mut out = BTreeMap::from([
        ("plain".into(), secret.into()),
        ("url".into(), escaped),
        ("hex".into(), hex),
    ]);
    for offset in 0..3 {
        let mut padded = vec![0; offset];
        padded.extend_from_slice(bytes);
        let full = base64::engine::general_purpose::STANDARD.encode(&padded);
        let full = full.trim_end_matches('=');
        let begin = match offset {
            0 => 0,
            1 => 2,
            _ => 3,
        };
        let end = full.len() - usize::from(padded.len() % 3 != 0);
        if begin <= end {
            let part = &full[begin..end];
            out.insert(format!("base64@{offset}"), part.into());
            out.insert(
                format!("base64url@{offset}"),
                part.replace('+', "-").replace('/', "_"),
            );
        }
    }
    out
}
fn strings(v: &Value, out: &mut String) {
    match v {
        Value::String(s) => out.push_str(s),
        Value::Array(a) => {
            for v in a {
                strings(v, out);
            }
        }
        Value::Object(o) => {
            for v in o.values() {
                strings(v, out);
            }
        }
        _ => {}
    }
}
pub fn scan(messages: &[String], canaries: &[Value]) -> (Vec<Value>, Vec<Value>) {
    let raw = messages.join("\n");
    let mut reassembled = String::new();
    for m in messages {
        if let Ok(v) = serde_json::from_str(m) {
            strings(&v, &mut reassembled);
        }
    }
    let mut leaks = vec![];
    let mut info = vec![];
    for c in canaries {
        let secret = c["value"].as_str().unwrap();
        for (encoding, v) in encodings(secret) {
            if v.len() < 8 {
                continue;
            }
            let where_seen = if raw.contains(&v) {
                Some("raw")
            } else if reassembled.contains(&v) {
                Some("reassembled")
            } else {
                None
            };
            if let Some(where_seen) = where_seen {
                let record = json!({"canary":c["name"],"cls":c["cls"],"encoding":encoding,"where":where_seen});
                if c["cls"] == "rendered" {
                    info.push(record);
                } else {
                    leaks.push(record);
                }
            }
        }
        if c["cls"] != "rendered" {
            for chunk in secret.as_bytes().windows(12) {
                let Ok(chunk) = std::str::from_utf8(chunk) else {
                    continue;
                };
                if raw.contains(chunk) && !leaks.iter().any(|l| l["canary"] == c["name"]) {
                    leaks.push(json!({"canary":c["name"],"cls":c["cls"],"encoding":"chunk12","where":"raw"}));
                    break;
                }
            }
        }
    }
    (leaks, info)
}

async fn sleep(ms: u64) {
    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
}
fn check(checks: &mut Vec<Value>, name: impl Into<String>, pass: bool, detail: Value) {
    checks.push(json!({"name":name.into(),"pass":pass,"detail":detail}));
}
fn find<'a>(obs: &'a Value, role: &str, name: &str) -> Option<&'a Value> {
    obs["items"]
        .as_array()?
        .iter()
        .find(|i| i["role"] == role && i["name"] == name)
}
fn has(obs: &Value, text: &str) -> bool {
    obs["items"].as_array().is_some_and(|a| {
        a.iter()
            .any(|i| i["name"].as_str().is_some_and(|s| s.contains(text)))
    })
}
async fn observe(b: &Arc<Broker>, s: &Value) -> Value {
    b.handle("session.observe", json!({"session":s})).await
}
async fn act(b: &Arc<Broker>, s: &Value, mut p: Value) -> Value {
    p["session"] = s.clone();
    b.handle("session.act", p).await
}
async fn home(b: &Arc<Broker>, s: &Value, origin: &str) -> Value {
    act(
        b,
        s,
        json!({"action":"navigate","url":format!("{origin}/app")}),
    )
    .await;
    observe(b, s).await
}
async fn click(b: &Arc<Broker>, s: &Value, obs: &Value, role: &str, name: &str) -> Result<Value> {
    let target = find(obs, role, name)
        .ok_or_else(|| Error::internal(format!("missing {role} {name}: {obs}")))?;
    Ok(act(
        b,
        s,
        json!({"action":"click","snapshot":obs["snapshot"],"ref":target["ref"]}),
    )
    .await)
}
async fn open(b: &Arc<Broker>, credential: &str, origin: &str) -> Value {
    let o = b
        .handle("session.open", json!({"credential_id":credential}))
        .await;
    if !o["error"].is_null() {
        return json!({"open":o});
    }
    let s = &o["session"];
    let sealed_observe = observe(b, s).await;
    let sealed_act = act(
        b,
        s,
        json!({"action":"navigate","url":format!("{origin}/echo")}),
    )
    .await;
    let mut status = Value::Null;
    for _ in 0..80 {
        sleep(250).await;
        status = b.handle("session.status", json!({"session":s})).await;
        if !["opening", "sealed"].contains(&status["state"].as_str().unwrap_or("")) {
            break;
        }
    }
    json!({"session":s,"st":status,"sealedObserve":sealed_observe,"sealedAct":sealed_act})
}
struct Shutdown(Arc<Broker>);
impl Drop for Shutdown {
    fn drop(&mut self) {
        self.0.shutdown();
    }
}
fn counts(keys: impl Iterator<Item = String>) -> BTreeMap<String, usize> {
    let mut m = BTreeMap::new();
    for key in keys {
        *m.entry(key).or_default() += 1;
    }
    m
}
fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}
pub async fn run_once(chrome: &str, use_proxy: bool) -> Result<Value> {
    let attacker = Attacker::start().map_err(|e| Error::internal(e.to_string()))?;
    let fixture = Fixture::start(attacker.origin()).map_err(|e| Error::internal(e.to_string()))?;
    let allowed = BTreeSet::from([fixture.host()]);
    let proxy = if use_proxy {
        Some(Proxy::start(allowed.clone()).map_err(|e| Error::internal(e.to_string()))?)
    } else {
        None
    };
    let origin = fixture.origin();
    let credentials = [
        ("classic", "/login", GOOD, json!({"path":"/app"})),
        ("spa", "/spa-login", GOOD, json!({"selector":"#welcome"})),
        (
            "spa_mirror",
            "/spa-login?mirror=1",
            GOOD,
            json!({"selector":"#welcome"}),
        ),
        ("bad", "/login", BAD, json!({"path":"/app"})),
    ]
    .into_iter()
    .map(|(id, path, password, success)| {
        (
            id.into(),
            Credential {
                username: USER.into(),
                password: password.into(),
                login_url: format!("{origin}{path}"),
                post_login_url: format!("{origin}/app"),
                success,
            },
        )
    })
    .collect();
    let broker = Broker::new(
        chrome.into(),
        credentials,
        allowed,
        proxy.as_ref().map(|p| p.server.port),
    );
    let _shutdown = Shutdown(broker.clone());
    let b = &broker;
    let mut checks = vec![];
    b.handle("initialize", json!({})).await;
    b.handle("credentials.list", json!({})).await;
    let a = open(b, "classic", &origin).await;
    check(
        &mut checks,
        "classic login reaches active",
        a["st"]["state"] == "active",
        a["st"].clone(),
    );
    check(
        &mut checks,
        "observe refused while sealed",
        a["sealedObserve"]["error"]["code"] == "session_sealed",
        a["sealedObserve"]["error"].clone(),
    );
    check(
        &mut checks,
        "act refused while sealed",
        a["sealedAct"]["error"]["code"] == "session_sealed",
        a["sealedAct"]["error"].clone(),
    );
    if a["st"]["state"] != "active" {
        let diag = b.diag.lock().unwrap();
        return Err(Error::internal(format!(
            "classic login failed proxy={use_proxy}: {}; errors={:?}; audit={:?}",
            a["st"], diag.errors, diag.audit
        )));
    }
    let s = &a["session"];
    let mut obs = observe(b, s).await;
    check(
        &mut checks,
        "dashboard readable",
        find(&obs, "heading", "Dashboard").is_some() && has(&obs, "3 open invoices"),
        obs["url"].clone(),
    );
    let first_snapshot = obs["snapshot"].clone();
    let stale_ref = find(&obs, "link", "Invoices")
        .map(|v| v["ref"].clone())
        .unwrap_or(Value::Null);
    click(b, s, &obs, "link", "Invoices").await?;
    obs = observe(b, s).await;
    check(
        &mut checks,
        "read task: invoice table visible after click",
        has(&obs, "INV-1002") && has(&obs, "380.00"),
        obs["url"].clone(),
    );
    let stale = act(
        b,
        s,
        json!({"action":"click","snapshot":first_snapshot,"ref":stale_ref}),
    )
    .await;
    check(
        &mut checks,
        "stale ref rejected",
        stale["error"]["code"] == "stale_ref",
        stale["error"].clone(),
    );
    for (link, label) in [
        ("Session diagnostics", "echo"),
        ("API tokens", "token"),
        ("Preview", "xss"),
    ] {
        obs = home(b, s, &origin).await;
        click(b, s, &obs, "link", link).await?;
        obs = observe(b, s).await;
        if label == "echo" {
            check(
                &mut checks,
                "echo page reached and still readable",
                find(&obs, "heading", "Session diagnostics").is_some(),
                obs["url"].clone(),
            );
            check(
                &mut checks,
                "echo page has withheld markers",
                has(&obs, "[withheld]"),
                Value::Null,
            );
        }
    }
    obs = home(b, s, &origin).await;
    let box_ref = find(&obs, "searchbox", "Search")
        .ok_or_else(|| Error::internal("searchbox missing"))?["ref"]
        .clone();
    act(b,s,json!({"action":"type","snapshot":obs["snapshot"],"ref":box_ref,"text":"northwind invoices"})).await;
    let typed = observe(b, s).await;
    check(
        &mut checks,
        "agent sees its own typed value",
        typed["items"]
            .as_array()
            .is_some_and(|a| a.iter().any(|i| i["value"] == "northwind invoices")),
        Value::Null,
    );
    act(b, s, json!({"action":"key","key":"Enter"})).await;
    obs = observe(b, s).await;
    check(
        &mut checks,
        "search (GET) works",
        has(&obs, "Results for: northwind invoices"),
        obs["url"].clone(),
    );
    obs = home(b, s, &origin).await;
    click(b, s, &obs, "button", "Delete project").await?;
    sleep(300).await;
    check(
        &mut checks,
        "POST blocked in safe-methods",
        !fixture.state.lock().unwrap().deleted,
        Value::Null,
    );
    obs = home(b, s, &origin).await;
    click(b, s, &obs, "link", "Confirm email").await?;
    sleep(200).await;
    let mutated = fixture.state.lock().unwrap().mutated;
    obs = home(b, s, &origin).await;
    click(b, s, &obs, "link", "Partner portal").await?;
    sleep(400).await;
    check(
        &mut checks,
        "redirect hop to attacker blocked",
        !attacker
            .state
            .lock()
            .unwrap()
            .hits
            .iter()
            .any(|h| h["url"].as_str().is_some_and(|u| u.starts_with("/steal"))),
        Value::Null,
    );
    obs = home(b, s, &origin).await;
    let before = b.diag.lock().unwrap().popups_closed;
    click(b, s, &obs, "link", "Open in new window").await?;
    sleep(500).await;
    let after = b.diag.lock().unwrap().popups_closed;
    check(
        &mut checks,
        "popup closed",
        after > before,
        json!(after - before),
    );
    obs = observe(b, s).await;
    check(
        &mut checks,
        "session still usable after popup",
        find(&obs, "heading", "Dashboard").is_some(),
        Value::Null,
    );
    for url in [
        format!("{}/direct", attacker.origin()),
        "javascript:alert(1)".into(),
        "file:///etc/passwd".into(),
        format!("view-source:{origin}/echo"),
        "data:text/html,hi".into(),
    ] {
        let r = act(b, s, json!({"action":"navigate","url":url})).await;
        check(
            &mut checks,
            format!("navigate denied: {}", url.split(':').next().unwrap()),
            r["error"]["code"] == "denied_by_policy",
            r["error"].clone(),
        );
    }
    let key = act(b, s, json!({"action":"key","key":"F12"})).await;
    check(
        &mut checks,
        "non-allowlisted key denied",
        key["error"]["code"] == "denied_by_policy",
        Value::Null,
    );
    b.handle("session.close", json!({"session":s})).await;
    let spa = open(b, "spa", &origin).await;
    check(
        &mut checks,
        "SPA login (no navigation) reaches active",
        spa["st"]["state"] == "active",
        spa["st"].clone(),
    );
    if spa["st"]["state"] == "active" {
        let o = observe(b, &spa["session"]).await;
        check(
            &mut checks,
            "SPA session lands on dashboard in fresh tab",
            find(&o, "heading", "Dashboard").is_some(),
            Value::Null,
        );
        b.handle("session.close", json!({"session":spa["session"]}))
            .await;
    }
    let mirror = open(b, "spa_mirror", &origin).await;
    check(
        &mut checks,
        "SPA that mirrors the password into the page fails closed",
        mirror["st"]["state"] == "login_failed" && mirror["st"]["result"] == "secret_residue",
        mirror["st"].clone(),
    );
    let bad = open(b, "bad", &origin).await;
    check(
        &mut checks,
        "wrong password (site echoes it) fails with enum only",
        bad["st"]["state"] == "login_failed" && bad["st"]["result"] == "success_assertion_failed",
        bad["st"].clone(),
    );
    let oracle = open(b, "classic", &origin).await;
    let os = &oracle["session"];
    obs = observe(b, os).await;
    let box_ref = find(&obs, "searchbox", "Search")
        .ok_or_else(|| Error::internal("oracle searchbox missing"))?["ref"]
        .clone();
    let wrong=act(b,os,json!({"action":"type","snapshot":obs["snapshot"],"ref":box_ref,"text":"hunter2-not-the-password"})).await;
    let right=act(b,os,json!({"action":"type","snapshot":obs["snapshot"],"ref":box_ref,"text":format!("x {GOOD} y")})).await;
    let opened = b
        .handle("session.open", json!({"credential_id":"classic"}))
        .await;
    check(
        &mut checks,
        "wrong guess is ordinary typing",
        wrong["ok"] == true,
        Value::Null,
    );
    check(
        &mut checks,
        "typing the vault secret kills the session",
        right["error"]["code"] == "session_killed",
        right["error"].clone(),
    );
    check(
        &mut checks,
        "subject suspended afterwards",
        opened["error"]["code"] == "suspended",
        opened["error"].clone(),
    );
    sleep(300).await;
    // Read back the fixture's actual HTTP report, not the broker's internal secret set.
    let minted = crate::http::get_json(fixture.server.port, "/__minted")
        .map_err(|e| Error::internal(e.to_string()))?;
    let minted = minted
        .as_array()
        .ok_or_else(|| Error::internal("minted not array"))?;
    let mut canaries = vec![
        json!({"name":"vault_password","value":GOOD,"cls":"vault"}),
        json!({"name":"vault_password_bad_record","value":BAD,"cls":"vault"}),
    ];
    canaries.extend(minted.iter().cloned());
    let messages = b.tap.lock().unwrap().clone();
    let raw = messages.join("\n");
    let (leaks, info) = scan(&messages, &canaries);
    let reversed = minted
        .iter()
        .filter(|m| m["name"] == "csrf_cookie")
        .any(|m| {
            raw.contains(
                &m["value"]
                    .as_str()
                    .unwrap()
                    .chars()
                    .rev()
                    .collect::<String>(),
            )
        });
    let diag = b.diag.lock().unwrap();
    let benign: Vec<_> = diag
        .masks
        .iter()
        .filter(|m| ["/app", "/invoices", "/search"].contains(&m["path"].as_str().unwrap_or("")))
        .collect();
    let with_masks: Vec<_> = benign
        .iter()
        .filter(|m| m["masked"].as_u64().unwrap_or(0) > 0)
        .collect();
    let attacker_state = attacker.state.lock().unwrap();
    let attacker_kinds = counts(attacker_state.hits.iter().map(|h| {
        format!(
            "{} {}",
            text(&h["kind"]),
            text(&h["url"]).split('?').next().unwrap_or("")
        )
    }));
    let forbidden = counts(
        diag.audit
            .iter()
            .filter(|a| a["decision"] == "forbid")
            .map(|a| format!("{} {}", text(&a["method"]), text(&a["type"]))),
    );
    let proxy_denied = proxy.as_ref().map(|p| {
        let denied = p.denied.lock().unwrap();
        counts(denied.iter().map(|v| text(&v["kind"]).to_owned()))
    });
    let scanned = canaries.iter().filter(|c| c["cls"] != "rendered").count();
    // Extra regression gates, in addition to every original hostile-agent case.
    check(
        &mut checks,
        "broker has no internal errors",
        diag.errors.is_empty(),
        json!(diag.errors),
    );
    if use_proxy {
        check(
            &mut checks,
            "proxy blocks all attacker egress",
            attacker_state.hits.is_empty(),
            json!(attacker_kinds),
        );
        check(
            &mut checks,
            "proxy blocks fixture WebSocket upgrades",
            fixture.state.lock().unwrap().ws_upgrades == 0,
            Value::Null,
        );
    }
    Ok(
        json!({"implementation":"rust","profile":"development","proxy":use_proxy,"checks":checks,"leaks":leaks,"canariesScanned":scanned,"tapBytes":raw.len(),
        "notClaimed":{"renderedApiTokenVisible":!info.is_empty(),"xssReversedCookieVisible":reversed,"stateChangedByGet":mutated},
        "egress":{"attackerHits":attacker_kinds,"attackerTcpConnections":attacker_state.connections,"fixtureWebSocketUpgrades":fixture.state.lock().unwrap().ws_upgrades,"proxyDenied":proxy_denied,"interceptedResourceTypes":diag.resource_types,"forbidden":forbidden},
        "falseTrips":{"benignObservations":benign.len(),"withMasks":with_masks.len(),"detail":with_masks},"axProbe":diag.ax_probe,"dialogsDropped":diag.dialogs_dropped,"brokerErrors":diag.errors}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scanner_detects_leaky_agent_messages_and_reassembled_fields() {
        let secret = "abcdef0123456789abcdef";
        let canary = json!({"name":"leaky","value":secret,"cls":"session"});
        let (leaks, _) = scan(
            &[json!({"name":secret}).to_string()],
            std::slice::from_ref(&canary),
        );
        assert!(!leaks.is_empty());
        let (leaks, _) = scan(
            &[json!({"a":&secret[..10],"b":&secret[10..]}).to_string()],
            &[canary],
        );
        assert!(leaks.iter().any(|l| l["where"] == "reassembled"));
    }
}
