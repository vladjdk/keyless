use crate::{
    Error, Result,
    cdp::Cdp,
    fixture::random_hex,
    secrets::{above_floor, leaves, matches, variants},
    sleep, text,
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use url::Url;
mod agent;
mod browser;
mod events;
mod gate;
mod login;
pub use gate::{Approver, Boxed, Classifier, Gate, Summary, pattern};
#[derive(Clone, Default)]
pub struct Credential {
    pub username: String,
    pub password: String,
    pub login_url: String,
    pub post_login_url: String,
    pub success: Value,
    /// CSS selector for the username field; `input[name=username]` when unset.
    pub username_selector: Option<String>,
    /// `false` is the `safe-methods` mode (GET and HEAD only). `true` lets other methods
    /// through to the gate's patterns, classifier and owner.
    pub writes: bool,
}
#[derive(Default)]
pub struct Diagnostics {
    pub masks: Vec<Value>,
    pub audit: Vec<Value>,
    pub popups_closed: usize,
    pub dialogs_dropped: usize,
    pub resource_types: BTreeMap<String, usize>,
    pub ax_probe: Vec<Value>,
    pub errors: Vec<String>,
}
#[derive(Clone)]
struct Page {
    target: String,
    sid: String,
}
struct SessionData {
    state: String,
    result: Option<String>,
    cdp: Option<Arc<Cdp>>,
    proc: Option<Child>,
    dir: Option<tempfile::TempDir>,
    vault: Vec<String>,
    secrets: BTreeSet<String>,
    tainted: BTreeSet<u64>,
    agent_typed: BTreeSet<u64>,
    ours: BTreeSet<String>,
    closing: BTreeSet<String>,
    deferred: Vec<String>,
    creating: usize,
    booted: bool,
    page: Option<Page>,
    snapshot: u64,
    refs: BTreeMap<String, (u64, String, String)>,
    /// Label of the element the agent last clicked and the page title, as the agent saw them.
    clicked: String,
    title: String,
    /// Refusal codes for requests the gate stopped since the agent's last action.
    refusals: Vec<&'static str>,
}
struct Session {
    cred: Credential,
    data: Mutex<SessionData>,
}
pub struct Broker {
    chrome: String,
    creds: BTreeMap<String, Credential>,
    allowed: BTreeSet<String>,
    proxy: Option<u16>,
    gate: Gate,
    sessions: Mutex<BTreeMap<String, Arc<Session>>>,
    suspended: AtomicBool,
    pub tap: Mutex<Vec<String>>,
    pub diag: Mutex<Diagnostics>,
}
impl Broker {
    pub fn new(
        chrome: String,
        creds: BTreeMap<String, Credential>,
        allowed: BTreeSet<String>,
        proxy: Option<u16>,
    ) -> Arc<Self> {
        Self::with_gate(chrome, creds, allowed, proxy, Gate::default())
    }
    pub fn with_gate(
        chrome: String,
        creds: BTreeMap<String, Credential>,
        allowed: BTreeSet<String>,
        proxy: Option<u16>,
        gate: Gate,
    ) -> Arc<Self> {
        Arc::new(Self {
            chrome,
            creds,
            allowed,
            proxy,
            gate,
            sessions: Mutex::new(BTreeMap::new()),
            suspended: AtomicBool::new(false),
            tap: Mutex::new(vec![]),
            diag: Mutex::new(Diagnostics::default()),
        })
    }
    pub async fn handle(self: &Arc<Self>, method: &str, p: Value) -> Value {
        let v = match self.dispatch(method, p).await {
            Ok(v) => v,
            Err(e) => {
                if let Some(detail) = e.detail {
                    self.diag.lock().unwrap().errors.push(detail);
                }
                json!({"error":{"code":e.code}})
            }
        };
        self.tap.lock().unwrap().push(v.to_string());
        v
    }
    async fn dispatch(self: &Arc<Self>, method: &str, p: Value) -> Result<Value> {
        if method == "initialize" {
            return Ok(json!({"protocol":"0.0-spike","profile":"development"}));
        }
        if method == "credentials.list" {
            let list: Vec<Value> = self
                .creds
                .iter()
                .map(|(id, c)| {
                    let origin = Url::parse(&c.login_url).map(|u| u.origin().ascii_serialization());
                    json!({"id": id, "username": c.username, "origin": origin.unwrap_or_default()})
                })
                .collect();
            return Ok(json!({ "credentials": list }));
        }
        if method == "session.open" {
            if self.suspended.load(Ordering::SeqCst) {
                return Err(Error::policy("suspended"));
            }
            let cred = self
                .creds
                .get(text(&p["credential_id"]))
                .ok_or_else(|| Error::policy("denied_by_policy"))?
                .clone();
            let id = format!("s_{}", random_hex(8));
            let session = Arc::new(Session {
                cred,
                data: Mutex::new(SessionData {
                    state: "opening".into(),
                    result: None,
                    cdp: None,
                    proc: None,
                    dir: None,
                    vault: vec![],
                    secrets: BTreeSet::new(),
                    tainted: BTreeSet::new(),
                    agent_typed: BTreeSet::new(),
                    ours: BTreeSet::new(),
                    closing: BTreeSet::new(),
                    deferred: vec![],
                    creating: 0,
                    booted: false,
                    page: None,
                    snapshot: 0,
                    refs: BTreeMap::new(),
                    clicked: String::new(),
                    title: String::new(),
                    refusals: vec![],
                }),
            });
            self.sessions
                .lock()
                .unwrap()
                .insert(id.clone(), session.clone());
            let broker = self.clone();
            tokio::spawn(async move {
                if let Err(e) = broker.login(&session).await {
                    if let Some(detail) = e.detail {
                        broker.diag.lock().unwrap().errors.push(detail);
                    }
                    session.data.lock().unwrap().result = Some(e.code.into());
                    broker.destroy(&session, "login_failed");
                }
            });
            return Ok(json!({"session":id,"state":"opening","retry_after_ms":300}));
        }
        let s = self
            .sessions
            .lock()
            .unwrap()
            .get(text(&p["session"]))
            .cloned()
            .ok_or_else(|| Error::policy("unknown_session"))?;
        let state = s.data.lock().unwrap().state.clone();
        match method {
            "session.status" => Ok(json!({"state":state,"result":s.data.lock().unwrap().result})),
            "session.close" => {
                self.destroy(&s, "closed");
                Ok(json!({"state":s.data.lock().unwrap().state}))
            }
            "session.observe" | "session.act" => {
                if state == "opening" || state == "sealed" {
                    return Err(Error::policy("session_sealed"));
                }
                if state != "active" {
                    return Err(Error::policy(match state.as_str() {
                        "closed" => "session_closed",
                        "killed" => "session_killed",
                        _ => "session_login_failed",
                    }));
                }
                if method == "session.observe" {
                    self.observe(&s).await
                } else {
                    self.act(&s, p).await
                }
            }
            _ => Err(Error::policy("unknown_method")),
        }
    }
    // One URL rule for agent navigation and every intercepted browser request.
    fn permits(&self, u: &Url) -> bool {
        ["http", "https"].contains(&u.scheme())
            && self
                .allowed
                .contains(&u[url::Position::BeforeHost..url::Position::AfterPort])
            && u.username().is_empty()
            && u.password().is_none()
    }
    fn destroy(&self, s: &Session, state: &str) {
        let mut d = s.data.lock().unwrap();
        if ["closed", "killed", "login_failed"].contains(&d.state.as_str()) {
            return;
        }
        d.state = state.into();
        if let Some(mut proc) = d.proc.take() {
            let _ = proc.kill();
            let _ = proc.wait();
        }
        d.cdp.take();
        d.dir.take();
    }
    pub fn shutdown(&self) {
        for s in self.sessions.lock().unwrap().values() {
            self.destroy(s, "closed");
        }
    }
}
fn walk_frames(t: &Value, out: &mut Vec<Value>) {
    out.push(t["frame"].clone());
    for child in t["childFrames"].as_array().into_iter().flatten() {
        walk_frames(child, out);
    }
}
fn cdp(s: &Session) -> Result<Arc<Cdp>> {
    s.data
        .lock()
        .unwrap()
        .cdp
        .clone()
        .ok_or_else(|| Error::internal("cdp unavailable"))
}
fn attr<'a>(n: &'a Value, name: &str) -> &'a str {
    n["attributes"]
        .as_array()
        .and_then(|a| {
            a.chunks(2)
                .find(|p| text(&p[0]) == name)
                .and_then(|p| p.get(1))
        })
        .map(text)
        .unwrap_or("")
}
fn walk_dom(n: &Value, out: &mut Vec<Value>) {
    out.push(n.clone());
    for key in ["children", "shadowRoots"] {
        for child in n[key].as_array().into_iter().flatten() {
            walk_dom(child, out);
        }
    }
    if !n["contentDocument"].is_null() {
        walk_dom(&n["contentDocument"], out);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn protocol_has_development_handshake_and_enum_errors() {
        let b = Broker::new("unused".into(), BTreeMap::new(), BTreeSet::new(), None);
        assert_eq!(
            b.handle("initialize", json!({})).await,
            json!({"protocol":"0.0-spike","profile":"development"})
        );
        assert_eq!(
            b.handle("session.open", json!({"credential_id":"missing"}))
                .await["error"]["code"],
            "denied_by_policy"
        );
        assert_eq!(
            b.handle("session.observe", json!({"session":"missing"}))
                .await["error"]["code"],
            "unknown_session"
        );
        assert_eq!(b.tap.lock().unwrap().len(), 3);
    }
    #[test]
    fn navigation_and_requests_share_one_url_rule() {
        let b = Broker::new(
            "unused".into(),
            BTreeMap::new(),
            BTreeSet::from(["localhost:8080".into()]),
            None,
        );
        let ok = |u: &str| b.permits(&Url::parse(u).unwrap());
        assert!(ok("http://localhost:8080/app"));
        assert!(ok("https://localhost:8080/app?q=1"));
        for denied in [
            "http://localhost:9090/app",
            "http://127.0.0.1:8080/app",
            "http://user:pw@localhost:8080/app",
            "ws://localhost:8080/ws",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "view-source:http://localhost:8080/",
            "data:text/html,hi",
        ] {
            assert!(!ok(denied), "{denied}");
        }
    }
}
