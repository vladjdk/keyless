use crate::{
    Error, Result,
    cdp::Cdp,
    fixture::random_hex,
    secrets::{above_floor, leaves, matches, variants},
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
#[derive(Clone)]
pub struct Credential {
    pub username: String,
    pub password: String,
    pub login_url: String,
    pub post_login_url: String,
    pub success: Value,
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
    refs: BTreeMap<String, (u64, String)>,
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
        Arc::new(Self {
            chrome,
            creds,
            allowed,
            proxy,
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
            return Ok(
                json!({"credentials":self.creds.iter().map(|(id,c)|json!({"id":id,"username":c.username,"origin":Url::parse(&c.login_url).unwrap().origin().ascii_serialization()})).collect::<Vec<_>>() }),
            );
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
    async fn login(self: &Arc<Self>, s: &Arc<Session>) -> Result<()> {
        self.launch(s).await?;
        {
            let mut d = s.data.lock().unwrap();
            d.state = "sealed".into();
            d.vault = vec![s.cred.password.clone()];
        }
        let login = self.new_page(s).await?;
        let cdp = cdp(s)?;
        cdp.send("Target.setDiscoverTargets", json!({"discover":true}), None)
            .await?;
        sleep(100).await;
        s.data.lock().unwrap().booted = true;
        self.goto(s, &login.sid, &s.cred.login_url).await?;
        let want = Url::parse(&s.cred.login_url).map_err(|_| Error::policy("origin_mismatch"))?;
        let mut frame = self.frame(s, &login.sid).await?;
        let at = Url::parse(text(&frame["url"])).map_err(|_| Error::policy("origin_mismatch"))?;
        if at.origin() != want.origin() || at.path() != want.path() {
            return Err(Error::policy("origin_mismatch"));
        }
        let doc = cdp
            .send("DOM.getDocument", json!({"depth":0}), Some(&login.sid))
            .await?;
        let user = cdp
            .send(
                "DOM.querySelector",
                json!({"nodeId":doc["root"]["nodeId"],"selector":"input[name=username]"}),
                Some(&login.sid),
            )
            .await?["nodeId"]
            .as_u64()
            .unwrap_or(0);
        let pass = cdp
            .send(
                "DOM.querySelector",
                json!({"nodeId":doc["root"]["nodeId"],"selector":"input[type=password]"}),
                Some(&login.sid),
            )
            .await?["nodeId"]
            .as_u64()
            .unwrap_or(0);
        if user == 0 || pass == 0 {
            return Err(Error::policy("field_not_found"));
        }
        let desc = cdp
            .send("DOM.describeNode", json!({"nodeId":pass}), Some(&login.sid))
            .await?["node"]
            .clone();
        if attr(&desc, "type") != "password" {
            return Err(Error::policy("field_not_found"));
        }
        cdp.send("DOM.focus", json!({"nodeId":user}), Some(&login.sid))
            .await?;
        cdp.send(
            "Input.insertText",
            json!({"text":s.cred.username}),
            Some(&login.sid),
        )
        .await?;
        cdp.send("DOM.focus", json!({"nodeId":pass}), Some(&login.sid))
            .await?;
        let focused =
            "function(){return document.activeElement===this && this.type===\"password\"}";
        if self.node_eval(s, &login.sid, pass, focused).await? != true {
            return Err(Error::policy("origin_mismatch"));
        }
        let loader = frame["loaderId"].clone();
        s.data
            .lock()
            .unwrap()
            .tainted
            .insert(desc["backendNodeId"].as_u64().unwrap_or(0));
        cdp.send(
            "Input.insertText",
            json!({"text":s.cred.password}),
            Some(&login.sid),
        )
        .await?;
        frame = self.frame(s, &login.sid).await?;
        if frame["loaderId"] != loader
            || self.node_eval(s, &login.sid, pass, focused).await? != true
        {
            return Err(Error::policy("origin_mismatch"));
        }
        let ax = cdp
            .send("Accessibility.getFullAXTree", json!({}), Some(&login.sid))
            .await?;
        self.diag.lock().unwrap().ax_probe.push(json!({"login":want.path(),"passwordVisibleInAX":ax["nodes"].to_string().contains(&s.cred.password)}));
        self.key(s, &login.sid, "Enter").await?;
        let mut ok = false;
        for _ in 0..40 {
            sleep(100).await;
            if let Some(path) = s.cred.success["path"].as_str() {
                if let Ok(frame) = self.frame(s, &login.sid).await {
                    ok = Url::parse(text(&frame["url"])).is_ok_and(|u| u.path() == path);
                }
            } else if let Some(selector) = s.cred.success["selector"].as_str() {
                ok = self
                    .query(s, &login.sid, selector)
                    .await
                    .is_ok_and(|n| n != 0);
            }
            if ok {
                break;
            }
        }
        if !ok {
            return Err(Error::policy("success_assertion_failed"));
        }
        if self.scan_vault(s, &login.sid).await? {
            return Err(Error::policy("secret_residue"));
        }
        self.refresh_secrets(s, &login.sid).await?;
        let page = self.new_page(s).await?;
        self.goto(s, &page.sid, &s.cred.post_login_url).await?;
        cdp.send("Target.closeTarget", json!({"targetId":login.target}), None)
            .await?;
        s.data.lock().unwrap().ours.remove(&login.target);
        let landed = Url::parse(text(&self.frame(s, &page.sid).await?["url"]))
            .map_err(|_| Error::policy("success_assertion_failed"))?;
        if landed.path() != Url::parse(&s.cred.post_login_url).unwrap().path() {
            return Err(Error::policy("success_assertion_failed"));
        }
        let mut d = s.data.lock().unwrap();
        // The owner may have closed the session while login was finishing; never revive it.
        if d.state == "sealed" {
            d.page = Some(page);
            d.tainted.clear();
            d.state = "active".into();
        }
        Ok(())
    }
    async fn launch(self: &Arc<Self>, s: &Arc<Session>) -> Result<()> {
        let dir = tempfile::Builder::new()
            .prefix("bf-spike-rust-")
            .tempdir()
            .map_err(|e| Error::internal(e.to_string()))?;
        let (input_read, input_write) = pipe()?;
        let (output_read, output_write) = pipe()?;
        let mut command = Command::new(&self.chrome);
        command.args([
            "--headless=new",
            "--remote-debugging-pipe",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-background-networking",
            "--disable-component-update",
            "--disable-sync",
            "--disable-extensions",
            "--disable-quic",
            "--disable-features=BackForwardCache,Translate,OptimizationHints,MediaRouter",
            "--password-store=basic",
            "--use-mock-keychain",
        ]);
        command.arg(format!("--user-data-dir={}", dir.path().display()));
        if let Some(port) = self.proxy {
            command
                .arg(format!("--proxy-server=http://127.0.0.1:{port}"))
                .arg("--proxy-bypass-list=<-loopback>");
        }
        command
            .arg("about:blank")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let read_fd = input_read.as_raw_fd();
        let write_fd = output_write.as_raw_fd();
        // SAFETY: pre_exec uses only async-signal-safe dup2; source fds are owned, valid and >=10.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(read_fd, 3) == -1 || libc::dup2(write_fd, 4) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let proc = command
            .spawn()
            .map_err(|e| Error::internal(e.to_string()))?;
        drop(input_read);
        drop(output_write);
        let (client, mut events) = Cdp::new(input_write, output_read);
        {
            let mut d = s.data.lock().unwrap();
            d.dir = Some(dir);
            d.proc = Some(proc);
            d.cdp = Some(client.clone());
        }
        let weak_b = Arc::downgrade(self);
        let weak_s = Arc::downgrade(s);
        tokio::spawn(async move {
            while let Some(event) = events.recv().await {
                let (Some(b), Some(s)) = (weak_b.upgrade(), weak_s.upgrade()) else {
                    break;
                };
                tokio::spawn(async move {
                    let _ = b.event(&s, event).await;
                });
            }
        });
        client
            .send(
                "Target.setAutoAttach",
                json!({"autoAttach":true,"waitForDebuggerOnStart":true,"flatten":true}),
                None,
            )
            .await?;
        Ok(())
    }
    async fn event(&self, s: &Session, event: Value) -> Result<()> {
        let p = &event["params"];
        let sid = event["sessionId"].as_str();
        let cdp = cdp(s)?;
        let sealed = s.data.lock().unwrap().state == "sealed";
        match text(&event["method"]) {
            "Fetch.requestPaused" => {
                let mut host = "?".to_owned();
                let mut path = "?".to_owned();
                let mut ok = false;
                if let Ok(u) = Url::parse(text(&p["request"]["url"])) {
                    host = u[url::Position::BeforeHost..url::Position::AfterPort].into();
                    path = u.path().into();
                    ok = self.permits(&u);
                }
                let method = text(&p["request"]["method"]);
                let state = s.data.lock().unwrap().state.clone();
                if state == "active" && !["GET", "HEAD"].contains(&method) {
                    ok = false;
                }
                {
                    let mut diag = self.diag.lock().unwrap();
                    *diag
                        .resource_types
                        .entry(text(&p["resourceType"]).into())
                        .or_default() += 1;
                    diag.audit.push(json!({"host":host,"path":path,"method":method,"type":p["resourceType"],"state":state,"decision":if ok {"permit"} else {"forbid"}}));
                }
                if ok {
                    cdp.send(
                        "Fetch.continueRequest",
                        json!({"requestId":p["requestId"]}),
                        sid,
                    )
                    .await?;
                } else {
                    cdp.send(
                        "Fetch.failRequest",
                        json!({"requestId":p["requestId"],"errorReason":"BlockedByClient"}),
                        sid,
                    )
                    .await?;
                }
            }
            "Page.javascriptDialogOpening" => {
                self.diag.lock().unwrap().dialogs_dropped += 1;
                cdp.send("Page.handleJavaScriptDialog", json!({"accept":false}), sid)
                    .await?;
            }
            "Target.attachedToTarget" => {
                let child = text(&p["sessionId"]);
                let t = &p["targetInfo"];
                let foreign = {
                    let d = s.data.lock().unwrap();
                    text(&t["type"]) == "page"
                        && !d.ours.contains(text(&t["targetId"]))
                        && d.creating == 0
                };
                if foreign {
                    self.close_foreign(s, text(&t["targetId"])).await;
                    return Ok(());
                }
                let _ = cdp.send("Network.enable", json!({}), Some(child)).await;
                let _ = cdp
                    .send(
                        "Fetch.enable",
                        json!({"patterns":[{"urlPattern":"*"}]}),
                        Some(child),
                    )
                    .await;
                if p["waitingForDebugger"] == true {
                    let _ = cdp
                        .send("Runtime.runIfWaitingForDebugger", json!({}), Some(child))
                        .await;
                }
            }
            "Target.targetCreated" => {
                let t = &p["targetInfo"];
                let id = text(&t["targetId"]);
                let close = {
                    let mut d = s.data.lock().unwrap();
                    if text(&t["type"]) != "page" || d.ours.contains(id) || d.closing.contains(id) {
                        false
                    } else if d.creating > 0 {
                        d.deferred.push(id.into());
                        false
                    } else {
                        true
                    }
                };
                if close {
                    self.close_foreign(s, id).await;
                }
            }
            "Network.responseReceivedExtraInfo" | "Network.requestWillBeSentExtraInfo" => {
                if let Some(headers) = p["headers"].as_object() {
                    for (k, v) in headers {
                        let v = text(v);
                        match k.to_ascii_lowercase().as_str() {
                            "set-cookie" => {
                                for c in v.split('\n') {
                                    self.add_secret(
                                        s,
                                        c.split(';')
                                            .next()
                                            .unwrap_or("")
                                            .split_once('=')
                                            .map(|(_, v)| v)
                                            .unwrap_or(""),
                                    );
                                }
                            }
                            "cookie" => {
                                for c in v.split(';') {
                                    self.add_secret(
                                        s,
                                        c.split_once('=').map(|(_, v)| v.trim()).unwrap_or(""),
                                    );
                                }
                            }
                            "authorization" => {
                                for x in v.split_whitespace() {
                                    self.add_secret(s, x);
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            "Network.requestWillBeSent" if sealed => {
                if let Ok(u) = Url::parse(text(&p["request"]["url"])) {
                    for (_, v) in u.query_pairs() {
                        self.add_secret(s, &v);
                    }
                    if let Some(hash) = u.fragment() {
                        for (_, v) in url::form_urlencoded::parse(hash.as_bytes()) {
                            self.add_secret(s, &v);
                        }
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
    async fn close_foreign(&self, s: &Session, id: &str) {
        let booted = {
            let mut d = s.data.lock().unwrap();
            if !d.closing.insert(id.into()) {
                return;
            }
            d.booted
        };
        if booted {
            self.diag.lock().unwrap().popups_closed += 1;
        }
        if let Ok(cdp) = cdp(s) {
            let _ = cdp
                .send("Target.closeTarget", json!({"targetId":id}), None)
                .await;
        }
    }
    async fn new_page(&self, s: &Session) -> Result<Page> {
        s.data.lock().unwrap().creating += 1;
        let cdp = cdp(s)?;
        let v = cdp
            .send("Target.createTarget", json!({"url":"about:blank"}), None)
            .await?;
        let target = text(&v["targetId"]).to_owned();
        let deferred = {
            let mut d = s.data.lock().unwrap();
            d.ours.insert(target.clone());
            d.creating -= 1;
            std::mem::take(&mut d.deferred)
        };
        for id in deferred {
            if !s.data.lock().unwrap().ours.contains(&id) {
                self.close_foreign(s, &id).await;
            }
        }
        let v = cdp
            .send(
                "Target.attachToTarget",
                json!({"targetId":target,"flatten":true}),
                None,
            )
            .await?;
        let sid = text(&v["sessionId"]).to_owned();
        for method in ["Page.enable", "Network.enable", "DOM.enable"] {
            cdp.send(method, json!({}), Some(&sid)).await?;
        }
        cdp.send(
            "Fetch.enable",
            json!({"patterns":[{"urlPattern":"*"}]}),
            Some(&sid),
        )
        .await?;
        cdp.send(
            "Target.setAutoAttach",
            json!({"autoAttach":true,"waitForDebuggerOnStart":true,"flatten":true}),
            Some(&sid),
        )
        .await?;
        Ok(Page { target, sid })
    }
    async fn frame(&self, s: &Session, sid: &str) -> Result<Value> {
        Ok(cdp(s)?
            .send("Page.getFrameTree", json!({}), Some(sid))
            .await?["frameTree"]["frame"]
            .clone())
    }
    async fn settle(&self, s: &Session, sid: &str) {
        let mut last = None;
        for i in 0..12 {
            sleep(if i == 0 { 350 } else { 90 }).await;
            let Ok(f) = self.frame(s, sid).await else {
                return;
            };
            if last.as_ref() == Some(&f["url"]) {
                return;
            }
            last = Some(f["url"].clone());
        }
    }
    async fn goto(&self, s: &Session, sid: &str, url: &str) -> Result<()> {
        cdp(s)?
            .send("Page.navigate", json!({"url":url}), Some(sid))
            .await?;
        self.settle(s, sid).await;
        Ok(())
    }
    async fn query(&self, s: &Session, sid: &str, selector: &str) -> Result<u64> {
        let cdp = cdp(s)?;
        let doc = cdp
            .send("DOM.getDocument", json!({"depth":0}), Some(sid))
            .await?;
        Ok(cdp
            .send(
                "DOM.querySelector",
                json!({"nodeId":doc["root"]["nodeId"],"selector":selector}),
                Some(sid),
            )
            .await?["nodeId"]
            .as_u64()
            .unwrap_or(0))
    }
    async fn node_eval(&self, s: &Session, sid: &str, node: u64, function: &str) -> Result<Value> {
        let cdp = cdp(s)?;
        let v = cdp
            .send("DOM.resolveNode", json!({"nodeId":node}), Some(sid))
            .await?;
        Ok(cdp.send("Runtime.callFunctionOn",json!({"objectId":v["object"]["objectId"],"functionDeclaration":function,"returnByValue":true}),Some(sid)).await?["result"]["value"].clone())
    }
    async fn scan_vault(&self, s: &Session, sid: &str) -> Result<bool> {
        let cdp = cdp(s)?;
        let doc = cdp
            .send(
                "DOM.getDocument",
                json!({"depth":-1,"pierce":true}),
                Some(sid),
            )
            .await?;
        let mut nodes = vec![];
        walk_dom(&doc["root"], &mut nodes);
        for n in nodes {
            if text(&n["nodeName"]) == "INPUT"
                && (attr(&n, "type") == "password"
                    || s.data
                        .lock()
                        .unwrap()
                        .tainted
                        .contains(&n["backendNodeId"].as_u64().unwrap_or(0)))
            {
                let value = self
                    .node_eval(
                        s,
                        sid,
                        n["nodeId"].as_u64().unwrap_or(0),
                        "function(){return this.value}",
                    )
                    .await?;
                if !text(&value).is_empty() {
                    return Ok(true);
                }
            }
        }
        let blob = doc.to_string()
            + &cdp
                .send("Accessibility.getFullAXTree", json!({}), Some(sid))
                .await?
                .to_string();
        Ok(s.data
            .lock()
            .unwrap()
            .vault
            .iter()
            .any(|v| variants(v).iter().any(|x| blob.contains(x))))
    }
    fn add_secret(&self, s: &Session, value: &str) {
        if above_floor(value) {
            s.data.lock().unwrap().secrets.insert(value.into());
        }
    }
    async fn refresh_secrets(&self, s: &Session, sid: &str) -> Result<()> {
        let cdp = cdp(s)?;
        let v = cdp.send("Storage.getCookies", json!({}), None).await?;
        for c in v["cookies"].as_array().into_iter().flatten() {
            let value = text(&c["value"]);
            if c["httpOnly"] == true && value.len() >= 8 {
                s.data.lock().unwrap().secrets.insert(value.into());
            } else {
                self.add_secret(s, value);
            }
        }
        let frame = self.frame(s, sid).await?;
        let u = Url::parse(text(&frame["url"])).map_err(|e| Error::internal(e.to_string()))?;
        for local in [true, false] {
            if let Ok(v)=cdp.send("DOMStorage.getDOMStorageItems",json!({"storageId":{"securityOrigin":u.origin().ascii_serialization(),"isLocalStorage":local}}),Some(sid)).await {
                for entry in v["entries"].as_array().into_iter().flatten() {let mut values=vec![];leaves(&entry[1],&mut values);for x in values {self.add_secret(s,&x);}}
            }
        }
        Ok(())
    }
    async fn key(&self, s: &Session, sid: &str, key: &str) -> Result<()> {
        let code = match key {
            "Enter" => 13,
            "Tab" => 9,
            "Escape" => 27,
            _ => return Err(Error::policy("denied_by_policy")),
        };
        let mut p = json!({"type":"keyDown","key":key,"code":key,"windowsVirtualKeyCode":code,"nativeVirtualKeyCode":code});
        if key == "Enter" {
            p["text"] = "\r".into();
        }
        cdp(s)?.send("Input.dispatchKeyEvent", p, Some(sid)).await?;
        cdp(s)?.send("Input.dispatchKeyEvent",json!({"type":"keyUp","key":key,"code":key,"windowsVirtualKeyCode":code,"nativeVirtualKeyCode":code}),Some(sid)).await?;
        Ok(())
    }

    async fn observe(&self, s: &Session) -> Result<Value> {
        let sid = s.data.lock().unwrap().page.as_ref().unwrap().sid.clone();
        sleep(150).await;
        self.refresh_secrets(s, &sid).await?;
        let cdp = cdp(s)?;
        let doc = cdp
            .send(
                "DOM.getDocument",
                json!({"depth":-1,"pierce":true}),
                Some(&sid),
            )
            .await?;
        let mut nodes = vec![];
        walk_dom(&doc["root"], &mut nodes);
        {
            let mut d = s.data.lock().unwrap();
            for n in nodes {
                if text(&n["nodeName"]) == "INPUT" && attr(&n, "type") == "password" {
                    d.tainted.insert(n["backendNodeId"].as_u64().unwrap_or(0));
                }
            }
        }
        let tree = cdp.send("Page.getFrameTree", json!({}), Some(&sid)).await?["frameTree"].clone();
        let mut frames = vec![];
        walk_frames(&tree, &mut frames);
        let mut refs = BTreeMap::new();
        let mut items = vec![];
        const ROLES: &[&str] = &[
            "RootWebArea",
            "heading",
            "link",
            "button",
            "textbox",
            "searchbox",
            "checkbox",
            "radio",
            "combobox",
            "StaticText",
            "image",
            "img",
            "cell",
            "columnheader",
            "Iframe",
        ];
        for fr in frames {
            let Ok(ax) = cdp
                .send(
                    "Accessibility.getFullAXTree",
                    json!({"frameId":fr["id"]}),
                    Some(&sid),
                )
                .await
            else {
                continue;
            };
            for node in ax["nodes"].as_array().into_iter().flatten() {
                if node["ignored"] == true {
                    continue;
                }
                let role = text(&node["role"]["value"]);
                if !ROLES.contains(&role) {
                    continue;
                }
                let name = text(&node["name"]["value"]);
                let interactive = ![
                    "StaticText",
                    "RootWebArea",
                    "heading",
                    "image",
                    "img",
                    "cell",
                    "columnheader",
                    "Iframe",
                ]
                .contains(&role);
                if name.is_empty() && !interactive {
                    continue;
                }
                let reference = format!("e{}", items.len() + 1);
                let mut item = json!({"ref":reference,"role":if role=="RootWebArea" {"page"}else {role},"name":name});
                for p in node["properties"].as_array().into_iter().flatten() {
                    let key = text(&p["name"]);
                    if ["disabled", "checked", "expanded", "focused"].contains(&key)
                        && p["value"]["value"] == true
                    {
                        item[key] = true.into();
                    }
                }
                let backend = node["backendDOMNodeId"].as_u64().unwrap_or(0);
                {
                    let d = s.data.lock().unwrap();
                    if d.agent_typed.contains(&backend)
                        && !d.tainted.contains(&backend)
                        && !node["value"].is_null()
                    {
                        item["value"] = node["value"]["value"].clone();
                    }
                }
                refs.insert(reference, (backend, role.into()));
                items.push(item);
            }
        }
        let u =
            Url::parse(text(&tree["frame"]["url"])).map_err(|e| Error::internal(e.to_string()))?;
        let path = u
            .path()
            .split('/')
            .map(|seg| if above_floor(seg) { "[withheld]" } else { seg })
            .collect::<Vec<_>>()
            .join("/");
        let mut out_url = u.origin().ascii_serialization() + &path;
        let mut fields = vec![out_url.clone()];
        let mut slots = vec![None];
        for (i, item) in items.iter().enumerate() {
            fields.push(text(&item["name"]).into());
            slots.push(Some((i, "name")));
            if let Some(value) = item["value"].as_str() {
                fields.push(value.into());
                slots.push(Some((i, "value")));
            }
        }
        let hit = {
            let d = s.data.lock().unwrap();
            matches(&d.vault, &d.secrets, &fields)
        };
        let hit = match hit {
            Ok(v) => v,
            Err(code) => {
                self.destroy(s, "killed");
                return Err(Error::policy(code));
            }
        };
        for i in &hit {
            if let Some((n, key)) = slots[*i] {
                items[n][key] = "[withheld]".into();
            } else {
                out_url = "[withheld]".into();
            }
        }
        self.diag
            .lock()
            .unwrap()
            .masks
            .push(json!({"path":u.path(),"masked":hit.len(),"items":items.len()}));
        let snapshot = {
            let mut d = s.data.lock().unwrap();
            d.snapshot += 1;
            d.refs = refs;
            d.snapshot
        };
        Ok(
            json!({"snapshot":snapshot,"url":out_url,"query_stripped":u.query().is_some(),"items":items}),
        )
    }
    async fn act(&self, s: &Session, p: Value) -> Result<Value> {
        let sid = s.data.lock().unwrap().page.as_ref().unwrap().sid.clone();
        let action = text(&p["action"]);
        if action == "navigate" {
            let u = Url::parse(text(&p["url"]))
                .ok()
                .filter(|u| self.permits(u))
                .ok_or_else(|| Error::policy("denied_by_policy"))?;
            self.goto(s, &sid, u.as_str()).await?;
            return Ok(json!({"ok":true}));
        }
        if action == "key" {
            self.key(s, &sid, text(&p["key"])).await?;
            self.settle(s, &sid).await;
            return Ok(json!({"ok":true}));
        }
        let (backend, role) = {
            let d = s.data.lock().unwrap();
            if p["snapshot"].as_u64() != Some(d.snapshot) {
                return Err(Error::policy("stale_ref"));
            }
            d.refs
                .get(text(&p["ref"]))
                .cloned()
                .filter(|(b, _)| *b != 0)
                .ok_or_else(|| Error::policy("stale_ref"))?
        };
        let cdp = cdp(s)?;
        if action == "click" {
            cdp.send(
                "DOM.scrollIntoViewIfNeeded",
                json!({"backendNodeId":backend}),
                Some(&sid),
            )
            .await?;
            let v = cdp
                .send(
                    "DOM.getBoxModel",
                    json!({"backendNodeId":backend}),
                    Some(&sid),
                )
                .await?;
            let c = v["model"]["content"]
                .as_array()
                .ok_or_else(|| Error::internal("no box"))?;
            let x = [0, 2, 4, 6]
                .iter()
                .map(|i| c[*i].as_f64().unwrap_or(0.0))
                .sum::<f64>()
                / 4.0;
            let y = [1, 3, 5, 7]
                .iter()
                .map(|i| c[*i].as_f64().unwrap_or(0.0))
                .sum::<f64>()
                / 4.0;
            for event in ["mousePressed", "mouseReleased"] {
                cdp.send(
                    "Input.dispatchMouseEvent",
                    json!({"type":event,"x":x,"y":y,"button":"left","clickCount":1}),
                    Some(&sid),
                )
                .await?;
            }
            self.settle(s, &sid).await;
            return Ok(json!({"ok":true}));
        }
        if action == "type" {
            let value = text(&p["text"]);
            let vault_hit = s
                .data
                .lock()
                .unwrap()
                .vault
                .iter()
                .any(|v| variants(v).iter().any(|x| value.contains(x)));
            if vault_hit {
                self.suspended.store(true, Ordering::SeqCst);
                self.destroy(s, "killed");
                return Err(Error::policy("session_killed"));
            }
            if !["textbox", "searchbox", "combobox"].contains(&role.as_str())
                || s.data.lock().unwrap().tainted.contains(&backend)
            {
                return Err(Error::policy("denied_by_policy"));
            }
            cdp.send("DOM.focus", json!({"backendNodeId":backend}), Some(&sid))
                .await?;
            cdp.send("Input.insertText", json!({"text":value}), Some(&sid))
                .await?;
            s.data.lock().unwrap().agent_typed.insert(backend);
            return Ok(json!({"ok":true}));
        }
        Err(Error::policy("unknown_method"))
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
async fn sleep(ms: u64) {
    tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
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
fn pipe() -> Result<(File, File)> {
    let mut fds = [-1; 2];
    // SAFETY: pipe writes two descriptors into a correctly sized array. Duplicate >=10 to avoid collision with CDP fd3/fd4.
    unsafe {
        if libc::pipe(fds.as_mut_ptr()) != 0 {
            return Err(Error::internal(std::io::Error::last_os_error().to_string()));
        }
        let a = libc::fcntl(fds[0], libc::F_DUPFD_CLOEXEC, 10);
        let b = libc::fcntl(fds[1], libc::F_DUPFD_CLOEXEC, 10);
        libc::close(fds[0]);
        libc::close(fds[1]);
        if a < 0 || b < 0 {
            if a >= 0 {
                libc::close(a);
            }
            if b >= 0 {
                libc::close(b);
            }
            return Err(Error::internal("pipe duplication failed"));
        }
        Ok((File::from_raw_fd(a), File::from_raw_fd(b)))
    }
}
fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
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
