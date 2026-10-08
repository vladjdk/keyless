use super::*;

impl Broker {
    pub(super) async fn event(&self, s: &Session, event: Value) -> Result<()> {
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
                    diag.audit.push(json!({
                        "host": host,
                        "path": path,
                        "method": method,
                        "type": p["resourceType"],
                        "state": state,
                        "decision": if ok { "permit" } else { "forbid" },
                    }));
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
    pub(super) fn add_secret(&self, s: &Session, value: &str) {
        if above_floor(value) {
            s.data.lock().unwrap().secrets.insert(value.into());
        }
    }
    pub(super) async fn refresh_secrets(&self, s: &Session, sid: &str) -> Result<()> {
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
            let id = json!({"storageId": {
                "securityOrigin": u.origin().ascii_serialization(),
                "isLocalStorage": local,
            }});
            let Ok(v) = cdp
                .send("DOMStorage.getDOMStorageItems", id, Some(sid))
                .await
            else {
                continue;
            };
            let mut values = vec![];
            for entry in v["entries"].as_array().into_iter().flatten() {
                leaves(&entry[1], &mut values);
            }
            for x in values {
                self.add_secret(s, &x);
            }
        }
        Ok(())
    }
}
