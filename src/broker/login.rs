use super::*;

impl Broker {
    pub(super) async fn login(self: &Arc<Self>, s: &Arc<Session>) -> Result<()> {
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
        // One getDocument for both lookups: a second call invalidates earlier node ids.
        let doc = cdp
            .send("DOM.getDocument", json!({"depth": 0}), Some(&login.sid))
            .await?;
        let mut ids = [0; 2];
        let user_selector = s
            .cred
            .username_selector
            .as_deref()
            .unwrap_or("input[name=username]");
        for (id, selector) in ids.iter_mut().zip([user_selector, "input[type=password]"]) {
            let q = json!({"nodeId": doc["root"]["nodeId"], "selector": selector});
            let r = cdp.send("DOM.querySelector", q, Some(&login.sid)).await?;
            *id = r["nodeId"].as_u64().unwrap_or(0);
        }
        let [user, pass] = ids;
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
        let visible = ax["nodes"].to_string().contains(&s.cred.password);
        self.diag
            .lock()
            .unwrap()
            .ax_probe
            .push(json!({"login": want.path(), "passwordVisibleInAX": visible}));
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
    pub(super) async fn scan_vault(&self, s: &Session, sid: &str) -> Result<bool> {
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
}
