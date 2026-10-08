use super::*;

impl Broker {
    pub(super) async fn observe(&self, s: &Session) -> Result<Value> {
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
                let shown = if role == "RootWebArea" { "page" } else { role };
                let mut item = json!({"ref": reference, "role": shown, "name": name});
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
    pub(super) async fn act(&self, s: &Session, p: Value) -> Result<Value> {
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
