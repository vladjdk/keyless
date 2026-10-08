use super::*;

impl Broker {
    pub(super) async fn launch(self: &Arc<Self>, s: &Arc<Session>) -> Result<()> {
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
    pub(super) async fn close_foreign(&self, s: &Session, id: &str) {
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
    pub(super) async fn new_page(&self, s: &Session) -> Result<Page> {
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
    pub(super) async fn frame(&self, s: &Session, sid: &str) -> Result<Value> {
        Ok(cdp(s)?
            .send("Page.getFrameTree", json!({}), Some(sid))
            .await?["frameTree"]["frame"]
            .clone())
    }
    pub(super) async fn settle(&self, s: &Session, sid: &str) {
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
    pub(super) async fn goto(&self, s: &Session, sid: &str, url: &str) -> Result<()> {
        cdp(s)?
            .send("Page.navigate", json!({"url":url}), Some(sid))
            .await?;
        self.settle(s, sid).await;
        Ok(())
    }
    pub(super) async fn query(&self, s: &Session, sid: &str, selector: &str) -> Result<u64> {
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
    pub(super) async fn node_eval(
        &self,
        s: &Session,
        sid: &str,
        node: u64,
        function: &str,
    ) -> Result<Value> {
        let cdp = cdp(s)?;
        let v = cdp
            .send("DOM.resolveNode", json!({"nodeId":node}), Some(sid))
            .await?;
        let call = json!({
            "objectId": v["object"]["objectId"],
            "functionDeclaration": function,
            "returnByValue": true,
        });
        let r = cdp.send("Runtime.callFunctionOn", call, Some(sid)).await?;
        Ok(r["result"]["value"].clone())
    }
    pub(super) async fn key(&self, s: &Session, sid: &str, key: &str) -> Result<()> {
        let code = match key {
            "Enter" => 13,
            "Tab" => 9,
            "Escape" => 27,
            _ => return Err(Error::policy("denied_by_policy")),
        };
        let cdp = cdp(s)?;
        for kind in ["keyDown", "keyUp"] {
            let mut p = json!({
                "type": kind,
                "key": key,
                "code": key,
                "windowsVirtualKeyCode": code,
                "nativeVirtualKeyCode": code,
            });
            if kind == "keyDown" && key == "Enter" {
                p["text"] = "\r".into();
            }
            cdp.send("Input.dispatchKeyEvent", p, Some(sid)).await?;
        }
        Ok(())
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
