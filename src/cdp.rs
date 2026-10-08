pub const ALLOW: &[&str] = &[
    "Target.createTarget",
    "Target.attachToTarget",
    "Target.closeTarget",
    "Target.setDiscoverTargets",
    "Target.setAutoAttach",
    "Page.enable",
    "Page.navigate",
    "Page.getFrameTree",
    "Page.handleJavaScriptDialog",
    "Network.enable",
    "Storage.getCookies",
    "Fetch.enable",
    "Fetch.continueRequest",
    "Fetch.failRequest",
    "DOM.enable",
    "DOM.getDocument",
    "DOM.querySelector",
    "DOM.describeNode",
    "DOM.focus",
    "DOM.resolveNode",
    "DOM.getBoxModel",
    "DOM.scrollIntoViewIfNeeded",
    "DOMStorage.getDOMStorageItems",
    "Accessibility.getFullAXTree",
    "Input.insertText",
    "Input.dispatchKeyEvent",
    "Input.dispatchMouseEvent",
    "Runtime.callFunctionOn",
    "Runtime.runIfWaitingForDebugger",
];
pub fn allowed(method: &str) -> bool {
    ALLOW.contains(&method)
}
use crate::{Error, Result};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::sync::{mpsc, oneshot};

type Pending = HashMap<u64, oneshot::Sender<Result<Value>>>;
pub struct Cdp {
    writer: Mutex<File>,
    pending: Arc<Mutex<Pending>>,
    id: AtomicU64,
    closed: Arc<AtomicBool>,
}
impl Cdp {
    pub fn new(writer: File, reader: File) -> (Arc<Self>, mpsc::UnboundedReceiver<Value>) {
        let (events, rx) = mpsc::unbounded_channel();
        let cdp = Arc::new(Self {
            writer: Mutex::new(writer),
            pending: Arc::new(Mutex::new(HashMap::new())),
            id: AtomicU64::new(0),
            closed: Arc::new(AtomicBool::new(false)),
        });
        let pending = cdp.pending.clone();
        let closed = cdp.closed.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(reader);
            loop {
                let mut bytes = Vec::new();
                if !matches!(reader.read_until(0, &mut bytes), Ok(n) if n > 0) {
                    break;
                }
                if bytes.pop() != Some(0) {
                    break;
                }
                let Ok(v) = serde_json::from_slice::<Value>(&bytes) else {
                    break;
                };
                if let Some(id) = v["id"].as_u64() {
                    if let Some(tx) = pending.lock().unwrap().remove(&id) {
                        let result = if !v["error"].is_null() {
                            Err(Error::internal(v["error"].to_string()))
                        } else {
                            Ok(v["result"].clone())
                        };
                        let _ = tx.send(result);
                    }
                } else if events.send(v).is_err() {
                    break;
                }
            }
            closed.store(true, Ordering::SeqCst);
            for (_, tx) in pending.lock().unwrap().drain() {
                let _ = tx.send(Err(Error::internal("cdp closed")));
            }
        });
        (cdp, rx)
    }
    pub async fn send(&self, method: &str, params: Value, sid: Option<&str>) -> Result<Value> {
        if !allowed(method) {
            return Err(Error::internal("CDP method not on allowlist"));
        }
        let id = self.id.fetch_add(1, Ordering::SeqCst) + 1;
        let mut msg = json!({"id":id,"method":method,"params":params});
        if let Some(sid) = sid {
            msg["sessionId"] = sid.into();
        }
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().unwrap();
            if self.closed.load(Ordering::SeqCst) {
                return Err(Error::internal("cdp closed"));
            }
            pending.insert(id, tx);
        }
        let mut bytes = serde_json::to_vec(&msg).map_err(|e| Error::internal(e.to_string()))?;
        bytes.push(0);
        if let Err(e) = self.writer.lock().unwrap().write_all(&bytes) {
            self.pending.lock().unwrap().remove(&id);
            return Err(Error::internal(e.to_string()));
        }
        match tokio::time::timeout(Duration::from_secs(10), rx).await {
            Ok(Ok(v)) => v.map_err(|mut e| {
                e.detail = Some(format!("{method}: {}", e.detail.unwrap_or_default()));
                e
            }),
            other => {
                self.pending.lock().unwrap().remove(&id);
                Err(Error::internal(format!(
                    "cdp response timeout/closed: {other:?}"
                )))
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn socket_file(stream: std::os::unix::net::UnixStream) -> File {
        let fd: std::os::fd::OwnedFd = stream.into();
        File::from(fd)
    }
    #[tokio::test]
    async fn nul_pipe_frames_survive_fragmentation_and_route_events() {
        use std::os::unix::net::UnixStream;
        let (write, request) = UnixStream::pair().unwrap();
        let (read, mut response) = UnixStream::pair().unwrap();
        let (cdp, mut events) = Cdp::new(socket_file(write), socket_file(read));
        let peer = std::thread::spawn(move || {
            let mut request = BufReader::new(request);
            let mut bytes = Vec::new();
            request.read_until(0, &mut bytes).unwrap();
            bytes.pop();
            let v: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(v["method"], "Page.enable");
            assert_eq!(v["sessionId"], "child");
            let frames = format!(
                "{}\0{}\0",
                json!({"method":"Page.loadEventFired","params":{"timestamp":1},"sessionId":"child"}),
                json!({"id":v["id"],"result":{"ready":true}})
            );
            for chunk in frames.as_bytes().chunks(3) {
                response.write_all(chunk).unwrap();
            }
        });
        assert_eq!(
            cdp.send("Page.enable", json!({}), Some("child"))
                .await
                .unwrap()["ready"],
            true
        );
        assert_eq!(
            events.recv().await.unwrap()["method"],
            "Page.loadEventFired"
        );
        peer.join().unwrap();
    }
    #[tokio::test]
    async fn pipe_eof_rejects_pending_requests() {
        use std::os::unix::net::UnixStream;
        let (write, request) = UnixStream::pair().unwrap();
        let (read, response) = UnixStream::pair().unwrap();
        let (cdp, _) = Cdp::new(socket_file(write), socket_file(read));
        let peer = std::thread::spawn(move || {
            let mut request = BufReader::new(request);
            let mut bytes = Vec::new();
            request.read_until(0, &mut bytes).unwrap();
            drop(response);
        });
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            cdp.send("DOM.enable", json!({}), None),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        peer.join().unwrap();
        assert!(cdp.pending.lock().unwrap().is_empty());
    }
    #[tokio::test]
    async fn forbidden_methods_never_write_to_the_pipe() {
        use std::io::Read;
        use std::os::unix::net::UnixStream;
        let (write, mut request) = UnixStream::pair().unwrap();
        let (read, response) = UnixStream::pair().unwrap();
        let (cdp, _) = Cdp::new(socket_file(write), socket_file(read));
        assert!(
            cdp.send(
                "Runtime.evaluate",
                json!({"expression":"document.cookie"}),
                None
            )
            .await
            .is_err()
        );
        request.set_nonblocking(true).unwrap();
        let mut byte = [0];
        assert_eq!(
            request.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(response);
    }
    #[test]
    fn only_driver_methods_are_allowed() {
        assert!(allowed("DOM.getDocument"));
        for forbidden in [
            "Runtime.evaluate",
            "Page.captureScreenshot",
            "Network.getResponseBody",
            "Browser.getVersion",
        ] {
            assert!(!allowed(forbidden));
        }
    }
}
