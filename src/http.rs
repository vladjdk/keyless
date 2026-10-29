use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
impl Response {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![],
            body: body.into(),
        }
    }
    pub fn header(mut self, k: &str, v: impl Into<String>) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
}
fn read_crlf(stream: &mut TcpStream) -> io::Result<String> {
    let mut bytes = Vec::new();
    let mut byte = [0];
    while !bytes.ends_with(b"\r\n") {
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        if bytes.len() > 65536 {
            return Err(io::Error::other("line too large"));
        }
    }
    bytes.truncate(bytes.len() - 2);
    String::from_utf8(bytes).map_err(io::Error::other)
}
pub fn read_request(stream: &mut TcpStream) -> io::Result<Request> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut head = Vec::new();
    let mut b = [0];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut b)?;
        head.push(b[0]);
        if head.len() > 65536 {
            return Err(io::Error::other("headers too large"));
        }
    }
    let text = String::from_utf8(head).map_err(io::Error::other)?;
    let mut lines = text.split("\r\n");
    let mut start = lines.next().unwrap_or("").split_whitespace();
    let method = start
        .next()
        .ok_or_else(|| io::Error::other("no method"))?
        .to_owned();
    let target = start
        .next()
        .ok_or_else(|| io::Error::other("no target"))?
        .to_owned();
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.to_ascii_lowercase();
            if headers.contains_key(&key)
                && ["content-length", "transfer-encoding"].contains(&key.as_str())
            {
                return Err(io::Error::other("duplicate body framing header"));
            }
            headers.insert(key, v.trim().to_owned());
        }
    }
    let body = if let Some(encoding) = headers.remove("transfer-encoding") {
        if !encoding.eq_ignore_ascii_case("chunked") || headers.contains_key("content-length") {
            return Err(io::Error::other(
                "ambiguous or unsupported transfer encoding",
            ));
        }
        let mut body = Vec::new();
        loop {
            let line = read_crlf(stream)?;
            let n = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16)
                .map_err(io::Error::other)?;
            if n == 0 {
                let mut trailer_bytes = 0;
                loop {
                    let trailer = read_crlf(stream)?;
                    trailer_bytes += trailer.len();
                    if trailer_bytes > 65536 {
                        return Err(io::Error::other("trailers too large"));
                    }
                    if trailer.is_empty() {
                        break;
                    }
                }
                break;
            }
            if n > 1024 * 1024 - body.len() {
                return Err(io::Error::other("body too large"));
            }
            let offset = body.len();
            body.resize(offset + n, 0);
            stream.read_exact(&mut body[offset..])?;
            let mut crlf = [0; 2];
            stream.read_exact(&mut crlf)?;
            if crlf != *b"\r\n" {
                return Err(io::Error::other("invalid chunk boundary"));
            }
        }
        headers.insert("content-length".into(), body.len().to_string());
        body
    } else {
        let n = headers
            .get("content-length")
            .map(|s| s.parse::<usize>())
            .transpose()
            .map_err(io::Error::other)?
            .unwrap_or(0);
        if n > 1024 * 1024 {
            return Err(io::Error::other("body too large"));
        }
        let mut body = vec![0; n];
        stream.read_exact(&mut body)?;
        body
    };
    Ok(Request {
        method,
        target,
        headers,
        body,
    })
}
pub fn write_response(stream: &mut TcpStream, r: Response) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: close\r\n",
        r.status,
        if r.status == 200 { "OK" } else { "Response" },
        r.body.len()
    )?;
    for (k, v) in r.headers {
        write!(stream, "{k}: {v}\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(&r.body)
}
pub struct Server {
    pub port: u16,
    stop: Arc<AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}
impl Server {
    pub fn start(
        handler: impl Fn(Request, &mut TcpStream) + Send + Sync + 'static,
    ) -> io::Result<Self> {
        Self::start_with_connection(handler, || {})
    }
    /// Like `start`, on a fixed loopback port (0 picks a free one).
    pub fn start_at(
        port: u16,
        handler: impl Fn(Request, &mut TcpStream) + Send + Sync + 'static,
    ) -> io::Result<Self> {
        Self::listen(TcpListener::bind(("127.0.0.1", port))?, handler, || {})
    }
    pub fn start_with_connection(
        handler: impl Fn(Request, &mut TcpStream) + Send + Sync + 'static,
        connected: impl Fn() + Send + Sync + 'static,
    ) -> io::Result<Self> {
        Self::listen(TcpListener::bind("127.0.0.1:0")?, handler, connected)
    }
    fn listen(
        listener: TcpListener,
        handler: impl Fn(Request, &mut TcpStream) + Send + Sync + 'static,
        connected: impl Fn() + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let handler = Arc::new(handler);
        let task = thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        connected();
                        let h = handler.clone();
                        thread::spawn(move || {
                            if let Ok(req) = read_request(&mut stream) {
                                h(req, &mut stream);
                            }
                        });
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            port,
            stop,
            task: Some(task),
        })
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.task.take() {
            let _ = t.join();
        }
    }
}
pub fn get_json(port: u16, path: &str) -> io::Result<serde_json::Value> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n"
    )?;
    let mut bytes = Vec::new();
    s.read_to_end(&mut bytes)?;
    let i = bytes
        .windows(4)
        .position(|x| x == b"\r\n\r\n")
        .ok_or_else(|| io::Error::other("bad response"))?;
    serde_json::from_slice(&bytes[i + 4..]).map_err(io::Error::other)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_duplicate_body_framing_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(b"GET / HTTP/1.1\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });
        let (mut s, _) = listener.accept().unwrap();
        let request = read_request(&mut s);
        t.join().unwrap();
        assert!(request.is_err());
    }
    #[test]
    fn decodes_chunked_uploads_before_proxy_forwarding() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(b"POST /api/login HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nx=y\r\n2;ext=yes\r\n&z\r\n0\r\nTrailer: unused\r\n\r\n").unwrap();
        });
        let (mut s, _) = listener.accept().unwrap();
        let request = read_request(&mut s);
        t.join().unwrap();
        let request = request.unwrap();
        assert_eq!(request.body, b"x=y&z");
        assert_eq!(request.headers["content-length"], "5");
        assert!(!request.headers.contains_key("transfer-encoding"));
    }
    #[test]
    fn accepts_fragmented_requests_from_nonblocking_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(b"GET /frag HTTP/1.1\r\n").unwrap();
            thread::sleep(Duration::from_millis(50));
            s.write_all(b"Host: localhost\r\n\r\n").unwrap();
        });
        let (mut s, _) = listener.accept().unwrap();
        s.set_nonblocking(true).unwrap();
        let request = read_request(&mut s);
        t.join().unwrap();
        assert_eq!(request.unwrap().target, "/frag");
    }
    #[test]
    fn parses_post_without_losing_body() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let t = thread::spawn(move || {
            let mut s = TcpStream::connect(addr).unwrap();
            s.write_all(b"POST /login HTTP/1.1\r\nContent-Length: 3\r\nCookie: sid=abc\r\n\r\nx=y")
                .unwrap();
        });
        let (mut stream, _) = listener.accept().unwrap();
        let req = read_request(&mut stream).unwrap();
        assert_eq!(req.body, b"x=y");
        assert_eq!(req.headers["cookie"], "sid=abc");
        t.join().unwrap();
    }
}
