//! Local comparison page: a password filled into the page the agent shares,
//! next to a sealed keyless session on the test site.
use keyless::{
    broker::{Broker, Credential},
    fixture::{Attacker, Fixture, GOOD, Proxy, USER, random_hex},
    harness::scan,
    http::{Request, Response, Server, write_response},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
};
use url::Url;

const PAGE: &str = include_str!("../demo/index.html");
const CHROME_MAC: &str = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const STYLE: &str = "<style>body{font:16px/1.5 system-ui,sans-serif;margin:0;padding:24px;background:#fff;color:#17181c}\
h1{font-size:22px;margin:0 0 16px}form{display:flex;flex-direction:column;gap:12px;max-width:320px}\
label{display:flex;flex-direction:column;gap:4px;font-size:14px}input{font:inherit;padding:8px 10px;border:1px solid #c9c5ba;border-radius:6px}\
button{font:inherit;font-weight:600;padding:10px 16px;border:0;border-radius:6px;background:#17181c;color:#fff;align-self:flex-start}</style>";
const BASE_LOGIN: &str = r#"<h1>Sign in</h1>
<form method="post" action="/baseline/login">
  <label>Email <input name="username" autocomplete="username"></label>
  <label>Password <input type="password" name="password" autocomplete="current-password"></label>
  <button>Sign in</button>
</form>"#;

#[derive(Default)]
struct Baseline {
    sessions: BTreeMap<String, Value>,
    latest: Option<Value>,
}

fn html(title: &str, body: &str) -> Response {
    Response::new(
        200,
        format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>{title}</title>{STYLE}</head><body>{body}</body></html>"),
    )
    .header("Content-Type", "text/html; charset=utf-8")
    .header("Cache-Control", "no-store")
}
fn json_response(v: Value) -> Response {
    Response::new(200, v.to_string())
        .header("Content-Type", "application/json")
        .header("Cache-Control", "no-store")
}
fn cookie<'a>(req: &'a Request, name: &str) -> &'a str {
    req.headers
        .get("cookie")
        .and_then(|c| {
            c.split(';')
                .find_map(|p| p.trim().strip_prefix(name)?.strip_prefix('='))
        })
        .unwrap_or("")
}

// The fill-into-page side: an ordinary site whose password field the "password manager" fills.
fn baseline(req: &Request, path: &str, st: &mut Baseline) -> Response {
    match (req.method.as_str(), path) {
        ("GET", "/baseline/login") => html("Sign in", BASE_LOGIN),
        ("POST", "/baseline/login") => {
            let form: BTreeMap<String, String> = url::form_urlencoded::parse(&req.body)
                .into_owned()
                .collect();
            if form.get("username").map(String::as_str) != Some(USER)
                || form.get("password").map(String::as_str) != Some(GOOD)
            {
                return html("Sign in failed", "<h1>Sign in failed</h1>");
            }
            let s = json!({"sid": random_hex(16), "csrf": random_hex(12), "access": random_hex(20)});
            let sid = s["sid"].as_str().unwrap().to_owned();
            let csrf = s["csrf"].as_str().unwrap().to_owned();
            st.sessions.insert(sid.clone(), s.clone());
            st.latest = Some(s);
            Response::new(302, "")
                .header("Location", "/baseline/app")
                .header("Set-Cookie", format!("sid={sid}; Path=/baseline; HttpOnly"))
                .header("Set-Cookie", format!("csrf={csrf}; Path=/baseline"))
        }
        ("GET", "/baseline/app") => {
            let Some(s) = st.sessions.get(cookie(req, "sid")) else {
                return Response::new(302, "").header("Location", "/baseline/login");
            };
            html(
                "Dashboard",
                &format!(
                    r#"<h1>Dashboard</h1>
<p>Welcome back. You have 3 open invoices totalling 1,240.00 EUR.</p>
<form method="post" action="/baseline/delete"><input type="hidden" name="csrf" value="{}"><button>Delete project</button></form>
<script>localStorage.setItem('auth', JSON.stringify({{ user: 'owner', access_token: '{}' }}));</script>"#,
                    s["csrf"].as_str().unwrap(),
                    s["access"].as_str().unwrap()
                ),
            )
        }
        ("GET", "/baseline/logout") => {
            st.latest = None;
            Response::new(302, "")
                .header("Location", "/baseline/login")
                .header("Set-Cookie", "sid=; Path=/baseline; Max-Age=0")
                .header("Set-Cookie", "csrf=; Path=/baseline; Max-Age=0")
        }
        // The password manager's side of the demo: what it fills into the page.
        ("GET", "/baseline/vault") => json_response(json!({"username": USER, "password": GOOD})),
        // Demo bookkeeping so the page can colour values; the simulated agent never calls it.
        ("GET", "/baseline/secrets") => {
            let mut v = st.latest.clone().unwrap_or_else(|| json!({}));
            v["password"] = GOOD.into();
            json_response(v)
        }
        _ => Response::new(404, "not found"),
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("{e}");
        std::process::exit(2);
    }
}

async fn run() -> std::io::Result<()> {
    let mut args = std::env::args().skip(1);
    let chrome = args
        .next()
        .or_else(|| std::env::var("CHROME").ok())
        .unwrap_or_else(|| CHROME_MAC.into());
    if !std::path::Path::new(&chrome).is_file() {
        return Err(std::io::Error::other(
            "Chromium not found: cargo run --bin demo -- /path/to/chrome [port]",
        ));
    }
    let port: u16 = args.next().and_then(|p| p.parse().ok()).unwrap_or(8765);

    let offlist = Attacker::start()?;
    let fixture = Fixture::start(offlist.origin())?;
    let allowed = BTreeSet::from([fixture.host()]);
    let proxy = Proxy::start(allowed.clone())?;
    let origin = fixture.origin();
    let creds = BTreeMap::from([(
        "classic".to_owned(),
        Credential {
            username: USER.into(),
            password: GOOD.into(),
            login_url: format!("{origin}/login"),
            post_login_url: format!("{origin}/app"),
            success: json!({"path":"/app"}),
        },
    )]);
    let broker = Broker::new(chrome, creds, allowed, Some(proxy.server.port));

    let rt = tokio::runtime::Handle::current();
    let base = Arc::new(Mutex::new(Baseline::default()));
    let current: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let minted = fixture.state.clone();
    let offlist_state = offlist.state.clone();
    let denied = proxy.denied.clone();
    let b = broker.clone();
    let _ui = Server::start_at(port, move |req, stream| {
        let Ok(u) = Url::parse(&format!("http://x{}", req.target)) else {
            let _ = write_response(stream, Response::new(400, ""));
            return;
        };
        let path = u.path().to_owned();
        let response = if path == "/" {
            Response::new(200, PAGE)
                .header("Content-Type", "text/html; charset=utf-8")
                .header("Cache-Control", "no-store")
        } else if path.starts_with("/baseline/") {
            baseline(&req, &path, &mut base.lock().unwrap())
        } else if path == "/api/broker" && req.method == "POST" {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            let method = body["method"].as_str().unwrap_or("");
            let mut params = body["params"].clone();
            if params.is_null() {
                params = json!({});
            }
            if method == "session.open" {
                // One live session at a time; credential is fixed to the test site.
                if let Some(old) = current.lock().unwrap().take() {
                    rt.block_on(b.handle("session.close", json!({"session": old})));
                }
                params = json!({"credential_id":"classic"});
            }
            if ![
                "session.open",
                "session.status",
                "session.observe",
                "session.act",
                "session.close",
            ]
            .contains(&method)
            {
                json_response(json!({"error":{"code":"unknown_method"}}))
            } else {
                let v = rt.block_on(b.handle(method, params));
                if method == "session.open" && v["session"].is_string() {
                    *current.lock().unwrap() = Some(v["session"].clone());
                }
                json_response(v)
            }
        } else if path == "/api/keyless/scan" {
            let tap = b.tap.lock().unwrap().clone();
            let mut canaries = minted.lock().unwrap().minted.clone();
            canaries.push(json!({"name":"vault_password","value":GOOD,"cls":"vault"}));
            let (leaks, rendered) = scan(&tap, &canaries);
            json_response(json!({
                "canaries": canaries.len(),
                "messages": tap.len(),
                "bytes": tap.iter().map(String::len).sum::<usize>(),
                "tail": tap[tap.len().saturating_sub(8)..],
                "leaks": leaks,
                "rendered": rendered,
                "offlist_connections": offlist_state.lock().unwrap().connections,
                "proxy_denied": denied.lock().unwrap().len(),
            }))
        } else {
            Response::new(404, "not found")
        };
        let _ = write_response(stream, response);
    })?;
    println!("keyless demo: http://localhost:{port}/");
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}
