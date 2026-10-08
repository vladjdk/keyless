// M0 spike broker: sealed login, allowlisted observation, secret matching, request policy.
// Single process, throwaway. Everything sent to the agent goes through emit(), which is the tap.

const { spawn } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { CDP } = require('./cdp');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const WITHHELD = '[withheld]';
const ROLES = new Set([
  'RootWebArea', 'heading', 'link', 'button', 'textbox', 'searchbox', 'checkbox', 'radio',
  'combobox', 'StaticText', 'image', 'img', 'cell', 'columnheader', 'Iframe',
]);
const KEYS = { Enter: 13, Tab: 9, Escape: 27 };

function entropy(s) {
  const c = {};
  for (const ch of s) c[ch] = (c[ch] || 0) + 1;
  return Object.values(c).reduce((h, n) => h - (n / s.length) * Math.log2(n / s.length), 0);
}
// A value counts as a session secret if it is long and token-shaped: digits mixed with letters,
// mixed case inside a run, or high character entropy. Plain words joined by separators do not.
const aboveFloor = (s) => typeof s === 'string' && s.length >= 12 && (
  (/[0-9]/.test(s) && /[A-Za-z]/.test(s)) || /[a-z][A-Z]|[A-Z][a-z]+[A-Z]/.test(s) || entropy(s) >= 4.0);

function b64Alignments(s) {
  const out = [];
  const b = Buffer.from(s);
  for (let off = 0; off < 3; off++) {
    const e = Buffer.concat([Buffer.alloc(off), b]).toString('base64').replace(/=+$/, '');
    const lead = [0, 2, 3][off];
    const tail = (off + b.length) % 3 ? 1 : 0;
    const v = e.slice(lead, e.length - tail);
    out.push(v, v.replace(/\+/g, '-').replace(/\//g, '_'));
  }
  return out;
}
function variants(s) {
  return [...new Set([s, encodeURIComponent(s), Buffer.from(s).toString('hex'), ...b64Alignments(s)])]
    .filter((v) => v.length >= 8);
}
function leaves(v, out = []) {
  if (typeof v === 'string') {
    out.push(v);
    try { const j = JSON.parse(v); if (j && typeof j === 'object') leaves(j, out); } catch {}
    if (/^[\w-]+\.[\w-]+\.[\w-]*$/.test(v)) v.split('.').forEach((p) => out.push(p)); // JWT-shaped
  } else if (Array.isArray(v)) v.forEach((x) => leaves(x, out));
  else if (v && typeof v === 'object') Object.values(v).forEach((x) => leaves(x, out));
  return out;
}

class Broker {
  constructor({ chromePath, creds, allowedHosts, proxyPort }) {
    Object.assign(this, { chromePath, creds, allowedHosts, proxyPort });
    this.tap = [];        // every byte the agent receives
    this.sessions = new Map();
    this.suspended = false;
    this.diag = { masks: [], audit: [], popupsClosed: 0, dialogsDropped: 0, resourceTypes: {}, axProbe: [], errors: [] };
  }

  emit(obj) { this.tap.push(JSON.stringify(obj)); return obj; }

  async handle(req) {
    try {
      return this.emit(await this.dispatch(req));
    } catch (e) {
      if (!e.code) this.diag.errors.push(String(e.stack || e)); // detail stays broker-side
      return this.emit({ error: { code: e.code || 'internal_error' } });
    }
  }

  fail(code) { const e = new Error(code); e.code = code; return e; }

  async dispatch({ method, params = {} }) {
    if (method === 'initialize') return { protocol: '0.0-spike', profile: 'development' };
    if (method === 'credentials.list') {
      return { credentials: Object.entries(this.creds).map(([id, c]) => ({ id, username: c.username, origin: new URL(c.login_url).origin })) };
    }
    if (method === 'session.open') {
      if (this.suspended) throw this.fail('suspended');
      const cred = this.creds[params.credential_id];
      if (!cred) throw this.fail('denied_by_policy');
      const s = {
        id: 's_' + crypto.randomBytes(8).toString('hex'), cred, state: 'opening', result: null,
        tainted: new Set(), agentTyped: new Set(), secrets: new Set(), ours: new Set(),
        snapshot: { id: 0, refs: new Map() }, creating: 0, deferred: [], booted: false, closing: new Set(),
      };
      this.sessions.set(s.id, s);
      this.login(s).catch((e) => {
        if (!e.code) this.diag.errors.push(String(e.stack || e));
        s.result = e.code || 'internal_error';
        this.destroy(s, 'login_failed');
      });
      return { session: s.id, state: 'opening', retry_after_ms: 300 };
    }
    const s = this.sessions.get(params.session);
    if (!s) throw this.fail('unknown_session');
    if (method === 'session.status') return { state: s.state, result: s.result };
    if (method === 'session.close') { this.destroy(s, 'closed'); return { state: s.state }; }
    if (method === 'session.observe' || method === 'session.act') {
      if (s.state === 'opening' || s.state === 'sealed') throw this.fail('session_sealed');
      if (s.state !== 'active') throw this.fail('session_' + s.state);
      return method === 'session.observe' ? this.observe(s) : this.act(s, params);
    }
    throw this.fail('unknown_method');
  }

  destroy(s, state) {
    if (['closed', 'killed', 'login_failed'].includes(s.state)) return;
    s.state = state;
    try { s.proc && s.proc.kill('SIGKILL'); } catch {}
    try { s.dir && fs.rmSync(s.dir, { recursive: true, force: true }); } catch {}
  }

  // ---- browser lifecycle -------------------------------------------------

  async launch(s) {
    s.dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bf-spike-'));
    const args = [
      '--headless=new', '--remote-debugging-pipe', `--user-data-dir=${s.dir}`,
      '--no-first-run', '--no-default-browser-check', '--disable-background-networking',
      '--disable-component-update', '--disable-sync', '--disable-extensions', '--disable-quic',
      '--disable-features=BackForwardCache,Translate,OptimizationHints,MediaRouter',
      '--password-store=basic', '--use-mock-keychain',
    ];
    if (this.proxyPort) args.push(`--proxy-server=http://127.0.0.1:${this.proxyPort}`, '--proxy-bypass-list=<-loopback>');
    args.push('about:blank');
    s.proc = spawn(this.chromePath, args, { stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'] });
    const cdp = (s.cdp = new CDP(s.proc));
    const autoAttach = () => cdp.send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true });

    cdp.on('Fetch.requestPaused', (p, sid) => this.onRequest(s, p, sid));
    cdp.on('Page.javascriptDialogOpening', (p, sid) => {
      this.diag.dialogsDropped++; // dialog text is never forwarded
      return cdp.send('Page.handleJavaScriptDialog', { accept: false }, sid);
    });
    cdp.on('Target.attachedToTarget', async (p) => {
      const child = p.sessionId;
      const t = p.targetInfo;
      if (t.type === 'page' && !s.ours.has(t.targetId) && s.creating === 0) {
        if (s.booted) this.diag.popupsClosed++;
        s.closing.add(t.targetId);
        return cdp.send('Target.closeTarget', { targetId: t.targetId }).catch(() => {}); // never resumed
      }
      try { await cdp.send('Network.enable', {}, child); } catch {}
      try { await cdp.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] }, child); } catch {}
      if (p.waitingForDebugger) { try { await cdp.send('Runtime.runIfWaitingForDebugger', {}, child); } catch {} }
    });
    cdp.on('Target.targetCreated', (p) => {
      const t = p.targetInfo;
      if (t.type !== 'page' || s.ours.has(t.targetId) || s.closing.has(t.targetId)) return;
      // While we are creating a tab ourselves, hold the decision until createTarget has returned.
      if (s.creating > 0) { s.deferred.push(t.targetId); return; }
      return this.closeForeign(s, t.targetId);
    });
    const collect = (headers) => {
      for (const [k, v] of Object.entries(headers || {})) {
        const key = k.toLowerCase();
        if (key === 'set-cookie') String(v).split('\n').forEach((c) => this.addSecret(s, (c.split(';')[0].split('=').slice(1).join('='))));
        if (key === 'cookie') String(v).split(';').forEach((c) => this.addSecret(s, c.split('=').slice(1).join('=').trim()));
        if (key === 'authorization') String(v).split(/\s+/).forEach((x) => this.addSecret(s, x));
      }
    };
    cdp.on('Network.responseReceivedExtraInfo', (p) => collect(p.headers));
    cdp.on('Network.requestWillBeSentExtraInfo', (p) => collect(p.headers));
    await autoAttach();
    cdp.on('Network.requestWillBeSent', (p) => {
      if (s.state !== 'sealed') return; // login-phase URL parameters join the session-secret set
      try {
        const u = new URL(p.request.url);
        for (const v of u.searchParams.values()) this.addSecret(s, v);
        if (u.hash) new URLSearchParams(u.hash.slice(1)).forEach((v) => this.addSecret(s, v));
      } catch {}
    });
  }

  closeForeign(s, targetId) {
    if (s.closing.has(targetId)) return;
    s.closing.add(targetId);
    if (s.booted) this.diag.popupsClosed++; // single tab: anything we did not create is closed
    return s.cdp.send('Target.closeTarget', { targetId }).catch(() => {});
  }

  async newPage(s) {
    s.creating++;
    const { targetId } = await s.cdp.send('Target.createTarget', { url: 'about:blank' });
    s.ours.add(targetId);
    s.creating--;
    for (const id of s.deferred.splice(0)) if (!s.ours.has(id)) this.closeForeign(s, id);
    const { sessionId } = await s.cdp.send('Target.attachToTarget', { targetId, flatten: true });
    const sid = sessionId;
    await s.cdp.send('Page.enable', {}, sid);
    await s.cdp.send('Network.enable', {}, sid);
    await s.cdp.send('DOM.enable', {}, sid);
    await s.cdp.send('Fetch.enable', { patterns: [{ urlPattern: '*' }] }, sid);
    await s.cdp.send('Target.setAutoAttach', { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, sid);
    return { targetId, sid };
  }

  async goto(s, sid, url) {
    await s.cdp.send('Page.navigate', { url }, sid);
    await this.settle(s, sid);
  }

  async settle(s, sid, ms = 900) {
    // Spike-grade: fixed wait, then poll until the frame tree stops changing URL.
    let last = null;
    for (let i = 0; i < 12; i++) {
      await sleep(i === 0 ? 350 : ms / 10);
      let url;
      try { url = (await s.cdp.send('Page.getFrameTree', {}, sid)).frameTree.frame.url; } catch { return; }
      if (url === last) return;
      last = url;
    }
  }

  // ---- request policy ----------------------------------------------------

  onRequest(s, p, sid) {
    let ok = false, host = '?', pathOnly = '?';
    try {
      const u = new URL(p.request.url);
      host = u.host; pathOnly = u.pathname;
      ok = (u.protocol === 'http:' || u.protocol === 'https:') && this.allowedHosts.has(u.host);
    } catch {}
    const method = p.request.method;
    // While sealed the binding governs; the safe-methods mode applies only once active.
    if (ok && s.state === 'active' && method !== 'GET' && method !== 'HEAD') ok = false;
    this.diag.resourceTypes[p.resourceType] = (this.diag.resourceTypes[p.resourceType] || 0) + 1;
    this.diag.audit.push({ host, path: pathOnly, method, type: p.resourceType, state: s.state, decision: ok ? 'permit' : 'forbid' });
    return ok
      ? s.cdp.send('Fetch.continueRequest', { requestId: p.requestId }, sid)
      : s.cdp.send('Fetch.failRequest', { requestId: p.requestId, errorReason: 'BlockedByClient' }, sid);
  }

  // ---- sealed login ------------------------------------------------------

  async q(s, sid, selector) {
    const { root } = await s.cdp.send('DOM.getDocument', { depth: 0 }, sid);
    const { nodeId } = await s.cdp.send('DOM.querySelector', { nodeId: root.nodeId, selector }, sid);
    return nodeId || null;
  }
  async nodeEval(s, sid, nodeId, fn) {
    const { object } = await s.cdp.send('DOM.resolveNode', { nodeId }, sid);
    const r = await s.cdp.send('Runtime.callFunctionOn', { objectId: object.objectId, functionDeclaration: fn, returnByValue: true }, sid);
    return r.result.value;
  }
  async frame(s, sid) { return (await s.cdp.send('Page.getFrameTree', {}, sid)).frameTree.frame; }

  async login(s) {
    const c = s.cred;
    await this.launch(s);
    s.state = 'sealed';
    s.vault = [c.password];
    const login = await this.newPage(s);
    await s.cdp.send('Target.setDiscoverTargets', { discover: true }); // also closes the default blank tab
    await sleep(100);
    s.booted = true;
    await this.goto(s, login.sid, c.login_url);

    const want = new URL(c.login_url);
    let f = await this.frame(s, login.sid);
    const at = new URL(f.url);
    if (at.origin !== want.origin || at.pathname !== want.pathname) throw this.fail('origin_mismatch');

    const { root } = await s.cdp.send('DOM.getDocument', { depth: 0 }, login.sid);
    const find = async (selector) => (await s.cdp.send('DOM.querySelector', { nodeId: root.nodeId, selector }, login.sid)).nodeId;
    const userNode = await find(c.user_sel || 'input[name=username]');
    const passNode = await find(c.pass_sel || 'input[type=password]');
    if (!userNode || !passNode) throw this.fail('field_not_found');
    const desc = (await s.cdp.send('DOM.describeNode', { nodeId: passNode }, login.sid)).node;
    const attrs = desc.attributes || [];
    if (attrs[attrs.indexOf('type') + 1] !== 'password') throw this.fail('field_not_found');

    await s.cdp.send('DOM.focus', { nodeId: userNode }, login.sid);
    await s.cdp.send('Input.insertText', { text: c.username }, login.sid);

    await s.cdp.send('DOM.focus', { nodeId: passNode }, login.sid);
    const focused = 'function(){return document.activeElement===this && this.type==="password"}';
    if (!(await this.nodeEval(s, login.sid, passNode, focused))) throw this.fail('origin_mismatch');
    const loaderBefore = f.loaderId;
    s.tainted.add(desc.backendNodeId);
    await s.cdp.send('Input.insertText', { text: c.password }, login.sid);
    f = await this.frame(s, login.sid);
    if (f.loaderId !== loaderBefore || !(await this.nodeEval(s, login.sid, passNode, focused))) throw this.fail('origin_mismatch');

    // Probe (broker-side only): does the accessibility tree expose a filled password value?
    const ax = await s.cdp.send('Accessibility.getFullAXTree', {}, login.sid);
    this.diag.axProbe.push({
      login: new URL(c.login_url).pathname,
      passwordVisibleInAX: JSON.stringify(ax.nodes).includes(c.password),
    });

    await this.key(s, login.sid, 'Enter');

    // Unseal predicate, part 1: the per-record success assertion.
    let ok = false;
    for (let i = 0; i < 40 && !ok; i++) {
      await sleep(100);
      try {
        if (c.success.path) ok = new URL((await this.frame(s, login.sid)).url).pathname === c.success.path;
        else ok = !!(await this.q(s, login.sid, c.success.selector));
      } catch {}
    }
    if (!ok) throw this.fail('success_assertion_failed');

    // Part 2: no populated password field, and no vault secret anywhere in what could be observed.
    const residue = await this.scanForVault(s, login.sid);
    if (residue) throw this.fail('secret_residue');

    await this.refreshSecrets(s, login.sid);

    // Tab swap: fresh tab first, then close the login tab. Heap, history and form state are dropped.
    const page = await this.newPage(s);
    await this.goto(s, page.sid, c.post_login_url);
    await s.cdp.send('Target.closeTarget', { targetId: login.targetId });
    s.ours.delete(login.targetId);
    const landed = new URL((await this.frame(s, page.sid)).url);
    if (landed.pathname !== new URL(c.post_login_url).pathname) throw this.fail('success_assertion_failed');

    s.page = page;
    s.tainted.clear(); // node ids belonged to the destroyed tab; taint is rebuilt per observation
    s.state = 'active';
  }

  async scanForVault(s, sid) {
    const doc = await s.cdp.send('DOM.getDocument', { depth: -1, pierce: true }, sid);
    let populated = false;
    const walk = async (n) => {
      if (n.nodeName === 'INPUT') {
        const a = n.attributes || [];
        if (a[a.indexOf('type') + 1] === 'password' || s.tainted.has(n.backendNodeId)) {
          const v = await this.nodeEval(s, sid, n.nodeId, 'function(){return this.value}');
          if (v) populated = true;
        }
      }
      for (const ch of [...(n.children || []), ...(n.shadowRoots || []), ...(n.contentDocument ? [n.contentDocument] : [])]) await walk(ch);
    };
    await walk(doc.root);
    if (populated) return true;
    const blob = JSON.stringify(doc) + JSON.stringify(await s.cdp.send('Accessibility.getFullAXTree', {}, sid));
    return s.vault.some((v) => variants(v).some((x) => blob.includes(x)));
  }

  // ---- secrets -----------------------------------------------------------

  addSecret(s, v) { if (aboveFloor(v)) s.secrets.add(v); }

  async refreshSecrets(s, sid) {
    const { cookies } = await s.cdp.send('Storage.getCookies', {});
    for (const c of cookies) { if (c.httpOnly && c.value.length >= 8) s.secrets.add(c.value); else this.addSecret(s, c.value); }
    const origin = new URL((await this.frame(s, sid)).url).origin;
    for (const isLocalStorage of [true, false]) {
      try {
        const { entries } = await s.cdp.send('DOMStorage.getDOMStorageItems', { storageId: { securityOrigin: origin, isLocalStorage } }, sid);
        for (const [, v] of entries) leaves(v).forEach((x) => this.addSecret(s, x));
      } catch {}
    }
  }

  // Returns the set of field indexes to withhold; throws if a vault secret is present.
  match(s, fields) {
    const joined = fields.join('');
    const starts = [];
    let pos = 0;
    for (const f of fields) { starts.push(pos); pos += f.length; }
    const hit = new Set();
    const mark = (from, to) => {
      for (let i = 0; i < fields.length; i++) if (starts[i] < to && starts[i] + fields[i].length > from) hit.add(i);
    };
    for (const v of s.vault) {
      for (const x of variants(v)) if (joined.includes(x)) { this.destroy(s, 'killed'); throw this.fail('session_killed'); }
    }
    for (const sec of s.secrets) {
      for (const x of variants(sec)) {
        let i = -1;
        while ((i = joined.indexOf(x, i + 1)) !== -1) mark(i, i + x.length);
      }
    }
    // Chunks: any long token that is a piece of a session secret.
    fields.forEach((f, i) => {
      for (const tok of f.match(/[A-Za-z0-9_\-+/=%]{12,}/g) || []) {
        for (const sec of s.secrets) if (sec.includes(tok)) hit.add(i);
      }
    });
    return hit;
  }

  // ---- observation -------------------------------------------------------

  async observe(s) {
    const { sid } = s.page;
    await sleep(150);
    await this.refreshSecrets(s, sid);

    // Rebuild taint: anything that is a password field right now is tainted for good.
    const doc = await s.cdp.send('DOM.getDocument', { depth: -1, pierce: true }, sid);
    (function walk(n) {
      const a = n.attributes || [];
      if (n.nodeName === 'INPUT' && a[a.indexOf('type') + 1] === 'password') s.tainted.add(n.backendNodeId);
      for (const ch of [...(n.children || []), ...(n.shadowRoots || []), ...(n.contentDocument ? [n.contentDocument] : [])]) walk(ch);
    })(doc.root);

    const tree = (await s.cdp.send('Page.getFrameTree', {}, sid)).frameTree;
    const frames = [];
    (function flat(t) { frames.push(t.frame); (t.childFrames || []).forEach(flat); })(tree);

    const snap = { id: s.snapshot.id + 1, refs: new Map() };
    const items = [];
    let n = 0;
    for (const fr of frames) {
      let ax;
      try { ax = await s.cdp.send('Accessibility.getFullAXTree', { frameId: fr.id }, sid); } catch { continue; }
      for (const node of ax.nodes) {
        if (node.ignored) continue;
        const role = node.role && node.role.value;
        if (!ROLES.has(role)) continue;
        const name = (node.name && node.name.value) || '';
        const interactive = !['StaticText', 'RootWebArea', 'heading', 'image', 'img', 'cell', 'columnheader', 'Iframe'].includes(role);
        if (!name && !interactive) continue;
        const item = { ref: 'e' + ++n, role: role === 'RootWebArea' ? 'page' : role, name: String(name) };
        for (const p of node.properties || []) {
          if (['disabled', 'checked', 'expanded', 'focused'].includes(p.name) && p.value && p.value.value === true) item[p.name] = true;
        }
        // Values are emitted only for controls the agent itself typed into, and never for tainted nodes.
        const b = node.backendDOMNodeId;
        if (s.agentTyped.has(b) && !s.tainted.has(b) && node.value) item.value = String(node.value.value);
        snap.refs.set(item.ref, { backend: b, role });
        items.push(item);
      }
    }

    const u = new URL(tree.frame.url);
    const url = u.origin + u.pathname.split('/').map((seg) => (aboveFloor(seg) ? WITHHELD : seg)).join('/');

    const fields = [url];
    const slots = [null];
    items.forEach((it) => { fields.push(it.name); slots.push([it, 'name']); if (it.value !== undefined) { fields.push(it.value); slots.push([it, 'value']); } });
    const hit = this.match(s, fields);
    let masked = 0;
    let outUrl = url;
    for (const i of hit) {
      masked++;
      if (slots[i]) slots[i][0][slots[i][1]] = WITHHELD; else outUrl = WITHHELD;
    }
    this.diag.masks.push({ path: u.pathname, masked, items: items.length });
    s.snapshot = snap;
    return { snapshot: snap.id, url: outUrl, query_stripped: !!u.search, items };
  }

  // ---- actions -----------------------------------------------------------

  async key(s, sid, name) {
    const code = KEYS[name];
    const base = { key: name, code: name, windowsVirtualKeyCode: code, nativeVirtualKeyCode: code };
    await s.cdp.send('Input.dispatchKeyEvent', { type: 'keyDown', ...base, ...(name === 'Enter' ? { text: '\r' } : {}) }, sid);
    await s.cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', ...base }, sid);
  }

  async act(s, p) {
    const { sid } = s.page;
    if (p.action === 'navigate') {
      let u;
      try { u = new URL(p.url); } catch { throw this.fail('denied_by_policy'); }
      if (!['http:', 'https:'].includes(u.protocol) || !this.allowedHosts.has(u.host) || u.username || u.password) throw this.fail('denied_by_policy');
      await this.goto(s, sid, u.href);
      return { ok: true };
    }
    if (p.action === 'key') {
      if (!KEYS[p.key]) throw this.fail('denied_by_policy');
      await this.key(s, sid, p.key);
      await this.settle(s, sid);
      return { ok: true };
    }
    if (p.snapshot !== s.snapshot.id) throw this.fail('stale_ref');
    const target = s.snapshot.refs.get(p.ref);
    if (!target || !target.backend) throw this.fail('stale_ref');

    if (p.action === 'click') {
      await s.cdp.send('DOM.scrollIntoViewIfNeeded', { backendNodeId: target.backend }, sid);
      const { model } = await s.cdp.send('DOM.getBoxModel', { backendNodeId: target.backend }, sid);
      const c = model.content;
      const x = (c[0] + c[2] + c[4] + c[6]) / 4, y = (c[1] + c[3] + c[5] + c[7]) / 4;
      for (const type of ['mousePressed', 'mouseReleased']) {
        await s.cdp.send('Input.dispatchMouseEvent', { type, x, y, button: 'left', clickCount: 1 }, sid);
      }
      await this.settle(s, sid);
      return { ok: true };
    }
    if (p.action === 'type') {
      const text = String(p.text || '');
      // Tripwire: agent-typed text containing a vault secret kills the session and suspends the subject.
      if (s.vault.some((v) => variants(v).some((x) => text.includes(x)))) {
        this.suspended = true;
        this.destroy(s, 'killed');
        throw this.fail('session_killed');
      }
      if (!['textbox', 'searchbox', 'combobox'].includes(target.role) || s.tainted.has(target.backend)) throw this.fail('denied_by_policy');
      await s.cdp.send('DOM.focus', { backendNodeId: target.backend }, sid);
      await s.cdp.send('Input.insertText', { text }, sid);
      s.agentTyped.add(target.backend);
      return { ok: true };
    }
    throw this.fail('unknown_method');
  }

  shutdown() { for (const s of this.sessions.values()) this.destroy(s, 'closed'); }
}

module.exports = { Broker, variants };
