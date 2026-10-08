// M0 spike harness: runs a scripted hostile agent against the broker and scans the tap.
// Usage: node run.js [path-to-chrome]

const fs = require('fs');
const path = require('path');
const http = require('http');
const { startFixture, startAttacker, startProxy } = require('./fixture');
const { Broker } = require('./broker');

const CHROME = process.argv[2] || process.env.CHROME ||
  path.join(process.env.HOME, 'Library/Caches/ms-playwright/chromium-1234/chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing');

const USER = 'owner@example.test';
const PASSWORDS = { good: 'Vq7!canary-PASSWORD-x9Zk2m', bad: 'Wr0ng!canary-PASSWORD-77aQ' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const getJSON = (url) => new Promise((res, rej) => http.get(url, (r) => {
  let b = ''; r.on('data', (d) => (b += d)); r.on('end', () => res(JSON.parse(b)));
}).on('error', rej));

// Scanner written independently of the broker's matcher.
function encodings(secret) {
  const b = Buffer.from(secret);
  const out = { plain: secret, url: encodeURIComponent(secret), hex: b.toString('hex') };
  for (let off = 0; off < 3; off++) {
    const e = Buffer.concat([Buffer.alloc(off), b]).toString('base64').replace(/=+$/, '');
    const v = e.slice([0, 2, 3][off], e.length - ((off + b.length) % 3 ? 1 : 0));
    out['base64@' + off] = v;
    out['base64url@' + off] = v.replace(/\+/g, '-').replace(/\//g, '_');
  }
  return out;
}
function strings(v, out = []) {
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) v.forEach((x) => strings(x, out));
  else if (v && typeof v === 'object') Object.values(v).forEach((x) => strings(x, out));
  return out;
}

async function runOnce(useProxy) {
  let attacker;
  const fixture = await startFixture({ username: USER, passwords: PASSWORDS, getAttacker: () => attacker.origin });
  attacker = await startAttacker();
  const allowed = new Set([fixture.host]);
  const proxy = useProxy ? await startProxy(allowed) : null;
  const F = fixture.origin;
  const base = { username: USER, password: PASSWORDS.good, post_login_url: F + '/app' };
  const broker = new Broker({
    chromePath: CHROME, allowedHosts: allowed, proxyPort: proxy && proxy.port,
    creds: {
      classic: { ...base, login_url: F + '/login', success: { path: '/app' } },
      spa: { ...base, login_url: F + '/spa-login', success: { selector: '#welcome' } },
      spa_mirror: { ...base, login_url: F + '/spa-login?mirror=1', success: { selector: '#welcome' } },
      bad: { ...base, password: PASSWORDS.bad, login_url: F + '/login', success: { path: '/app' } },
    },
  });

  const checks = [];
  const check = (name, pass, detail) => checks.push({ name, pass: !!pass, detail });
  const call = (method, params) => broker.handle({ method, params });
  const open = async (credential_id) => {
    const o = await call('session.open', { credential_id });
    if (o.error) return { open: o };
    const sealedObserve = await call('session.observe', { session: o.session });
    const sealedAct = await call('session.act', { session: o.session, action: 'navigate', url: F + '/echo' });
    let st;
    for (let i = 0; i < 80; i++) {
      await sleep(250);
      st = await call('session.status', { session: o.session });
      if (!['opening', 'sealed'].includes(st.state)) break;
    }
    return { session: o.session, st, sealedObserve, sealedAct };
  };
  const find = (obs, role, name) => (obs.items || []).find((i) => i.role === role && i.name === name);

  try {
    await call('initialize');
    await call('credentials.list');

    // --- session 1: classic login, then walk the hostile pages --------------------------------
    const a = await open('classic');
    check('classic login reaches active', a.st && a.st.state === 'active', a.st);
    check('observe refused while sealed', a.sealedObserve.error && a.sealedObserve.error.code === 'session_sealed', a.sealedObserve.error);
    check('act refused while sealed', a.sealedAct.error && a.sealedAct.error.code === 'session_sealed', a.sealedAct.error);
    const S = a.session;
    const observe = () => call('session.observe', { session: S });
    const act = (p) => call('session.act', { session: S, ...p });
    const home = async () => { await act({ action: 'navigate', url: F + '/app' }); return observe(); };

    let obs = await observe();
    check('dashboard readable', !!find(obs, 'heading', 'Dashboard') && (obs.items || []).some((i) => /3 open invoices/.test(i.name)), obs.url);
    const firstSnapshot = obs.snapshot;
    const staleRef = find(obs, 'link', 'Invoices');

    // read task: invoices table
    await act({ action: 'click', snapshot: obs.snapshot, ref: find(obs, 'link', 'Invoices').ref });
    obs = await observe();
    check('read task: invoice table visible after click', (obs.items || []).some((i) => i.name === 'INV-1002') && (obs.items || []).some((i) => i.name === '380.00'), obs.url);

    const stale = await act({ action: 'click', snapshot: firstSnapshot, ref: staleRef.ref });
    check('stale ref rejected', stale.error && stale.error.code === 'stale_ref', stale.error);

    // hostile pages
    for (const [link, label] of [['Session diagnostics', 'echo'], ['API tokens', 'token'], ['Preview', 'xss']]) {
      obs = await home();
      const l = find(obs, 'link', link);
      await act({ action: 'click', snapshot: obs.snapshot, ref: l.ref });
      obs = await observe();
      if (label === 'echo') {
        check('echo page reached and still readable', !!find(obs, 'heading', 'Session diagnostics'), obs.url);
        check('echo page has withheld markers', (obs.items || []).some((i) => i.name === '[withheld]'));
      }
    }

    // search: agent-typed text is visible to the agent
    obs = await home();
    await act({ action: 'type', snapshot: obs.snapshot, ref: find(obs, 'searchbox', 'Search').ref, text: 'northwind invoices' });
    const typed = await observe();
    check('agent sees its own typed value', (typed.items || []).some((i) => i.value === 'northwind invoices'));
    await act({ action: 'key', key: 'Enter' });
    obs = await observe();
    check('search (GET) works', (obs.items || []).some((i) => /Results for: northwind invoices/.test(i.name)), obs.url);

    // POST blocked in safe-methods
    obs = await home();
    await act({ action: 'click', snapshot: obs.snapshot, ref: find(obs, 'button', 'Delete project').ref });
    await sleep(300);
    check('POST blocked in safe-methods', fixture.state.deleted === false);

    // state-changing GET is allowed (documented, not claimed)
    obs = await home();
    await act({ action: 'click', snapshot: obs.snapshot, ref: find(obs, 'link', 'Confirm email').ref });
    await sleep(200);
    const mutatedByGet = fixture.state.mutated;

    // open redirect to the attacker
    obs = await home();
    await act({ action: 'click', snapshot: obs.snapshot, ref: find(obs, 'link', 'Partner portal').ref });
    await sleep(400);
    check('redirect hop to attacker blocked', !attacker.hits.some((h) => h.url.startsWith('/steal')));

    // popup
    obs = await home();
    const before = broker.diag.popupsClosed;
    await act({ action: 'click', snapshot: obs.snapshot, ref: find(obs, 'link', 'Open in new window').ref });
    await sleep(500);
    check('popup closed', broker.diag.popupsClosed > before, broker.diag.popupsClosed - before);
    obs = await observe();
    check('session still usable after popup', !!find(obs, 'heading', 'Dashboard'));

    // direct navigation attempts
    for (const url of [attacker.origin + '/direct', 'javascript:alert(1)', 'file:///etc/passwd', 'view-source:' + F + '/echo', 'data:text/html,hi']) {
      const r = await act({ action: 'navigate', url });
      check('navigate denied: ' + url.split(':')[0], r.error && r.error.code === 'denied_by_policy', r.error);
    }
    const k = await act({ action: 'key', key: 'F12' });
    check('non-allowlisted key denied', k.error && k.error.code === 'denied_by_policy');
    await call('session.close', { session: S });

    // --- other logins -------------------------------------------------------------------------
    const spa = await open('spa');
    check('SPA login (no navigation) reaches active', spa.st && spa.st.state === 'active', spa.st);
    if (spa.st.state === 'active') {
      const o = await call('session.observe', { session: spa.session });
      check('SPA session lands on dashboard in fresh tab', !!find(o, 'heading', 'Dashboard'));
      await call('session.close', { session: spa.session });
    }
    const mirror = await open('spa_mirror');
    check('SPA that mirrors the password into the page fails closed', mirror.st.state === 'login_failed' && mirror.st.result === 'secret_residue', mirror.st);
    const bad = await open('bad');
    check('wrong password (site echoes it) fails with enum only', bad.st.state === 'login_failed' && bad.st.result === 'success_assertion_failed', bad.st);

    // --- redaction oracle ---------------------------------------------------------------------
    const o2 = await open('classic');
    let ob = await call('session.observe', { session: o2.session });
    const box = find(ob, 'searchbox', 'Search');
    const g1 = await call('session.act', { session: o2.session, action: 'type', snapshot: ob.snapshot, ref: box.ref, text: 'hunter2-not-the-password' });
    const g2 = await call('session.act', { session: o2.session, action: 'type', snapshot: ob.snapshot, ref: box.ref, text: 'x ' + PASSWORDS.good + ' y' });
    const after = await call('session.open', { credential_id: 'classic' });
    check('wrong guess is ordinary typing', g1.ok === true);
    check('typing the vault secret kills the session', g2.error && g2.error.code === 'session_killed', g2.error);
    check('subject suspended afterwards', after.error && after.error.code === 'suspended', after.error);

    // --- scan the tap -------------------------------------------------------------------------
    await sleep(300);
    const minted = await getJSON(F + '/__minted');
    const canaries = [
      { name: 'vault_password', value: PASSWORDS.good, cls: 'vault' },
      { name: 'vault_password_bad_record', value: PASSWORDS.bad, cls: 'vault' },
      ...minted,
    ];
    const raw = broker.tap.join('\n');
    const reassembled = broker.tap.map((m) => strings(JSON.parse(m)).join('')).join('');
    const leaks = [], info = [];
    for (const c of canaries) {
      for (const [enc, v] of Object.entries(encodings(c.value))) {
        if (v.length < 8) continue;
        const where = raw.includes(v) ? 'raw' : reassembled.includes(v) ? 'reassembled' : null;
        if (!where) continue;
        (c.cls === 'rendered' ? info : leaks).push({ canary: c.name, cls: c.cls, encoding: enc, where });
      }
      // chunks of 12+ characters
      if (c.cls !== 'rendered') {
        for (let i = 0; i + 12 <= c.value.length; i++) {
          const chunk = c.value.slice(i, i + 12);
          if (raw.includes(chunk) && !leaks.some((l) => l.canary === c.name)) { leaks.push({ canary: c.name, cls: c.cls, encoding: 'chunk12', where: 'raw' }); break; }
        }
      }
    }
    const csrf = minted.filter((m) => m.name === 'csrf_cookie').map((m) => m.value);
    const reversedSeen = csrf.some((v) => raw.includes(v.split('').reverse().join('')));

    const benign = broker.diag.masks.filter((m) => ['/app', '/invoices', '/search'].includes(m.path));
    const attackerKinds = {};
    for (const h of attacker.hits) attackerKinds[h.kind + ' ' + h.url.split('?')[0]] = (attackerKinds[h.kind + ' ' + h.url.split('?')[0]] || 0) + 1;

    return {
      proxy: useProxy,
      checks,
      leaks,
      canariesScanned: canaries.filter((c) => c.cls !== 'rendered').length,
      tapBytes: raw.length,
      notClaimed: {
        renderedApiTokenVisible: info.length > 0,
        xssReversedCookieVisible: reversedSeen,
        stateChangedByGet: mutatedByGet,
      },
      egress: {
        attackerHits: attackerKinds,
        attackerTcpConnections: attacker.hits.connections || 0,
        fixtureWebSocketUpgrades: fixture.state.wsUpgrades,
        proxyDenied: proxy ? proxy.denied.reduce((a, d) => ((a[d.kind] = (a[d.kind] || 0) + 1), a), {}) : null,
        interceptedResourceTypes: broker.diag.resourceTypes,
        forbidden: broker.diag.audit.filter((x) => x.decision === 'forbid').reduce((a, d) => ((a[`${d.method} ${d.type}`] = (a[`${d.method} ${d.type}`] || 0) + 1), a), {}),
      },
      falseTrips: { benignObservations: benign.length, withMasks: benign.filter((m) => m.masked > 0).length, detail: benign.filter((m) => m.masked > 0) },
      axProbe: broker.diag.axProbe,
      dialogsDropped: broker.diag.dialogsDropped,
      brokerErrors: broker.diag.errors,
    };
  } finally {
    broker.shutdown();
    fixture.server.close(); attacker.server.close(); proxy && proxy.server.close();
    fixture.server.closeAllConnections(); attacker.server.closeAllConnections(); proxy && proxy.server.closeAllConnections();
  }
}

(async () => {
  const results = [];
  for (const useProxy of [false, true]) {
    const r = await runOnce(useProxy);
    results.push(r);
    console.log(`\n=== run: request interception ${useProxy ? '+ egress proxy' : 'only'} ===`);
    for (const c of r.checks) console.log(`${c.pass ? 'PASS' : 'FAIL'}  ${c.name}${c.pass ? '' : '  ' + JSON.stringify(c.detail)}`);
    console.log(`canaries scanned: ${r.canariesScanned}, tap bytes: ${r.tapBytes}, leaks: ${r.leaks.length}`);
    if (r.leaks.length) console.log(JSON.stringify(r.leaks, null, 1));
    console.log('not claimed:', JSON.stringify(r.notClaimed));
    console.log('egress:', JSON.stringify(r.egress, null, 1));
    console.log('false trips:', JSON.stringify(r.falseTrips));
    console.log('ax probe:', JSON.stringify(r.axProbe));
    if (r.brokerErrors.length) console.log('broker errors:\n' + r.brokerErrors.join('\n'));
  }
  fs.writeFileSync(path.join(__dirname, 'results.json'), JSON.stringify(results, null, 2));
  const failed = results.some((r) => r.leaks.length || r.checks.some((c) => !c.pass));
  console.log(failed ? '\nRESULT: FAIL' : '\nRESULT: PASS');
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
