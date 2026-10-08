// Generates the logo and README diagrams into assets/, in light and dark variants.
// Run: node tools/diagrams.js
//
// Visual system
//   brand / secret path   magenta, dashed line
//   agent-visible data    blue, solid line
//   allowed / active      green
//   refused / boundary    red
// Line style and labels carry the meaning as well, never colour alone.

const fs = require('fs');
const path = require('path');

const THEMES = {
  dark: {
    bg: '#0d1117', surface: '#161b22', raised: '#1c2330', border: '#30363d', text: '#e6edf3', muted: '#8b949e',
    brand: '#e86aa6', blue: '#58a6ff', green: '#3fb950', amber: '#d29922', red: '#f85149', steel: '#4b5868',
  },
  light: {
    bg: '#ffffff', surface: '#f6f8fa', raised: '#eef1f4', border: '#d0d7de', text: '#1f2328', muted: '#656d76',
    brand: '#bf3989', blue: '#0969da', green: '#1a7f37', amber: '#9a6700', red: '#cf222e', steel: '#8c959f',
  },
};
const SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif";
const MONO = "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, 'Liberation Mono', monospace";
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const tw = (s, size, mono) => s.length * size * (mono ? 0.602 : 0.535);

function make(t) {
  const txt = (x, y, s, o = {}) => {
    const { size = 14, fill = t.text, anchor = 'start', weight = 400, mono = false, ls = 0, bg = null } = o;
    let out = '';
    if (bg) {
      const w = tw(s, size, mono) + 12;
      const x0 = anchor === 'middle' ? x - w / 2 : anchor === 'end' ? x - w + 6 : x - 6;
      out += `<rect x="${x0}" y="${y - size}" width="${w}" height="${size + 6}" rx="4" fill="${bg}"/>`;
    }
    return out + `<text x="${x}" y="${y}" font-family="${mono ? MONO : SANS}" font-size="${size}" fill="${fill}" text-anchor="${anchor}" font-weight="${weight}"${ls ? ` letter-spacing="${ls}"` : ''}>${esc(s)}</text>`;
  };
  const tag = (x, y, s, color) => txt(x, y, s.toUpperCase(), { size: 10.5, fill: color, weight: 600, ls: 0.9 });
  const card = (x, y, w, h, o) => {
    const { tagText, tagColor = t.muted, title, sub, dashed = false, mono = false, fill = t.surface, stroke = t.border } = o;
    let out = `<rect x="${x}" y="${y}" width="${w}" height="${h}" rx="10" fill="${fill}" stroke="${stroke}" stroke-width="1.25"${dashed ? ' stroke-dasharray="5 4"' : ''}/>`;
    let ty = y + (tagText ? 46 : 28);
    if (tagText) out += tag(x + 16, y + 24, tagText, tagColor);
    out += txt(x + 16, ty, title, { size: 16, weight: 600, mono });
    if (sub) out += txt(x + 16, ty + 20, sub, { size: 12.5, fill: t.muted });
    return out;
  };
  const pill = (cx, cy, s, color, o = {}) => {
    const size = 12, w = tw(s, size, o.mono) + 20;
    return `<rect x="${cx - w / 2}" y="${cy - 11}" width="${w}" height="22" rx="11" fill="${t.bg}" stroke="${color}" stroke-width="1.1"/>` +
      txt(cx, cy + 4, s, { size, fill: color, anchor: 'middle', mono: o.mono, weight: 500 });
  };
  const mid = (c) => 'a' + c.slice(1);
  const line = (pts, color, o = {}) => {
    const { dashed = false, width = 1.6, both = false, r = 8, head = true } = o;
    let d = `M${pts[0][0]} ${pts[0][1]}`;
    for (let i = 1; i < pts.length; i++) {
      const [x, y] = pts[i];
      if (i < pts.length - 1) {
        const [px, py] = pts[i - 1], [nx, ny] = pts[i + 1];
        const a = Math.hypot(x - px, y - py), b = Math.hypot(nx - x, ny - y), rr = Math.min(r, a / 2, b / 2);
        d += ` L${x - ((x - px) / a) * rr} ${y - ((y - py) / a) * rr} Q${x} ${y} ${x + ((nx - x) / b) * rr} ${y + ((ny - y) / b) * rr}`;
      } else d += ` L${x} ${y}`;
    }
    return `<path d="${d}" fill="none" stroke="${color}" stroke-width="${width}" stroke-linecap="round"${dashed ? ' stroke-dasharray="6 5"' : ''}${head ? ` marker-end="url(#${mid(color)})"` : ''}${both ? ` marker-start="url(#${mid(color)})"` : ''}/>`;
  };
  const legend = (x, y, items) => {
    let out = '', cx = x;
    for (const [label, color, dashed] of items) {
      out += `<path d="M${cx} ${y}H${cx + 36}" stroke="${color}" stroke-width="1.8" stroke-linecap="round"${dashed ? ' stroke-dasharray="6 5"' : ''}/>` + txt(cx + 46, y + 4, label, { size: 12.5, fill: t.muted });
      cx += 46 + tw(label, 12.5) + 30;
    }
    return out;
  };
  const wrap = (w, h, label, body) => {
    const markers = [t.brand, t.blue, t.green, t.amber, t.red, t.steel, t.muted].map((c) =>
      `<marker id="${mid(c)}" viewBox="0 0 10 10" refX="8.6" refY="5" markerWidth="6.5" markerHeight="6.5" orient="auto-start-reverse"><path d="M1.6 1.6L8.6 5L1.6 8.4" fill="none" stroke="${c}" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></marker>`).join('');
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" role="img" aria-label="${esc(label)}">
<defs>${markers}</defs>
<rect x="0.5" y="0.5" width="${w - 1}" height="${h - 1}" rx="12" fill="${t.bg}" stroke="${t.border}"/>
${body}
</svg>\n`;
  };

  // ---- the mark: a blindfolded ninja leaning on a vault slab ---------------------------------

  const ninja = (ox, oy, k) => {
    const ink = t.text, gap = t.bg, cloth = t.brand, steel = t.steel;
    const part = (d, fill = ink) => `<path d="${d}" fill="${fill}" stroke="${gap}" stroke-width="3" stroke-linejoin="round"/>`;
    const figure = [
      `<path d="M-82 -236L8 -188" stroke="${steel}" stroke-width="10" stroke-linecap="round"/>`,
      `<path d="M-82 -236L-54 -221" stroke="${ink}" stroke-width="10" stroke-linecap="round"/>`,
      `<path d="M-45 -229L-53 -206" stroke="${steel}" stroke-width="5" stroke-linecap="round"/>`,
      part('M-34 -198L4 -198L-3 -14L-31 -14Z'),
      part('M-33 -18L-2 -18L0 0L-56 0Q-56 -10 -33 -18Z'),
      part('M-2 -198L35 -198L41 -106L-24 -4L-52 -20L5 -108Z'),
      part('M-54 -22L-24 -5L-40 0L-74 0Q-72 -12 -54 -22Z'),
      part('M-46 -326Q-50 -336 -38 -339L38 -339Q50 -336 46 -326L35 -198L-35 -198Z'),
      `<rect x="-36" y="-214" width="72" height="15" rx="2" fill="${steel}"/>`,
      `<path d="M-22 -201L-10 -201L-15 -166L-28 -171Z" fill="${steel}"/>`,
      part('M-42 -334Q-62 -328 -60 -300L-56 -262L-36 -262L-38 -332Z'),
      part('M42 -334Q62 -328 60 -300L56 -262L36 -262L38 -332Z'),
      part('M-58 -288Q-58 -297 -49 -297L49 -297Q58 -297 58 -288L56 -267Q56 -258 47 -258L-47 -258Q-56 -258 -56 -267Z'),
      `<path d="M-12 -297L16 -258" stroke="${gap}" stroke-width="3" stroke-linecap="round"/>`,
      part('M-10 -350L10 -350L10 -334L-10 -334Z'),
      `<circle cx="0" cy="-376" r="36" fill="${ink}" stroke="${gap}" stroke-width="3"/>`,
      `<path d="M-38 -388C-68 -412 -100 -370 -134 -390S-190 -410 -224 -392C-196 -389 -172 -381 -139 -373C-103 -356 -68 -396 -38 -375Z" fill="${cloth}"/>`,
      `<path d="M-38 -380C-62 -362 -90 -346 -120 -358S-162 -356 -186 -336C-162 -341 -141 -343 -120 -344C-90 -333 -60 -350 -38 -370Z" fill="${cloth}"/>`,
      `<rect x="-37.5" y="-389" width="75" height="19" rx="2" fill="${cloth}"/>`,
      `<circle cx="-39" cy="-379.5" r="8" fill="${cloth}"/>`,
    ].join('');
    return `<g transform="translate(${ox} ${oy}) scale(${k})">
<rect x="102" y="-452" width="92" height="452" rx="6" fill="${t.raised}" stroke="${t.border}" stroke-width="2"/>
<path d="M102 -300H194M102 -150H194" stroke="${t.border}" stroke-width="2"/>
<circle cx="148" cy="-382" r="10" fill="${t.border}"/><path d="M143 -378L153 -378L157 -352L139 -352Z" fill="${t.border}"/>
<path d="M-240 0H232" stroke="${t.border}" stroke-width="2.5" stroke-linecap="round"/>
<g transform="rotate(8)">${figure}</g>
</g>`;
  };

  const logo = () => `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" role="img" aria-label="blindfold logo">
<rect width="512" height="512" rx="96" fill="${t.bg}"/>
<rect x="2" y="2" width="508" height="508" rx="94" fill="none" stroke="${t.border}" stroke-width="4"/>
${ninja(246, 462, 0.9)}
</svg>\n`;

  const banner = () => {
    const w = 1040, h = 320;
    return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${w} ${h}" width="${w}" role="img" aria-label="blindfold: sealed browser sessions for AI agents">
<rect x="0.5" y="0.5" width="${w - 1}" height="${h - 1}" rx="12" fill="${t.bg}" stroke="${t.border}"/>
${ninja(196, 286, 0.56)}
${txt(380, 150, 'blindfold', { size: 76, weight: 700, mono: true, ls: -1.5 })}
${txt(384, 196, 'Sealed browser sessions for AI agents.', { size: 23, weight: 500 })}
${txt(384, 230, 'The agent drives the page. It never holds the password or the session.', { size: 16, fill: t.muted })}
</svg>\n`;
  };

  // ---- architecture --------------------------------------------------------------------------

  const architecture = () => {
    const w = 1040, h = 548;
    let b = '';
    b += `<rect x="328" y="40" width="444" height="416" rx="12" fill="${t.raised}" stroke="${t.border}" stroke-width="1.25"/>`;
    b += tag(348, 68, 'Broker', t.green) + txt(408, 68, 'runs as separate system users', { size: 12.5, fill: t.muted });
    b += card(40, 88, 204, 88, { tagText: 'Untrusted', tagColor: t.red, title: 'Agent', sub: 'May be prompt-injected' });
    b += card(40, 304, 204, 88, { tagText: 'Owner', title: 'You', sub: 'Add logins, set policy' });
    b += card(348, 88, 188, 88, { tagText: 'Front door', tagColor: t.green, title: 'Gateway', sub: 'Checks every request' });
    b += card(564, 88, 188, 88, { tagText: 'Login and filter', tagColor: t.green, title: 'Driver', sub: 'Builds the filtered view' });
    b += card(348, 304, 188, 88, { tagText: 'Vault', tagColor: t.brand, title: 'Keeper', sub: 'One secret at a time', stroke: t.brand });
    b += tag(564, 328, 'Never leaves the broker', t.muted);
    ['Passwords', 'TOTP seeds', 'Cookies and tokens'].forEach((s, i) => {
      b += `<circle cx="568" cy="${348 + i * 24}" r="2.5" fill="${t.brand}"/>` + txt(580, 353 + i * 24, s, { size: 14 });
    });
    b += card(816, 88, 184, 88, { tagText: 'Sandbox', tagColor: t.amber, title: 'Browser', sub: 'One per session' });
    b += card(816, 206, 184, 66, { title: 'Egress proxy', sub: 'Allowlist, HTTPS only' });
    b += card(816, 304, 184, 88, { tagText: 'External', title: 'Website', sub: 'Sees a normal login', dashed: true, fill: t.bg });

    b += `<path d="M286 40V456" stroke="${t.red}" stroke-width="1.4" stroke-dasharray="2 6" stroke-linecap="round"/>`;
    b += pill(286, 478, 'trust boundary: no secret crosses', t.red);

    b += line([[244, 116], [346, 116]], t.blue) + pill(295, 116, 'actions', t.blue);
    b += line([[348, 150], [246, 150]], t.blue) + pill(295, 150, 'filtered view', t.blue);
    b += line([[538, 132], [562, 132]], t.steel, { both: true });
    b += line([[244, 348], [346, 348]], t.steel) + pill(295, 348, 'setup', t.muted);
    b += line([[442, 304], [442, 240], [658, 240], [658, 178]], t.brand, { dashed: true }) + pill(550, 240, 'one secret per login', t.brand);
    b += line([[752, 132], [814, 132]], t.brand, { dashed: true });
    b += line([[908, 176], [908, 204]], t.brand, { dashed: true });
    b += line([[908, 272], [908, 302]], t.brand, { dashed: true });

    b += legend(40, 520, [['What the agent sends and sees', t.blue, false], ['Path a secret travels', t.brand, true], ['Out of band', t.steel, false]]);
    return wrap(w, h, 'Architecture: the agent talks only to the gateway. Secrets travel from keeper to driver to browser to website and never cross the trust boundary.', b);
  };

  // ---- sealed login --------------------------------------------------------------------------

  const sealedLogin = () => {
    const cols = { Agent: 124, Gateway: 290, Driver: 456, Keeper: 622, Browser: 788, Website: 944 };
    const tint = { Agent: t.red, Gateway: t.green, Driver: t.green, Keeper: t.brand, Browser: t.amber, Website: t.muted };
    const rows = [
      ['Agent', 'Gateway', 'session.open', 'blue', 1],
      ['Gateway', 'Agent', 'opening', 'blue', 1],
      ['Gateway', 'Keeper', 'Allowed by policy?', 'steel'],
      ['Gateway', 'Driver', 'Begin sealed login', 'steel'],
      ['Driver', 'Browser', 'Open the pinned login URL', 'steel'],
      ['Browser', 'Website', 'Load login page', 'steel'],
      ['Agent', 'Gateway', 'session.observe', 'blue', 1],
      ['Gateway', 'Agent', 'session_sealed', 'red', 1],
      ['Driver', 'Browser', 'Verify field, origin and TLS', 'steel'],
      ['Keeper', 'Driver', 'Secret, for one fill', 'brand'],
      ['Driver', 'Browser', 'Type and submit', 'brand'],
      ['Browser', 'Website', 'Credentials', 'brand'],
      ['Website', 'Browser', 'Session cookie', 'brand'],
      ['Driver', 'Browser', 'Check unseal conditions', 'steel'],
      ['Driver', 'Browser', 'Open fresh tab, close login tab', 'steel'],
      ['Driver', 'Gateway', 'active', 'green', 1],
      ['Agent', 'Gateway', 'session.observe', 'blue', 1],
      ['Gateway', 'Agent', 'Filtered snapshot', 'blue'],
    ];
    const top = 132, step = 38, w = 1040, h = top + rows.length * step + 62;
    const bandTop = top + 2 * step - 24, bandBottom = top + 14 * step + 16;
    let b = `<rect x="56" y="${bandTop}" width="${w - 80}" height="${bandBottom - bandTop}" rx="10" fill="${t.brand}" fill-opacity="0.055" stroke="${t.brand}" stroke-opacity="0.55" stroke-width="1.1" stroke-dasharray="2 5"/>`;
    for (const [name, x] of Object.entries(cols)) {
      b += `<path d="M${x} 78V${h - 62}" stroke="${t.border}" stroke-width="1.25"/>`;
      b += `<rect x="${x - 66}" y="34" width="132" height="44" rx="10" fill="${t.surface}" stroke="${t.border}" stroke-width="1.25"/>`;
      b += `<circle cx="${x - 46}" cy="56" r="4" fill="${tint[name]}"/>` + txt(x - 34, 61, name, { size: 15, weight: 600 });
    }
    b += pill(w - 24 - 190, bandTop, 'SEALED: no actions, no observations', t.brand);
    rows.forEach(([from, to, label, col, mono], i) => {
      const y = top + i * step, x1 = cols[from], x2 = cols[to], dir = x2 > x1 ? 1 : -1;
      const inBand = y > bandTop && y < bandBottom;
      b += txt(32, y + 4, String(i + 1).padStart(2, '0'), { size: 11.5, fill: t.muted, mono: true, anchor: 'middle' });
      b += line([[x1 + dir * 5, y], [x2 - dir * 5, y]], t[col], { dashed: col === 'brand' });
      b += txt((x1 + x2) / 2, y - 9, label, { size: 12.5, fill: col === 'steel' ? t.text : t[col], anchor: 'middle', mono: !!mono, weight: 500, bg: inBand ? null : t.bg });
    });
    b += legend(56, h - 28, [['What the agent sends and sees', t.blue, false], ['Path a secret travels', t.brand, true], ['Internal step', t.steel, false]]);
    return wrap(w, h, 'Sealed login sequence: the agent is refused until the driver has logged in, checked the result and moved to a fresh tab.', b);
  };

  // ---- lifecycle -----------------------------------------------------------------------------

  const lifecycle = () => {
    const w = 1040, h = 470;
    const node = (x, y, ww, name, methods, color) =>
      `<rect x="${x}" y="${y}" width="${ww}" height="78" rx="12" fill="${t.surface}" stroke="${color}" stroke-width="1.4"/>` +
      txt(x + ww / 2, y + 34, name, { size: 16, weight: 600, mono: true, anchor: 'middle' }) +
      txt(x + ww / 2, y + 56, methods, { size: 12, fill: t.muted, anchor: 'middle', mono: true });
    let b = '';
    b += node(40, 110, 176, 'opening', 'status  close', t.steel);
    b += node(300, 110, 176, 'sealed', 'status  close', t.brand);
    b += node(560, 110, 232, 'active', 'observe  act  status  close', t.green);
    b += node(300, 290, 176, 'needs_human', 'status  close', t.amber);
    b += node(40, 290, 176, 'login_failed', 'status', t.red);
    [['closed', 'session.close', t.steel], ['expired', 'lifetime or idle limit', t.steel], ['revoked', 'owner or policy change', t.amber], ['killed', 'tripwire or circuit breaker', t.red]].forEach(([name, why, color], i) => {
      const y = 46 + i * 92;
      b += `<rect x="852" y="${y}" width="148" height="46" rx="12" fill="${t.surface}" stroke="${color}" stroke-width="1.4"/>` + txt(926, y + 29, name, { size: 15, weight: 600, mono: true, anchor: 'middle' });
      b += txt(926, y + 64, why, { size: 11.5, fill: t.muted, anchor: 'middle' });
      b += line([[792, 149], [822, 149], [822, y + 23], [850, y + 23]], t.steel);
    });
    b += line([[216, 149], [298, 149]], t.steel) + pill(257, 149, 'ready', t.muted);
    b += line([[476, 149], [558, 149]], t.green, { width: 2.2 }) + pill(517, 149, 'unseal', t.green);
    b += txt(517, 96, 'the only way in', { size: 12, fill: t.muted, anchor: 'middle' });
    b += line([[352, 188], [352, 288]], t.amber) + pill(352, 238, 'code needed', t.amber);
    b += line([[424, 290], [424, 190]], t.amber) + pill(444, 262, 'owner attends', t.amber);
    b += line([[300, 172], [258, 172], [258, 312], [218, 312]], t.red) + pill(258, 226, 'error', t.red);
    b += line([[300, 346], [218, 346]], t.red) + pill(259, 346, 'timeout', t.red);
    b += txt(40, 418, 'The second line of each state lists the methods the agent may call. Anything else is refused.', { size: 13, fill: t.muted });
    b += txt(40, 440, 'Revoke reaches every live state. Sessions are not resumed after a crash.', { size: 13, fill: t.muted });
    return wrap(w, h, 'Session lifecycle: opening, sealed, needs_human, active, and the terminal states closed, expired, revoked, killed and login_failed.', b);
  };

  // ---- spike results -------------------------------------------------------------------------

  const canaries = () => {
    const groups = [
      ['In page text', t.blue, ['Visible paragraph', 'Page title', 'Image alt text', 'aria-label', 'Inside an iframe', 'Closed shadow DOM', 'Base64 encoded', 'Hex encoded', 'Split across two tags', '20-character chunk', 'Storage token in JSON']],
      ['In markup the agent never receives', t.green, ['Link target', 'URL path segment', 'Hidden form field', 'Input value', 'data- attribute', 'Canvas pixels', 'console.log', 'alert() dialog', 'Login redirect parameter']],
      ['The password, returned by the site at login', t.brand, ['Echoed on the error page', 'Mirrored into the page']],
    ];
    const w = 1040, cw = 232, ch = 40, gx = 14, gy = 10, x0 = 40;
    let b = '';
    [['22', 'hiding places'], ['22', 'secret values scanned for'], ['0', 'reached the agent']].forEach(([n, l], i) => {
      const x = x0 + i * 330;
      b += `<rect x="${x}" y="36" width="300" height="84" rx="10" fill="${t.surface}" stroke="${i === 2 ? t.green : t.border}" stroke-width="1.25"/>`;
      b += txt(x + 20, 92, n, { size: 40, weight: 700, mono: true, fill: i === 2 ? t.green : t.text }) + txt(x + 84, 86, l, { size: 14, fill: t.muted });
    });
    let y = 132;
    for (const [title, color, items] of groups) {
      y += 30;
      b += `<circle cx="${x0 + 4}" cy="${y - 4}" r="4" fill="${color}"/>` + tag(x0 + 16, y, title, t.muted);
      y += 14;
      items.forEach((it, i) => {
        const x = x0 + (i % 4) * (cw + gx), yy = y + Math.floor(i / 4) * (ch + gy);
        b += `<rect x="${x}" y="${yy}" width="${cw}" height="${ch}" rx="8" fill="${t.surface}" stroke="${t.border}" stroke-width="1.1"/>`;
        b += `<path d="M${x + 15} ${yy + 21}l4.5 4.5l8.5 -10" fill="none" stroke="${t.green}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>`;
        b += txt(x + 40, yy + 25, it, { size: 13.5 });
      });
      y += Math.ceil(items.length / 4) * (ch + gy);
    }
    b += txt(x0, y + 26, 'Scanned as plain text, URL-encoded, hex, base64, base64url and 12-character chunks.', { size: 12.5, fill: t.muted });
    return wrap(w, y + 50, 'Spike result: a hostile site hid secrets in 22 places and none reached the agent.', b);
  };

  const egress = () => {
    const w = 1040, h = 318, x0 = 388, full = 560, max = 16;
    const rows = [
      ['Request interception only', 16, '13 WebSocket, 3 from a popup'],
      ['New tabs paused at creation', 13, 'All WebSocket'],
      ['Egress proxy added', 0, 'Nothing leaves'],
    ];
    let b = txt(40, 52, 'Requests that reached a host outside the allowlist', { size: 17, weight: 600 });
    b += txt(40, 76, 'One run of the hostile fixture per configuration. Lower is better.', { size: 13, fill: t.muted });
    rows.forEach(([label, n, note], i) => {
      const y = 112 + i * 52, bw = Math.max((n / max) * full, 0);
      b += txt(40, y + 20, label, { size: 14.5, weight: 500 }) + txt(40, y + 38, note, { size: 12, fill: t.muted });
      b += `<rect x="${x0}" y="${y + 6}" width="${full}" height="24" rx="6" fill="${t.surface}" stroke="${t.border}" stroke-width="1"/>`;
      if (n) b += `<rect x="${x0}" y="${y + 6}" width="${bw}" height="24" rx="6" fill="${t.red}" fill-opacity="0.85"/>`;
      b += txt(x0 + full + 16, y + 24, String(n), { size: 17, weight: 700, mono: true, fill: n ? t.red : t.green });
    });
    b += txt(40, h - 22, 'Browser request interception does not pause WebSocket connections, so the proxy is required.', { size: 12.5, fill: t.muted });
    return wrap(w, h, 'Requests reaching a host outside the allowlist: 16 with interception only, 13 with new tabs paused, 0 with the egress proxy.', b);
  };

  return { logo, banner, architecture, sealedLogin, lifecycle, canaries, egress };
}

const out = path.join(__dirname, '..', 'assets');
fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });
const written = [];
for (const [name, theme] of Object.entries(THEMES)) {
  const d = make(theme);
  const files = { banner: d.banner(), architecture: d.architecture(), 'sealed-login': d.sealedLogin(), lifecycle: d.lifecycle(), 'spike-canaries': d.canaries(), 'spike-egress': d.egress() };
  for (const [f, svg] of Object.entries(files)) { fs.writeFileSync(path.join(out, `${f}-${name}.svg`), svg); written.push(`${f}-${name}.svg`); }
  if (name === 'dark') { fs.writeFileSync(path.join(out, 'logo.svg'), d.logo()); written.push('logo.svg'); }
}
console.log('wrote ' + written.length + ' files');
