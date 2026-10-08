// Minimal CDP client over --remote-debugging-pipe, with a method allowlist.
// Throwaway spike code (M0). Not the reference implementation.

const ALLOW = new Set([
  'Target.createTarget', 'Target.attachToTarget', 'Target.closeTarget',
  'Target.setDiscoverTargets', 'Target.setAutoAttach',
  'Page.enable', 'Page.navigate', 'Page.getFrameTree', 'Page.handleJavaScriptDialog',
  'Network.enable', 'Storage.getCookies',
  'Fetch.enable', 'Fetch.continueRequest', 'Fetch.failRequest',
  'DOM.enable', 'DOM.getDocument', 'DOM.querySelector', 'DOM.describeNode', 'DOM.focus',
  'DOM.resolveNode', 'DOM.getBoxModel', 'DOM.scrollIntoViewIfNeeded',
  'DOMStorage.getDOMStorageItems',
  'Accessibility.getFullAXTree',
  'Input.insertText', 'Input.dispatchKeyEvent', 'Input.dispatchMouseEvent',
  // Driver-internal only: read a field's value and focus state. Never exposed to the agent.
  'Runtime.callFunctionOn', 'Runtime.runIfWaitingForDebugger',
]);

class CDP {
  constructor(proc) {
    this.w = proc.stdio[3];
    this.r = proc.stdio[4];
    this.id = 0;
    this.pending = new Map();
    this.handlers = new Map();
    this.buf = Buffer.alloc(0);
    this.closed = false;
    this.r.on('data', (d) => this._data(d));
    this.r.on('close', () => this._close());
    this.w.on('error', () => this._close());
  }

  _close() {
    this.closed = true;
    for (const { reject } of this.pending.values()) reject(new Error('cdp closed'));
    this.pending.clear();
  }

  _data(d) {
    this.buf = Buffer.concat([this.buf, d]);
    let i;
    while ((i = this.buf.indexOf(0)) !== -1) {
      const msg = JSON.parse(this.buf.subarray(0, i).toString('utf8'));
      this.buf = this.buf.subarray(i + 1);
      if (msg.id !== undefined) {
        const p = this.pending.get(msg.id);
        if (!p) continue;
        this.pending.delete(msg.id);
        if (msg.error) p.reject(new Error(`${p.method}: ${msg.error.message}`));
        else p.resolve(msg.result);
      } else if (msg.method) {
        for (const fn of this.handlers.get(msg.method) || []) {
          Promise.resolve(fn(msg.params, msg.sessionId)).catch(() => {});
        }
      }
    }
  }

  send(method, params = {}, sessionId) {
    if (!ALLOW.has(method)) throw new Error(`CDP method not on allowlist: ${method}`);
    if (this.closed) return Promise.reject(new Error('cdp closed'));
    const id = ++this.id;
    const msg = { id, method, params };
    if (sessionId) msg.sessionId = sessionId;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, method });
      this.w.write(JSON.stringify(msg) + '\0');
    });
  }

  on(event, fn) {
    if (!this.handlers.has(event)) this.handlers.set(event, []);
    this.handlers.get(event).push(fn);
  }
}

module.exports = { CDP, ALLOW };
