# src

```text
lib.rs               Error type, shared helpers (text, sleep), module list
broker/              The broker: logs in for the agent and filters what it sees
  mod.rs             Types, request dispatch, session teardown, URL allow rule
  login.rs           Sealed login: fill, submit, success check, secret scan, fresh tab
  browser.rs         Starting Chrome, opening pages, low-level CDP helpers
  events.rs          Browser events: request filtering, popups, dialogs, secret collection
  agent.rs           What the agent gets: observe (page snapshot) and act (click, type, ...)
cdp.rs               Chrome DevTools Protocol client over a pipe, with a method allowlist
secrets.rs           Secret encodings and matching (plain, URL, hex, base64)
http.rs              Minimal HTTP/1.1 server and request parser for the test fixtures
fixture.rs           Hostile test website, attacker server and egress proxy
harness.rs           Runs the fixture end to end and scans agent output for leaks
diagrams.rs          Writes the SVG diagrams in assets/ from diagram_templates/
diagram_templates/   Source SVGs for the logo, banners and diagrams
bin/spike.rs         `cargo run --bin spike -- /path/to/chrome`
bin/diagrams.rs      `cargo run --bin diagrams`
```

The agent only ever talks to `Broker::handle` in `broker/mod.rs`. Everything it receives passes through `agent.rs`.
