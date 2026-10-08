<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/banner-dark.svg">
    <img src="assets/banner-light.svg" alt="keyless: sealed browser sessions for AI agents" width="100%">
  </picture>
</p>

<p align="center">
  <a href="#architecture">Architecture</a> ·
  <a href="#security-model">Security model</a> ·
  <a href="#prototype-results">Prototype results</a> ·
  <a href="docs/DESIGN.md">Design</a> ·
  <a href="docs/TRADEOFFS.md">Tradeoffs and gaps</a>
</p>

# keyless

keyless is a local browser-session broker for AI agents. Its specified production design keeps credentials and enumerated session secrets behind an isolated service boundary and exposes a filtered page view with restricted actions.

Status: pre-alpha prototype. The isolated production broker is not implemented. No independent security audit has been performed. The prototype does not establish protection against an agent with a same-user shell.

## Run

The repository uses Rust and Cargo. A Chrome or Chromium executable is required for the browser fixture.

```bash
cargo build
cargo test
cargo run --bin spike -- /path/to/chrome
cargo run --bin diagrams
```

The `spike` binary runs the local hostile-site fixture and behavioural checks. The `diagrams` binary generates SVG assets. These commands do not install an isolated service. Rust measurement output belongs in `spike/results-rust.json`; [spike/results.json](spike/results.json) contains legacy prototype measurements, not Rust results.

## Architecture

The table and diagrams describe the specified isolated production design, not the prototype's process boundaries.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/architecture-dark.svg">
    <img src="assets/architecture-light.svg" alt="Specified architecture: the gateway exposes a filtered protocol; credentials remain within keeper, driver, browser and site." width="100%">
  </picture>
</p>

| Component | Responsibility | Required boundary |
|---|---|---|
| Keeper | Vault access, authorisation, audit | No browser-page or agent-protocol parsing |
| Driver | Login, browser control, filtering, secret matching, egress proxy | Session-limited access to credential material |
| Gateway | Agent protocol, schemas, session state | No credential material |
| Browser | One sandboxed Chromium instance per session | Separate session uid; allowlisted egress |

Rust is the implementation language for the prototype, diagram generator and specified services. The specified MCP adapter uses the official `modelcontextprotocol/rust-sdk` (`rmcp`); the adapter is not implemented.

## Sealed login

The production design requires the broker to select the login target from the credential binding. The agent supplies neither login selectors nor credential input and receives no page observations or actions during login.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/sealed-login-dark.svg">
    <img src="assets/sealed-login-light.svg" alt="Specified sealed login: broker-controlled fill, success and residue checks, then a fresh tab." width="100%">
  </picture>
</p>

Activation requires a passing stored success assertion, empty tainted fields and a passing secret scan. A fresh tab opens at the pinned post-login URL; the login tab closes and the success assertion is checked again. Cookies persist. Login-page script state and form history are not transferred.

## Session lifecycle

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/lifecycle-dark.svg">
    <img src="assets/lifecycle-light.svg" alt="Specified lifecycle: opening, sealed, needs_human, active, and terminal states." width="100%">
  </picture>
</p>

The design specifies local expiration and revocation. The diagram is not an implementation-status map; [tradeoffs and gaps](docs/TRADEOFFS.md) lists unimplemented capabilities.

## Agent interface

The production protocol exposes a structured text observation and `click`, `type`, `select`, `scroll`, `navigate` and `wait` actions. Element references are snapshot-bound. The agent can read back ordinary values it typed; broker-filled credentials remain tainted.

The protocol does not expose script evaluation, raw HTML, attributes, link targets, hidden fields, cookies, storage or network inspection. Screenshots and file transfers are outside the initial protocol scope. Withheld content uses a fixed marker without disclosing its length.

New credentials default to `safe-methods`: GET and HEAD only. This restricts request methods; it does not make a website read-only.

## Security model

The adversary is a prompt-injected agent that can use its granted tools, including a shell under its own uid. The specified Isolated profile requires that every principal the agent can act as be unable to read service memory or files, modify service code or configuration, or access raw browser control.

The security target is non-emission of vault secrets and an enumerated session-secret set in plain, URL-encoded, base64 and hex form on the agent channel. This is a conformance requirement, not a verified guarantee for this repository. A passing finite fixture suite does not prove arbitrary-site confidentiality.

An allowed page can expose a newly created API token, transform a non-HttpOnly cookie beyond the matcher, or perform a state change through GET. Filtering does not prevent misuse of authorised site features. Full exclusions and verification gaps are in [docs/TRADEOFFS.md](docs/TRADEOFFS.md); engineering requirements are in [docs/DESIGN.md](docs/DESIGN.md).

## Prototype results

[Legacy prototype measurements](spike/RESULTS.md) record two local fixture configurations, each with 27 passing behavioural checks and no detected leaks among 22 scanned canaries. These are historical measurements from the legacy prototype, not measurements of the Rust implementation.

In the recorded interception-only configuration, the attacker received 13 WebSocket upgrades and 16 TCP connections. In the proxy configuration, it received zero upgrades and zero TCP connections. The fixture also records a visible API token, a transformed cookie and a state-changing GET as explicit security exclusions.

The raw legacy report is [spike/results.json](spike/results.json). Current Rust measurements must be read from `spike/results-rust.json` after a Rust fixture run; no Rust pass count is asserted here.

## Repository layout

```text
Cargo.toml           Rust package and binary definitions
src/                 Rust prototype and diagram-generation sources
spike/               Fixture reports and measurement documentation
assets/              Branding and SVG diagrams
docs/DESIGN.md       Production architecture and engineering requirements
docs/TRADEOFFS.md    Tradeoffs, unimplemented capabilities and verification gaps
```

## License

`Cargo.toml` declares Apache-2.0 for the Rust package. The repository does not include a license text. Specification licensing is listed in [tradeoffs and gaps](docs/TRADEOFFS.md).
