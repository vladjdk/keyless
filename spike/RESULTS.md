# Prototype measurements

[results.json](results.json) is the recorded report from the legacy prototype. Its numbers are not measurements of the Rust implementation. The current Rust fixture command is:

```bash
cargo run --bin spike -- /path/to/chrome
```

Run it from the repository root. Rust measurement output belongs in `spike/results-rust.json`. No Rust result count is asserted in this document.

## Legacy fixture results

The report contains two configurations, one with browser request interception alone and one with interception plus a host-allowlisting proxy.

| Measurement | Interception only | With proxy |
|---|---:|---:|
| Passing behavioural checks | 27 of 27 | 27 of 27 |
| Canaries scanned | 22 | 22 |
| Detected leaks in tapped output | 0 | 0 |
| Tapped bytes | 31,115 | 31,013 |
| Attacker TCP connections | 16 | 0 |
| Attacker WebSocket upgrades | 13 | 0 |
| Benign observations | 15 | 15 |
| Benign observations with masks | 0 | 0 |
| Accessibility password probes | 5 | 5 |
| Password visible in those probes | 0 | 0 |
| Dialogs dropped | 1 | 1 |
| Broker errors | 0 | 0 |

The recorded scanner covered plain, URL-encoded, hex, base64 at all alignments, base64url and 12-character chunks. Zero detected canary leaks is a finite fixture result, not a proof of arbitrary-site confidentiality.

## Behavioural coverage

- Classic form and no-navigation SPA login; a fresh post-login tab.
- Observation and action refusal while sealed with `session_sealed`.
- Wrong-password echo returning an enum-only failure; password residue in page text failing closed with `secret_residue`.
- Dashboard and invoice reading, a readable echo page with withheld markers, GET search and readback of ordinary agent-typed text.
- Stale references, POST blocking in `safe-methods`, prohibited navigation, redirect-hop refusal, popup closure and continued session use.
- Rejection of non-allowlisted keys.
- Ordinary typing for an incorrect guess; session termination and subject suspension when the agent types the vault secret.

The fixture places cookie canaries in visible text, title, alt/ARIA text, link targets, URL paths, hidden fields, input values, data attributes, frames, closed shadow DOM, canvas, console, dialogs, encoded text and split/chunked text. It also includes a storage token nested in JSON.

## Transport observations

The interception-only report records 13 WebSocket upgrades at the attacker and 16 attacker TCP connections. The proxy report records neither. The proxy denied 5 HTTP requests and 181 CONNECT requests in the recorded run. Browser interception alone is not host confinement.

These measurements do not verify every browser transport or production TLS enforcement. Required transport and platform verification is listed in [tradeoffs and gaps](../docs/TRADEOFFS.md#verification-gaps).

## Explicit security exclusions

Both configurations record all three of the following:

| Fixture condition | Recorded result |
|---|---|
| API token rendered as page text | Visible |
| Non-HttpOnly cookie transformed by same-origin script | Visible |
| State-changing GET | State changed |

These outcomes demonstrate exclusions in the specified security target. They are not canary-scanner failures concealed from the result count.

## Evidence boundary

The legacy prototype ran as a single process under the caller's uid, without service isolation. Its tapped agent channel was an in-process function boundary, not a real socket. The fixture used HTTP on localhost. It did not implement TOTP, owner attendance, lifetime/revocation controls or an audit chain.

The isolated production architecture is specified in [DESIGN.md](../docs/DESIGN.md). Unimplemented capabilities, unrun real-application benchmarks, platform isolation checks and independent-audit status are listed in [TRADEOFFS.md](../docs/TRADEOFFS.md).
