# Prototype measurements

[results.json](results.json) is the report from the legacy JavaScript prototype. The Rust port has its own run:

```bash
cargo run --bin spike -- /path/to/chrome
```

Run it from the repository root. It writes `spike/results-rust.json`. The numbers below are all from the legacy prototype.

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

The recorded scanner covered plain, URL-encoded, hex, base64 at all alignments, base64url and 12-character chunks. Zero leaks on this fixture is a good sign, but it does not prove the same holds on every site.

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

Other browser transports and TLS enforcement were not tested; see [tradeoffs and gaps](../docs/TRADEOFFS.md#verification-gaps).

## Explicit security exclusions

Both configurations record all three of the following:

| Fixture condition | Recorded result |
|---|---|
| API token rendered as page text | Visible |
| Non-HttpOnly cookie transformed by same-origin script | Visible |
| State-changing GET | State changed |

These are known gaps in the security target, and the fixture includes them on purpose. They are reported here rather than counted as scanner failures.

## Evidence boundary

The legacy prototype ran as a single process under the caller's uid, without service isolation. Its tapped agent channel was an in-process function call rather than a socket. The fixture used HTTP on localhost. It did not implement TOTP, owner attendance, lifetime/revocation controls or an audit chain.

The production architecture is in [DESIGN.md](../docs/DESIGN.md). What is still missing or untested is in [TRADEOFFS.md](../docs/TRADEOFFS.md).
