# Tradeoffs and gaps

This is the list of what keyless costs, what is not built yet, what has not been tested and what it does not try to protect against. [DESIGN.md](DESIGN.md) has the spec and [prototype measurements](../spike/RESULTS.md) have the test results.

## Engineering tradeoffs

| Choice | Benefit | Cost or limitation |
|---|---|---|
| Constructive accessibility observations | Smaller output surface than raw browser access | No visual interpretation; inaccessible UI and canvas tasks lose information |
| No screenshots or file transfers | Avoids additional secret-bearing output/input channels | Blocks image, upload and download workflows |
| Fresh browser profile per session | Limits state persistence and cross-session residue | Repeated device challenges and headless-browser rejection |
| Fresh tab after login | Removes login-page heap, history and form state from the active tab | Sites relying only on `sessionStorage` lose authentication unless a restricted transfer is specified |
| GET/HEAD default | Restricts ordinary write requests | POST/GraphQL reads fail; GET can still change state |
| Host proxy plus target interception | Separates host confinement from method/path control | Proxy, target lifecycle and platform firewall enforcement must agree |
| Block WebSocket, WebTransport and WebRTC | Reduces transport-policy bypass surface | Excludes transport-dependent sites |
| Dedicated service and browser identities | Protects memory and files from a same-user agent shell | Privileged installation, platform-specific hardening and identity management |
| One browser per session | Separates browser memory and state | Roughly 200–300 MB per session (estimate, not measured here) |
| Secret length/entropy floors | Avoids withholding ordinary text such as language codes | Short and low-entropy tokens are not fully covered by matching |
| Vault-secret tripwire | Prevents graded credential-guess redaction feedback | Secret-bearing page content can terminate a session; detection reveals a coarse kill outcome |
| Rust and allowlisted CDP | Explicit ownership and a restricted browser-control surface | Browser lifecycle, zeroisation and protocol correctness still require tests |
| Local revocation | Ends the agent's access to the local browser | Does not invalidate a server-side session already copied elsewhere |
| Forward-secure audit MAC | Limits external-writer tampering | Keeper-originated tail truncation needs a separate checkpoint sink |

## Unimplemented production capabilities

None of the following exists yet:

- Keeper/Driver/Gateway service separation, privileged installer, dedicated session uids and isolation diagnostics.
- Encrypted production vault, signing/enrolment flow, signed manifests, rollback protection and external vault backends.
- TOTP, owner-only SMS/email attendance and the complete `needs_human` flow.
- Production lifetime limits, local revocation controls and the full circuit breaker.
- Hash-chained forward-secure audit log, event hooks and independent checkpoints.
- JSON-RPC Unix-socket binding, authenticated subjects and the Rust MCP adapter using `modelcontextprotocol/rust-sdk`.
- A complete normative specification with requirement IDs, negotiation rules, schemas, transition tables and a black-box conformance kit.
- Production deny packs, reproducible signed releases and audited dependency attestations.

The prototype covers a narrower version of login, filtering, policy and the hostile-site checks. It also has the request gate (fixed patterns, an optional escalate-only Jev classifier and an owner approval hook) and a Development-profile MCP server for dogfooding; see [DOGFOOD.md](DOGFOOD.md). The Rust port's results come from its own run (`spike/results-rust.json`), so the legacy numbers do not carry over.

## Verification gaps

- The Jev classifier has not been run against the live API here; only its request format and response handling are tested against a local stand-in. `jev-eval` measures it once a key is available. Published third-party tests put its prompt-injection recall between about 63% and 83%, so it is a second opinion, not a gate on its own.
- Gate patterns are English path, field and label words. They miss state changes hidden in GraphQL or RPC bodies (`POST /graphql`), non-English labels and state-changing GETs with neutral names (the fixture's `/prefs/sync` passes without a classifier).
- New-token withholding only runs on pages whose path falls into a credential, authorization or account-security category. A token shown in a modal on `/` or on a neutral path reaches the agent.

- No independent security audit has been performed.
- [spike/results.json](../spike/results.json) is from the legacy JavaScript prototype and says nothing about the Rust port.
- The legacy fixture uses HTTP on localhost and an in-process tapped boundary. Neither TLS enforcement nor a real agent socket has been tested.
- The isolated macOS LaunchDaemon installation and agent-uid memory/file probes have not been tested. Neither has Linux isolation.
- The ten-read-task benchmark on Gitea, Nextcloud and WordPress has not been run. The production ten-site completion and installation-time targets are unmeasured.
- Secret-floor false positives were measured on one fixture: zero masked observations among 15 benign observations in each recorded configuration. One fixture tells us little about real sites.
- The legacy report records five accessibility-tree password probes per configuration with no visible password. Other Chromium builds and login widgets may behave differently.
- WebSocket escape and proxy blocking are recorded fixture results. WebTransport, WebRTC, UDP/QUIC, DNS, TLS trust-store handling, all worker/frame types and platform firewall confinement are untested.
- Atomic secret/snapshot capture, cookie rotation, storage enumeration, cross-message scanning and all transformed-token cases still need conformance tests.
- Protocol/HTML/URL fuzzing, crypto negative vectors, crash cleanup, audit truncation, stock-agent recovery and cross-implementation conformance are untested.
- Device-bound session behaviour in headless Chromium and on Linux has not been verified.

## Threat-model exclusions

The security target does not cover:

- Misuse of actions that policy permits, including account recovery changes, passkey creation, API-token generation and OAuth grants.
- API tokens, recovery codes or other secrets rendered as allowed page text outside the enumerated match set.
- Same-origin attacker script that transforms or chunks non-HttpOnly secrets beyond supported matching, including reflected XSS and uploaded active content.
- Exfiltration through allowed site features such as mail, comments, sharing or export.
- State changes triggered by GET requests.
- Sites exposing in-app code execution, including cloud shells, CI consoles and script editors.
- Confidentiality of ordinary page content the agent is permitted to read.
- Availability: hostile page content can cause session termination.
- Hardware side channels, cold-boot attacks or an adversary with root privileges.
- Same-user memory/file protection in the Development profile.
- A compromised agent persuading an owner to disclose a password or code outside the broker's input channel.

The legacy fixture reproduces three of these on purpose: a readable rendered API token, a transformed non-HttpOnly cookie and a state-changing GET.

## Additional capabilities outside the initial scope

- Encrypted persistent profiles with bounded age and cryptographic erasure; owner-only headed attendance for CAPTCHA and device challenges.
- SSO with transit-only identity-provider origins, broker-controlled consent, passkeys and explicit mid-session re-authentication.
- Server-side logout, device-specific revocation and device-bound sessions.
- Policy-controlled WebSocket support, masked screenshots and quarantined file transfer.
- 1Password and Bitwarden vault adapters; a signed recipe/deny-pack registry.
- Attested remote execution with attestation-bound transport keys; a second browser driver using WebDriver BiDi.
- Independent signed audit checkpoints and stricter subresource policies.

## Unresolved choices

- Package and trademark availability for the `keyless` name, and the governance model.
- Specification license: Community Specification License 1.0 or CC-BY 4.0 with a patent grant. The code is licensed under Apache-2.0 ([LICENSE](../LICENSE)).
- Exact secret floors, storage decomposition rules, supported-site list and narrowly scoped permits for read-over-POST applications.
- A restricted mechanism for transferring session-only authentication state across the login tab swap.
- Platform enforcement details for controlled browser trust stores, encrypted swap, ephemeral profiles and transport/firewall confinement.
- Exact approval-hook interface and trust boundary for `require_approval`.

Rust, local lifetime and revocation, and the privileged Isolated installer are settled.
