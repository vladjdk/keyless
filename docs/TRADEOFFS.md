# Tradeoffs and gaps

[README](../README.md) describes the repository. [DESIGN.md](DESIGN.md) specifies the isolated production system. [Prototype measurements](../spike/RESULTS.md) describe recorded fixture evidence. Requirements are not implementation claims.

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
| One browser per session | Separates browser memory and state | Estimated 200–300 MB per session; not a repository benchmark |
| Secret length/entropy floors | Avoids withholding ordinary text such as language codes | Short and low-entropy tokens are not fully covered by matching |
| Vault-secret tripwire | Prevents graded credential-guess redaction feedback | Secret-bearing page content can terminate a session; detection reveals a coarse kill outcome |
| Rust and allowlisted CDP | Explicit ownership and a restricted browser-control surface | Browser lifecycle, zeroisation and protocol correctness still require tests |
| Local revocation | Ends the agent's access to the local browser | Does not invalidate a server-side session already copied elsewhere |
| Forward-secure audit MAC | Limits external-writer tampering | Keeper-originated tail truncation needs a separate checkpoint sink |

## Unimplemented production capabilities

The fixture prototype is not the isolated production architecture. The following production capabilities are not implemented:

- Keeper/Driver/Gateway service separation, privileged installer, dedicated session uids and isolation diagnostics.
- Encrypted production vault, signing/enrolment flow, signed manifests, rollback protection and external vault backends.
- TOTP, owner-only SMS/email attendance and the complete `needs_human` flow.
- Production lifetime limits, local revocation controls and the full circuit breaker.
- Hash-chained forward-secure audit log, event hooks and independent checkpoints.
- JSON-RPC Unix-socket binding, authenticated subjects and the Rust MCP adapter using `modelcontextprotocol/rust-sdk`.
- A complete normative specification with requirement IDs, negotiation rules, schemas, transition tables and a black-box conformance kit.
- Production deny packs, reproducible signed releases and audited dependency attestations.

The prototype's local login, filtering, policy and hostile-site checks are narrower than these requirements. Their Rust verification status must be taken from `spike/results-rust.json` after a measured run, not inherited from the legacy report.

## Verification gaps

- No independent security audit has been performed.
- [spike/results.json](../spike/results.json) contains legacy prototype measurements. It does not verify the Rust implementation.
- The legacy fixture uses HTTP on localhost and an in-process tapped boundary. It does not test production TLS enforcement or a real agent socket.
- The isolated macOS LaunchDaemon installation and agent-uid memory/file probes have not been tested. Linux isolation is also not established by the legacy fixture.
- The ten-read-task benchmark on Gitea, Nextcloud and WordPress has not been run. The production ten-site completion and installation-time targets are unmeasured.
- Secret-floor false positives were measured on one fixture: zero masked observations among 15 benign observations in each recorded configuration. This is not a real-site false-positive rate.
- The legacy report records five accessibility-tree password probes per configuration with no visible password. It does not establish that every Chromium build or login widget behaves identically.
- WebSocket escape and proxy blocking are recorded fixture results. WebTransport, WebRTC, UDP/QUIC, DNS, TLS trust-store handling, all worker/frame types and platform firewall confinement are not established by that report.
- Atomic secret/snapshot capture, cookie rotation, storage enumeration, cross-message scanning and all transformed-token cases require independent conformance evidence.
- Protocol/HTML/URL fuzzing, crypto negative vectors, crash cleanup, audit truncation, stock-agent recovery and cross-implementation conformance are not verified by the legacy report.
- Device-bound session behaviour in headless Chromium and on Linux has not been verified.

## Threat-model exclusions

The specified security target does not cover:

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

The legacy fixture explicitly demonstrates three exclusions: a readable rendered API token, a transformed non-HttpOnly cookie and a state-changing GET.

## Additional capabilities outside the initial scope

- Encrypted persistent profiles with bounded age and cryptographic erasure; owner-only headed attendance for CAPTCHA and device challenges.
- SSO with transit-only identity-provider origins, broker-controlled consent, passkeys and explicit mid-session re-authentication.
- Server-side logout, device-specific revocation and device-bound sessions.
- Policy-controlled WebSocket support, masked screenshots and quarantined file transfer.
- 1Password and Bitwarden vault adapters; a signed recipe/deny-pack registry.
- Attested remote execution with attestation-bound transport keys; a second browser driver using WebDriver BiDi.
- Independent signed audit checkpoints and stricter subresource policies.

These capabilities are not implemented and are not prerequisites implied by the prototype run commands.

## Unresolved choices

- Final public name, package/trademark availability and governance model.
- Specification license: Community Specification License 1.0 or CC-BY 4.0 with a patent grant. The Rust package declares Apache-2.0 in `Cargo.toml`; the repository has no license text.
- Exact secret floors, storage decomposition rules, supported-site list and narrowly scoped permits for read-over-POST applications.
- A restricted mechanism for transferring session-only authentication state across the login tab swap.
- Platform enforcement details for controlled browser trust stores, encrypted swap, ephemeral profiles and transport/firewall confinement.
- Exact approval-hook interface and trust boundary for `require_approval`.

Rust, local lifetime/revocation requirements and privileged Isolated installation are specified architecture choices, not pending language or scope decisions.
