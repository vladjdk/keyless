# keyless design

keyless specifies a local broker that lets an agent operate an authenticated website through a filtered channel. Credentials and raw browser control remain inside the broker boundary.

This document specifies the isolated production system. It does not describe an implemented production release. The repository contains a browser-fixture prototype and diagram generator written in Rust. [Prototype measurements](../spike/RESULTS.md) and [tradeoffs and gaps](TRADEOFFS.md) distinguish recorded evidence from requirements.

## Scope

The initial deployment is local and single-owner, for coding or operations agents using admin consoles, vendor portals and billing dashboards without a suitable API. The interface consists of command-line tools, files and a protocol; authorisation is policy-based rather than a prompt for each action.

The production scope includes password and TOTP login, sealed sessions, default-deny request policy, local lifetime limits and revocation, an audit trail, an MCP binding and a public conformance kit. Password forms, identifier-first flows and TOTP require broker-controlled recipes. SMS and email codes require an owner-only TTY input channel.

Excluded capabilities, implementation gaps and unresolved choices are listed separately in [TRADEOFFS.md](TRADEOFFS.md).

## Security target

For a conformant Isolated deployment, the agent channel must not emit vault secrets or members of the enumerated session-secret set in plain, URL-encoded, base64 or hex form under the conformance suite. The suite must scan concatenated messages, including errors and handles. This is a specified test obligation, not a verified guarantee of the current prototype.

Vault secrets include passwords, TOTP seeds and live login codes. The session-secret set includes cookie values, credential-bearing headers, qualifying storage values and login redirect parameters. Structural non-emission excludes raw HTML, attributes, hidden fields and network data from the protocol. These controls do not establish confidentiality for every token a site renders or transforms.

An agent is an untrusted principal subject to prompt injection. It can use all tools and privileges granted to it, including a same-user shell. The Isolated profile must prevent every principal the agent can act as from reading broker or browser memory, reading vault files, replacing binaries or configuration, or obtaining raw browser control. At-rest encryption does not replace this boundary.

## Protocol and conformance

The Core specifies observable behaviour in terms of Agent, Broker, Browser and Site. The reference process architecture is an implementation detail.

| Specification surface | Required content |
|---|---|
| Core | Methods, state transitions and security requirements |
| Bindings | Size-capped newline-delimited JSON-RPC 2.0 over a Unix socket; MCP tool profile; subject authentication |
| Data model | Credential bindings, policy, signed manifest, audit schema and resource types |
| Vault backend interface | `unwrap`, `totp(id, t)`, `release(id, origin)` |
| Reference architecture | Service identities, key hierarchy and process isolation |

- Normative requirements use BCP 14 keywords and unique IDs, each mapped to a conformance test.
- Conformance classes are Broker, Vault Backend and Agent Binding. Assurance profiles are a separate axis.
- A subject is binding-authenticated, never client-asserted. The Unix binding derives identity from socket path and peer uid. Agents sharing a uid are indistinguishable.
- `initialize` negotiates version, capabilities, achieved assurance profile and limits under an explicit negotiation rule.
- Unknown fields fail closed in policy and binding documents; unknown response fields are ignored.
- Errors use stable `snake_case` codes and do not disclose secret-dependent state. The secret-match exception has only `session_killed` and subject state `suspended` outcomes.
- Policy refusals expose `denied_by_policy`; matching rule IDs appear only in the audit log.
- URL canonicalisation follows the WHATWG URL Standard.
- Conformance requires the Isolated profile and a passing conformance-kit report. The same-user prototype is not conformant.

## Rust stack

Keeper, Driver, Gateway, the prototype and the diagram generator use Rust. The production MCP adapter uses the official `modelcontextprotocol/rust-sdk` (`rmcp`) on the untrusted side of the broker. No separate runtime is required for the adapter.

The browser driver uses an allowlisted CDP client over an inherited pipe, with Chromium pinned by hash and the browser sandbox enabled. Production dependencies require `cargo-vet` and `cargo-deny` checks. Release requirements include signatures and reproducible builds. These are production requirements, not evidence of dependency audit or release verification.

Repository commands are documented in [README.md](../README.md#run).

## Reference architecture

A root-owned supervisor spawns the services and passes inherited socketpairs. The agent socket directory is root-owned.

| Component | Identity and responsibility |
|---|---|
| Keeper | Dedicated uid; vault identity, TOTP, policy decisions and sole audit writer; no browser-page or agent-protocol parser |
| Driver | Broker service identity; sole CDP client, login controller, observation builder, secret matcher and egress proxy |
| Gateway | Broker service identity; agent socket, protocol state and schema validation; no vault secrets or secret hashes |
| Chromium | Separate uid per session; sandboxed; ephemeral RAM-backed or encrypted profile; proxy-confined egress |
| Event hook | Separate unprivileged uid; fixed argv and clean environment |
| Enrolment | Separate uid; write-only vault inbox and restricted signing-key access |

The Gateway's socket writer must accept only a Driver-minted filtered observation type. An architecture test must enforce that restriction. The Keeper releases one secret per authorised fill; TOTP seeds never leave it. The Driver retains the session's vault secret in locked memory for matching and zeroises it at session end.

Internal channels are inherited descriptors, not named sockets authenticated only by uid. Each session has its own Chromium process, with an estimated 200–300 MB footprint and a default global cap of four sessions. Sessions are not resumable. Driver or Gateway failure destroys the associated browser process group; startup removes stale profiles.

## Assurance and installation requirements

| Profile | Required property |
|---|---|
| Development | Same uid as the agent; transcript filtering only; explicitly non-conformant |
| Isolated | Agent-reachable principals cannot read protected memory or files or modify service code, configuration or launch paths |
| Attested | Separate machine or microVM with attestation-bound key release; outside the initial implementation scope |

The specified Isolated installer uses dedicated service uids: systemd system/socket units and transient browser identities on Linux; a root-owned LaunchDaemon and browser-uid pool on macOS. Containers alone do not establish isolation from an agent that controls their runtime.

- Binaries and hash-pinned Chromium must be root-owned. Any non-root-writable ancestor of service executables, browser, vault, policy or hooks prevents Isolated startup.
- The Chromium sandbox must be enabled and verified at launch. Linux requires the user-namespace sandbox and an appropriate AppArmor profile where required.
- Linux services require non-dumpable state, disabled core dumps, no new privileges, restricted `/proc` access and swap disabled.
- macOS requires protected RAM-disk or per-session encrypted profiles, locked secret pages, encrypted swap and full-disk encryption for hibernation exposure. A failed platform check prevents reporting Isolated.
- Enrolment uses a root-owned sudoers rule with environment reset, a fixed command, password authentication and no credential caching.
- Isolation diagnostics must check cached/passwordless sudo, container-runtime access, path ownership, browser sandbox, dump limits, encryption and shadowed owner commands.
- The handshake and every audit record must state the achieved profile.

## Keys and credential bindings

The vault uses an age identity wrapped in independent slots: an unattended Keeper key restricted to its uid, an Argon2id passphrase slot for administration/export/backup, and optional hardware sealing. Records are age-encrypted to the public key, so adding a record does not require unlocking existing records.

A broker-side binding references a backend `secret_ref` and specifies `login_url`, `post_login_url`, `fill_origins`, `session_origins`, recipe and success assertion. These bindings apply equally to built-in and external vault backends.

An Ed25519 owner signature covers a manifest containing `vault_id`, `epoch`, record hashes, binding hashes, policy hash and hook path. The Keeper refuses unlisted or mismatched records. The signing key is passphrase-wrapped and inaccessible to the agent. The Keeper pins the public key and rejects epochs below its stored high-water mark. Epoch and audit-MAC state are excluded from backup/restore sets.

Session handles are 128-bit random values bound to their creating connection. Secrets enter through owner-only TTY input, never command arguments or piped plaintext. Bulk vault import uses a restricted file descriptor.

## Owner and agent interfaces

The production CLI requires `install`, `add`, `agent add`, `policy edit`, `policy explain`, `policy test`, `attend`, `doctor`, `sessions ls`, scoped `revoke` and `audit tail` commands. These commands are specified interfaces, not available prototype commands. Installation must clear cached sudo credentials. Credential enrolment must validate a test login, derive a success assertion and post-login URL, obtain owner confirmation and warn when a password falls below the tripwire floor.

Agent refusals require `{code, retryable, retry_after, explanation, next_step, tell_user}`. Repeated identical refusals return `stop_retrying`. Tool descriptions must prohibit requesting passwords or codes through the agent. A `needs_human` response can direct the owner to the attendance command without conveying secret material. Denied audit entries should identify a narrowly scoped permit rather than a broad policy relaxation.

## Session states

The normative transition table must specify each state, trigger, permitted method and error. Its vocabulary governs the lifecycle diagram.

```text
opening -> sealed -> active -> closed | expired | revoked | killed
              |
              +-> needs_human -> sealed
              +-> login_failed | locked_out_risk
```

`session.open` returns immediately with `opening` and `retry_after`. The unseal predicate is the only transition into `active`. Human attendance has its own timeout. Subject states are `enabled` and `suspended`.

## Sealed login requirements

- The Driver controls the entire login. Before `active`, the agent receives no observations and cannot act.
- Login requests follow `fill_origins` and `session_origins`; the active-session request mode does not block the login form submission.
- Each session permits one fill sequence. The Driver types the username and verifies the displayed identifier before releasing any secret.
- Filling requires a recipe-declared step, a password or one-time-code field, exact origin and permitted path, a form action within `fill_origins`, valid TLS, verified focus before and after typing, and a pinned loader ID. Mismatch destroys the session.
- Field detection can use a declarative secret-free recipe with selectors, order and frame origin. Only owner-approved recipes are authoritative.
- Unsealing requires the stored success assertion, empty tainted fields in every frame and a full canary scan. Failure times out to `login_failed`.
- A fresh tab opens at the pinned post-login URL; the login tab closes; the success assertion is checked again. Cookies persist; the login page's heap, history and back-forward cache are not transferred.
- Mid-session password and code prompts are not filled.
- TOTP steps cannot be reused across sessions. Login attempts are rate-limited per credential; a wrong password is not retried.
- Login errors are closed enums, not page text: `field_not_found`, `bad_credentials`, `mfa_required`, `bot_challenge`, `origin_mismatch`, `tls_error`, `success_assertion_failed`, `timeout`.

## Observation and secret matching

Observations are constructed from per-frame accessibility data into an allowlisted schema: role, filtered name, selected states and permitted values. Broker-filled and password controls are permanently tainted, including after show-password toggles or input-type changes. The agent can read back ordinary text it typed into untainted controls.

The channel excludes HTML, attributes, hrefs, hidden inputs, console output, dialog text, validation messages and download names. Links use opaque snapshot-bound references. Titles receive the same filtering as page text. URLs expose origin and path; high-entropy path segments are masked and query values hidden unless their keys are explicitly allowed. Withheld values use a fixed marker without their original length. Screenshots are excluded.

The enumerated session-secret set comprises:

- Cookie values, including HttpOnly values read over CDP.
- `Set-Cookie`, `Authorization` and qualifying high-entropy request-header values.
- Local storage, session storage and IndexedDB values decomposed through JSON, JWT and URL-encoded structures.
- Query and fragment values observed in login redirects.

Length and entropy floors exclude ordinary low-information values. Secret collection and page snapshots must be consistent per observation; matching covers individual nodes and concatenated text. Matching covers qualifying substrings, URL encoding, hex, base64 at all three alignments and base64url. The set accumulates across cookie rotation. Live login codes leave the set after unsealing.

| Match | Agent-originated text | Page content |
|---|---|---|
| Vault secret above the floor | Kill session and suspend subject | Kill session only |
| Session secret | Mask; count toward circuit breaker | Mask only |

Page-originated matches cannot suspend a subject. Secret-match responses must not provide a graded redaction oracle.

## Actions and egress

Actions are `click`, `type`, `select`, `scroll`, `navigate` and `wait`. Text insertion and an allowlist of bare keys are permitted; modifier chords are not. References name their originating snapshot. Stale references return `stale_ref` with a fresh snapshot.

All Chromium egress must pass through the Driver-owned host-allowlisting proxy. QUIC and non-proxied UDP are disabled. WebSocket, WebTransport and WebRTC are blocked in the initial scope. A uid-keyed firewall must reinforce this where available.

Method/path policy requires paused-on-start CDP auto-attachment and interception on every target, redirect, popup, frame and worker before execution resumes. Closing a popup after it runs is insufficient. The CDP method allowlist is compile-time; every added method requires a conformance case.

Production navigation is HTTPS-only. `javascript:`, `data:`, `blob:`, `file:`, `view-source:` and internal browser URLs are denied. The session has one agent tab. Dialogs, permission prompts and external protocols are denied.

## Policy and lifetime

Policy is a small declarative schema: default deny, forbid overrides permit, and order-independent evaluation. Request resources include credential, session, canonical origin, method, path, resource type and top-level status. Stateful rate, concurrency and lifetime limits belong to broker enforcement.

| Mode | Meaning |
|---|---|
| `safe-methods` | Default; GET and HEAD only; no transport upgrades; does not guarantee no state change |
| `allowlisted-writes` | Additional named method/path permits |
| `open-with-denies` | Explicit broad-access opt-in with deny rules |

Effects are `permit`, `forbid` and `require_approval`. Without an implemented approval hook, rules that rely on approval to permit access must be rejected at load. Explanation output treats such rules as forbidden.

Deny packs are hash-pinned in the signed manifest and only narrow access. Categories include password/email/MFA changes, API tokens, OAuth grants, exports, recovery codes and known state-changing GETs. Agent-supplied `purpose` is length-capped and audited as tainted data, never used for authorisation.

Defaults are a 30-minute session lifetime, 5-minute idle timeout and one concurrent session per credential. Effective lifetime is the minimum of rule, credential and session limits, measured with a monotonic clock. A backwards wall-clock jump fails closed.

Revocation supports session, agent, credential and all-session scopes through an out-of-band control channel checked on each call. Revocation destroys the local browser and profile. Credential deletion, policy changes and broker restart end derived sessions. Agent-uid access to revoke or attend must not grant access to credentials; it can affect availability.

Repeated agent-originated denials, secret matches or hook failures feed a circuit breaker that can revoke sessions and suspend subjects. Page-originated requests do not count toward subject suspension.

## Audit requirements

The Keeper alone writes hash-chained JSONL with a forward-secure MAC. The initial MAC key is wrapped to the owner and not retained by the Keeper. The initial scope is tamper evidence against writers outside the Keeper uid; detecting Keeper-originated tail truncation requires independent signed checkpoints.

Fields include sequence, time, agent identity, peer uid/pid, session, credential, origin, method, canonical path, action kind, decision, rule ID, policy hash, achieved assurance profile and reason code. Logs exclude typed text except length, observation content, query strings, secrets and secret hashes.

Event hooks use a root-owned manifest-bound path, a separate unprivileged uid, clean environment and event JSON on stdin. Hook failures and timeouts are audited.

## Memory and interception requirements

Protected service and browser memory must be inaccessible to agent-reachable principals through debugger attachment, `task_for_pid`, `ptrace`, `/proc`, crash reports, dumps, swap and shared memory. Services require platform hardening without debugging entitlements. GPU acceleration is disabled. Browser passwords can remain in freed browser memory until process exit; browser identity isolation and session destruction are required controls, not browser-heap zeroisation claims.

The browser-to-site connection requires HTTPS and fatal TLS errors. The browser must use a controlled root store and ignore user trust anchors, environment/system proxy settings and user-level DNS overrides. The egress proxy tunnels CONNECT without terminating TLS or holding a CA key. The Driver binds its listener before starting the browser.

Owner input requires trusted enrolment/attendance commands. A separate agent uid prevents the agent from rewriting the owner's shell environment or substituting commands. Diagnostics must detect aliases, functions and earlier PATH entries shadowing protected commands. The protocol must never ask the agent to collect a password or one-time code. It cannot prevent a compromised agent from independently asking the owner for one.

## Verification requirements

The conformance kit is black-box: fixture server, vault seed format, protocol client and machine-readable report. It must run against independent implementations.

- Scan the full agent byte stream for fixture-minted vault/session canaries across concatenated messages and encodings, including error strings and handles.
- Exercise no-navigation SPA login, echo-on-error, password toggles, masked controls, cloned fields, title/ARIA/alt/URL leaks, frames, shadow DOM, canvas, dialogs, nested storage, split tokens, redirects, popups and back-forward cache.
- Test WebSocket, WebTransport and WebRTC egress, state-changing GETs, same-origin transformed cookies, re-authentication, decoy fields and low-entropy collisions.
- Exercise hostile action sequences, redaction-oracle attempts, modifier keys, prohibited schemes, cross-credential use, stale references and policy modification.
- Run memory/file/control-channel isolation probes as the agent uid with loaded canary secrets. Include debugger access, crash/dump/swap/shared-memory exposure, binary replacement, fake sockets, runtime privileges, command substitution and reused browser-uid residue.
- Fuzz HTML placement, protocol parsing and URL canonicalisation; run model-based random action sequences.
- Differential-test self-hosted Gitea, Keycloak, Nextcloud and WordPress behind a recording proxy that identifies minted secrets.
- Test record swaps, unlisted records, rollback, slot stripping and external-writer log truncation with published vectors.
- Verify that a stock agent recovers from each error using tool descriptions without requesting credentials.
- Measure at least 70% task completion against an unrestricted browser baseline on a fixed ten-site supported-login set. The legacy ten-read-task benchmark for Gitea, Nextcloud and WordPress is separate and unrun.
- Measure install-to-first-sealed-login time against a ten-minute target and validate platform isolation before claiming support.

These tests are required evidence. Their implementation and execution status is recorded in [TRADEOFFS.md](TRADEOFFS.md), not inferred from this specification.

## Diagrams

Diagrams are informative; text and normative tables govern. SVGs must use consistent trust-zone colours, distinct secret and agent-data paths, role shapes and legends, with meaning conveyed by more than colour and support for light/dark display.

Required diagram subjects are trust zones, lifecycle, wire sequence, reference process boundaries, sealed login, key hierarchy and request flow. A lifecycle diagram generated from the normative transition table must remain consistent with that table. Existing repository diagrams do not establish implementation or conformance status.
