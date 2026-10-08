# Sealed-session protocol for agents: product spec, engineering spec, future plan

Working name: `blindfold`. Placeholder only: the product seat prefers an airlock/broker metaphor, and no npm, GitHub or trademark check has been done. Avoid "vault" in the name (Infisical, Notte, HashiCorp).

Status: revision 3, after two rounds of a ten-seat expert panel. The sign-off record is at the end.

## Context

Agents that log in to websites today either see the password or rely on a vendor flow whose guarantee stops at delivery. Several vendors now say the password stays out of LLM context (1Password, Notte, Anchor, Kernel). None that I found documents or tests that the logged-in session is withheld from the agent: that cookies, tokens, script evaluation, raw CDP and the DOM are out of its reach. After login the session is the credential.

Decisions already made by the owner: new open spec + reference implementation; the agent drives the session through a filtered channel; the adversary is a prompt-injected agent (honest but hijackable, limited to the tools it was given, which may include a same-user shell); local deployment; policy-based authorisation with no per-use prompt; UI-free (CLI, files and protocol only); diagrams in the protocol design and spec are visually designed.

## How the panel changed the first draft

| Topic | Draft | Now | Seats driving it |
|---|---|---|---|
| Core claim | Password never in context | The **session** is sealed, stated as a byte-level test over an enumerated secret set | Product, red team, browser |
| Seal exit | "Until navigation completes" | Explicit predicate, then a fresh tab; login page destroyed | Browser, web auth, systems |
| Login | Agent may help between steps | Fully broker-run; zero agent actions or observations | Red team, web auth |
| Observation | Emit, then redact | Built from an allowlist; tainted values never emitted; no screenshots in v0 | Browser, systems |
| Enforcement | Check `navigate` actions | Egress proxy for hosts, request interception for method and path, on every hop | Browser, red team, policy |
| Policy default | Allow, with path deny list | Default deny; new credentials are safe-methods-only | Policy, red team |
| Isolation | "Container or separate user" | Defined by property; dedicated service uids; containers are packaging | OS isolation |
| Process model | One broker | Keeper, Driver, Gateway, plus a per-session browser uid | Systems, crypto, OS |
| Stack | TypeScript + Playwright | Rust core with an allowlisted CDP client; adapter stays TypeScript | Systems, crypto, OS |
| Integrity | MAC under vault key | Owner-signed manifest with rollback epoch | Crypto, policy |
| Agent identity | Bearer token | Derived from the socket and peer uid; the agent holds nothing secret | Crypto, OS, policy, protocol |
| TTL and revoke | Future | **Local TTL and revoke in v0**; server-side tiers stay future | Policy, product, web auth |
| Build order | Filter built fourth | Spike on the filter first, with kill criteria | Systems |
| Protocol | One SPEC.md | Four documents, numbered requirements, public conformance kit | Protocol |

One change touches something the owner asked for: TTL and revoke were requested as a future item. Three seats argued that with no human in the loop, lifetime caps and a kill switch are the only compensating control, and that local revocation is nearly free because the session never leaves the sandbox. This plan moves the local part into v0 and leaves server-side revocation on the future list.

---

# Part 1: Product spec

## Problem and first user

> "My agent needs to be logged in. Today that means the password or the cookie sits somewhere any web page can instruct it to leak."

First user: a solo developer or small team running a local coding or operations agent (Claude Code, Cursor and similar) against sites with no usable API: admin consoles, vendor portals, billing dashboards. Not consumers, not enterprise fleets. v0 launches as a preview aimed at self-hosted admin consoles.

## The guarantee

> For a conformant Isolated deployment, no byte sequence on the agent socket contains a vaulted secret or a session secret, in plain, URL-encoded, base64 or hex form, under the published hostile-agent suite.

"Session secret" is an enumerated set, defined in the engineering spec: cookie values, credential-bearing header values, web-storage values and login-phase redirect parameters, above a length and entropy floor. Tokens outside that set are covered only by structural non-emission (the agent never receives HTML, attributes, hidden inputs or network data).

The suite ships as a runnable conformance kit. "Conformant" may only be claimed with the Isolated profile and a passing kit run.

## What is claimed and what is not

| Claimed | Explicitly not claimed |
|---|---|
| Vault secrets (password, TOTP seed, live login codes) never reach agent context | Protection from in-session account takeover (recovery email, new passkey, API token, OAuth grant) in any mode |
| Session secrets in the enumerated set are never emitted on the agent socket in the four listed encodings | Secrets a site renders as page text on a page the policy allows (API-key pages, recovery codes) |
| The protocol exposes no script-evaluation, storage or network method | Attacker script already on an allowed origin (reflected XSS, uploaded HTML or SVG) re-encoding or chunking non-HttpOnly session secrets into page text |
| | Exfiltration through site features (send mail, comment, share, export) |
| Browser egress is confined to allowed hosts, at every hop | State changes caused by GET requests (logout, confirm, unsubscribe links) |
| Destroying a session ends the agent's access to it | Sites with in-app code execution (cloud shells, CI, script editors) |
| | Confidentiality of page content the agent is allowed to read |
| | Availability: page content can cause a session to be killed |
| | Anything in the Development profile |

## Goals and non-goals for v0

Goals: password and TOTP login; sealed session; default-deny request policy; local TTL and revoke; audit trail; MCP adapter; public conformance kit; install to first sealed login in under ten minutes.

Non-goals: API keys in HTTP headers (use Infisical Agent Vault or OneCLI); CAPTCHA or bot-detection evasion (explicit no-stealth stance); remote or multi-tenant use; SSO; passkeys; screenshots; uploads and downloads; WebSocket-dependent sites; preventing misuse of actions the policy allows.

## Login support matrix

| Phase | Login classes |
|---|---|
| v0 | Single-page password; identifier-first password; TOTP |
| v0, owner attends on a TTY | SMS or email one-time code |
| v0.2 | New-device challenges and CAPTCHA via an owner-only headed bootstrap plus encrypted profile persistence |
| Deferred | SSO and "sign in with", passkeys, mid-session re-authentication, password rotation |

Honest limits: with a fresh browser profile per session, many real sites will raise a new-device challenge every time. v0 is a proof against fixtures, self-hosted apps and a short list of real sites documented as working. v0.2 is what makes it usable day to day. Single-page apps that keep their token only in `sessionStorage` arrive logged out after the tab swap unless the record opts in to carrying it over.

## Owner experience

```
sudo blindfold install              # one-time: service users, root-owned binaries, socket; ends with sudo -k
blindfold add github                # TTY prompts; runs a test login; proposes success check and deny pack
blindfold agent add claude-code [--dedicated-uid]   # prints the MCP config snippet or launch wrapper
blindfold policy edit | explain | test
blindfold attend [session]          # type an SMS/email code on the TTY; the Driver enters it
blindfold doctor [credential]       # isolation checks with exact remediation, or a redacted login trace
blindfold sessions ls | revoke <session|agent|credential|all>
blindfold audit tail [--denied]     # denied entries include a paste-ready narrow permit rule
```

- One `sudo` is unavoidable: a boundary set up without a privilege the agent lacks is not a boundary.
- If an isolation check fails, the broker refuses to start as Isolated and says exactly what to fix. Cached sudo and container-runtime access are the common causes; `--dedicated-uid` creates an agent user without either. Rootless runtimes and macOS Docker Desktop are assessed separately, not treated as automatic failures.
- New credentials default to safe-methods-only, 30-minute lifetime, 5-minute idle timeout, one concurrent session.
- `add` derives the success check and post-login URL from its own test login and asks the owner to confirm. It warns on passwords below the tripwire floor.
- Adding a credential never requires unlocking existing ones.
- Secrets are entered on a TTY only, never as arguments or piped input. Bulk import from 1Password or Bitwarden reads via file descriptor.

## Agent experience

- Observations are an accessibility snapshot with per-snapshot element refs (`e12`). Each action names the snapshot it was based on and returns the resulting change. A stale ref has its own error code and comes with a fresh snapshot.
- Withheld content is marked (`[withheld]`), with no length, so the agent does not conclude the page is broken.
- Every refusal carries `{code, retryable, retry_after, explanation, next_step, tell_user}`. Example: `needs_human` → "Ask the user to run `blindfold attend s_7`. Do not ask for the password or code; you cannot use it."
- After repeated identical refusals the broker answers `stop_retrying`.
- Tool descriptions include a normative "never request credentials from the user" sentence.

## Positioning

- **Password managers** (1Password, Bitwarden): complementary. They are future vault backends. Bitwarden Agent Access delivers plaintext to a process the agent launches; here the receiver is the Keeper. Re-verify against their current docs before publishing.
- **Cloud browsers** (Browserbase, Anchor, Kernel, Notte, Hyperbrowser): local, open and verifiable. They could ship a restricted mode quickly; the durable assets are the open conformance kit and local-first deployment.
- **Placeholder libraries** (browser-use, Skyvern, Stagehand): they substitute values inside the agent's own process. Here the session is sealed as well as the password, across a real privilege boundary.

## Success metrics

- Zero canary leaks in CI.
- Under ten minutes from install to first sealed login.
- At least 70% task completion on a fixed ten-site list versus unrestricted Playwright MCP, built only from sites v0 can log in to.
- Within 90 days of release: one external adapter and one independent red-team write-up.

## Adoption risks

- Bot detection against headless Chromium; mitigated by real Chrome in new-headless mode and the v0.2 bootstrap, not by evasion.
- Safe-methods-only breaking sites that read over POST or GraphQL; mitigated by paste-ready narrow permits and starter deny packs, so the narrow path is easier than the permissive one.
- No screenshots, uploads, downloads or WebSockets may block real tasks; the usefulness benchmark measures this in the spike, before v0 is frozen.

---

# Part 2: Engineering spec

## Specification set and conformance

"The protocol" is the agent-to-broker Core plus the conformance kit. The reference broker is one implementation.

| Document | Normative content |
|---|---|
| Core | Methods, session and subject state tables, security requirements. Speaks only of Agent, Broker, Browser and Site. |
| Bindings | JSON-RPC 2.0 over a Unix socket (newline-delimited, size-capped); MCP tool profile; how each binding authenticates the subject |
| Data model | Binding documents, policy, manifest, audit event schema, resource-type enum |
| Vault Backend Interface | `unwrap`, `totp(id, t)`, `release(id, origin)` |
| Reference architecture (informative annex) | Keeper/Driver/Gateway split, uid layout, key hierarchy |

- Core requirements describe observable effects only. Keeper, Driver, Gateway, epochs, RAM disks and Rust types belong to the annex.
- BCP 14 keywords. Every MUST has an ID mapped to at least one kit test.
- Conformance classes: Broker, Vault Backend, Agent Binding. Assurance profiles are a separate axis.
- The **subject** is a binding-authenticated principal, never client-asserted. The Unix binding maps socket path plus peer uid to an agent id, and states that agents sharing a uid are indistinguishable.
- `initialize` exchanges protocol version, capabilities, assurance profile and limits, with a stated negotiation rule. Unknown fields fail closed in policy and binding documents and are ignored in responses.
- Errors use stable `snake_case` codes and MUST NOT vary with secret-dependent state, with one carve-out: secret matches (the tripwire and the circuit breaker it feeds), whose only outcomes are `session_killed` and the subject state `suspended`.
- Denials are a coarse `denied_by_policy`; the rule id goes only to the audit log.
- URL canonicalisation follows the WHATWG URL Standard.
- Spec licensed under Community Specification License 1.0 or CC-BY 4.0 with a patent grant; code and kit Apache-2.0. Versions 0.x are explicitly unstable.

## Reference architecture

```
 root supervisor: spawns everything, hands out inherited socketpairs, owns the agent socket directory

   ┌─ uid keeper ───────────────────────────────────┐
   │ KEEPER: vault identity, TOTP, policy decisions, │──▶ hook (uid hook, clean env, fixed argv)
   │ audit. No browser or agent parsing code.        │
   └──────────▲──────────────────────▲───────────────┘
     decisions│            one secret│per fill
 agent ──────▶ GATEWAY ─────────────▶ DRIVER ── CDP pipe ──▶ CHROMIUM (uid per session,
 (user's uid)  agent socket, state    login, observation     RAM-backed profile, all egress
               table, schema checks.  building, secret       through the Driver's proxy)
               Never sees a secret.   matching, egress proxy.
               └────────── uid broker ──────────┘
```

- **Keeper** releases one secret per authorised fill. TOTP seeds never leave it. It is the only writer of the audit log.
- **Driver** is the only CDP client. It builds observations, runs all secret matching, and holds the session's vault secret in locked memory until the session ends, then zeroises it. It trusts the browser, not a second URL parser, for origins.
- **Gateway** owns the agent socket and the protocol state table. It validates that outbound observations fit the schema and receives no vault material or hashes of it. A CI architecture test ensures the socket writer accepts only the Driver-minted filtered type.
- **Chromium** runs under its own uid per session, so an escaped renderer cannot debug the Driver, read other sessions or reach the key.
- Internal channels are inherited socketpairs, never named sockets authenticated by uid. The agent socket is socket-activated in a root-owned directory.
- One Chromium process per session (roughly 200 to 300 MB each); default cap of four concurrent sessions.
- Sessions are not resumable. If the Driver or Gateway dies, the process group is killed and stale profiles are swept at startup.

## Assurance profiles

| Profile | Property | Status |
|---|---|---|
| Development | Same uid as the agent. Keeps secrets out of transcripts only. | Non-conformant; needs `--insecure-dev` on every start |
| Isolated | No principal the agent can act as can read broker memory or files, or alter its code, config or launcher | The only conformant profile; reference default |
| Attested (future) | Separate machine or microVM; key released on attestation | Future |

Reference mechanism for Isolated: dedicated service uids installed by `sudo blindfold install`. Linux uses systemd system and socket units with transient per-session browser users; macOS uses a root-owned LaunchDaemon with a pool of browser uids. Containers are packaging only, unless the agent itself is the one confined.

- Binaries and the hash-pinned Chromium are root-owned. The broker refuses to start if any ancestor of its executable, browser, vault, policy or hook is writable by a non-root uid.
- The Chromium sandbox MUST be on and is asserted at launch; on Linux this means the user-namespace sandbox, with an AppArmor profile shipped for distributions that restrict it. Fail closed.
- Hardening: core dumps off, non-dumpable, no new privileges, hidden `/proc` and no swap on Linux. macOS cannot disable swap and has no tmpfs, so profiles go on a RAM disk or a per-session encrypted volume and the spec says so.
- Enrolment and signing run under a separate enrolment uid with write-only access to a vault inbox and read-only access to the wrapped signing key, reached through a root-owned sudoers entry (`env_reset`, fixed command, password required, no credential caching).
- Keystroke capture is not treated as a threat: reading another process's keyboard input needs an OS permission the owner would have to grant. The one narrow input risk is a planted fake command (see Interception surfaces).
- `blindfold doctor` checks cached or passwordless sudo, container-runtime access, path ownership, sandbox status and core limits.
- The broker reports the profile it actually achieved in the handshake and in every audit record.

## Keys and data

- One hierarchy: the vault has an age identity. That identity is what gets wrapped, in independent slots: the Keeper's own key (0400, keeper uid) for unattended start; an Argon2id passphrase slot for admin, export and backup; optional TPM or Secure Enclave sealing.
- Records are age-encrypted to the vault's public key, so `add` needs no unlock.
- Origin bindings (`login_url`, `post_login_url`, `fill_origins`, `session_origins`, recipe, success assertion) live in a broker-side binding document that references a backend `secret_ref`, so the guarantee survives a 1Password or Bitwarden backend.
- An Ed25519 owner signature covers a manifest `{vault_id, epoch, secret_ref → record hash, binding hashes, policy hash, hook path}`. age records carry no sender authentication, so the Keeper refuses any record or binding absent from the manifest.
- The signing key is passphrase-wrapped and unreadable by the agent's uid. The Keeper pins the public key and refuses any epoch lower than the highest it has seen. The epoch high-water mark and audit MAC state are kept out of any backup or restore set.
- Stated plainly in the spec: in the Isolated profile, uid isolation is the control against the agent. At-rest encryption covers disk theft, backups and accidental commits.
- Session handles are 128-bit random and bound to the connection that created them.

## Session and subject states

One normative transition table (state, trigger, allowed methods, error code) with a single vocabulary. The lifecycle diagram is generated from it.

```
opening ─▶ sealed ─▶ active ─▶ closed | expired | revoked | killed
            ▲  │
            │  ├─▶ needs_human ─(owner attends; own timeout)─▶ back to sealed
            │  └─▶ login_failed | locked_out_risk
            └─ the unseal predicate is the only edge into active
```

- `session.open` returns at once with state `opening` and a `retry_after`.
- Subject states: `enabled`, `suspended`.

## Sealed login

- Runs entirely in the Driver. From `session.open` until `active`, the agent has no actions and no observations.
- While `sealed`, requests are governed by the binding (`fill_origins`, `session_origins`). The credential's policy mode applies only from `active`, so a safe-methods-only credential can still submit its login form.
- One fill sequence per session. The Driver types the username itself and checks the identifier shown before any secret.
- Fill conditions: recipe-declared step; `type=password` or one-time-code field; exact origin and path pattern; form action within `fill_origins`; valid TLS; focused node verified before and after typing; loader id pinned across typing. Any mismatch destroys the session.
- Heuristic field detection by default; an optional declarative, secret-free recipe (selectors, step order, frame origin) for sites that need it. An agent may propose a recipe; only the owner can approve it.
- **Unseal predicate**: the per-record success assertion holds; no tainted field in any frame is non-empty; a full canary scan passes. Otherwise time out to `login_failed`.
- **On success**: a new tab opens at the pinned `post_login_url`, then the login tab closes, and the success assertion is re-checked in the new tab. Cookies persist; the JS heap, history and back-forward cache do not.
- Mid-session password or code prompts are never filled (re-authentication is the site's own takeover defence).
- TOTP: never reuse a time step across sessions. Login attempts are rate-limited per credential, with no retry on a wrong password.
- Login results are a closed enum (`field_not_found`, `bad_credentials`, `mfa_required`, `bot_challenge`, `origin_mismatch`, `tls_error`, `success_assertion_failed`, `timeout`), never page text.

## Observation

- Built constructively from the accessibility tree per frame into an allowlisted schema: role, name, a small set of states, and value only for controls the Driver has not tainted.
- Never emitted: HTML, attributes, hrefs, hidden inputs, console output, dialog text, validation messages, download names. Links are opaque refs. The page title is filtered like any other text.
- Taint is permanent per node: anything the Driver typed into, or that was ever a password field. This covers show-password toggles and CSS-masked text inputs.
- URLs show origin and path, with high-entropy path segments masked and query values hidden unless the key is on a per-credential allowlist.
- No screenshots in v0.

### Session-secret set (the enumerated set in the guarantee)

- Cookie values, including HttpOnly, read over CDP.
- `Set-Cookie`, `Authorization` and other high-entropy request-header values.
- Local, session and IndexedDB storage values, decomposed through JSON, JWT and urlencoded structure.
- Query and fragment values seen on redirects during login.
- A minimum length and entropy floor applies, so values like `en` or `yes` are not treated as secrets.
- The set and the page are snapshotted atomically per observation, and matching runs over the concatenated snapshot text as well as per node.

### Match outcomes

| Match | In text the agent typed | In page content |
|---|---|---|
| Vault secret (above the floor) | Kill session, suspend subject | Kill session only |
| Session secret | Mask, count toward circuit breaker | Mask only |

- Killing on a vault-secret match removes the "type guesses and watch what gets masked" oracle.
- Only agent-originated matches can suspend, so page authors cannot lock an agent out, only end a session.
- Live login codes leave the match set once the session is unsealed.
- Matching covers substrings at or above the floor, base64 at all three alignments plus base64url, and stays cumulative across cookie rotation.

## Actions and egress

- Actions: `click`, `type` (text insertion plus a small set of bare keys; no modifier chords), `select`, `scroll`, `navigate`, `wait`.
- **Hosts**: all Chromium egress goes through a Driver-owned proxy that allowlists hosts. QUIC and non-proxied UDP are off. WebSocket, WebTransport and WebRTC are blocked by default. A uid-keyed firewall rule backs this where the platform offers one.
- **Method and path**: CDP auto-attach (paused on start) with request interception on every target, redirect hop, popup, frame and worker, enabled before any target resumes.
- HTTPS only. `javascript:`, `data:`, `blob:`, `file:`, `view-source:` and browser-internal URLs are blocked. Single tab. Dialogs, permission prompts and external protocols are auto-denied.
- The CDP client has a compile-time method allowlist. Adding a method requires a new conformance case.

## Policy

Small purpose-built declarative schema with Cedar-style semantics: default deny, forbid overrides permit, order-independent. No embedded policy language, because rate, concurrency and lifetime conditions are stateful.

- Resource: credential, session, and request tuple (canonical origin, method, path, spec-defined resource type, top-level or not).
- Effects: `permit`, `forbid`, `require_approval`. Until a step-up hook ships, a policy that relies on `require_approval` to permit anything is rejected at load, and `policy explain` shows it as forbid.
- Per-credential modes:
  - `safe-methods` (default): GET and HEAD only, no WebSocket or WebTransport upgrades (in v0 no mode can re-enable them). Defined normatively as "safe-method requests only; does not guarantee no state change".
  - `allowlisted-writes`: named method and path rules on top.
  - `open-with-denies`: explicit opt-in, warned.
- Deny packs: hash-pinned under the signed manifest, per-site rule sets by category (password, email, MFA, API tokens, OAuth authorise and grants, export, recovery codes, and known state-changing GETs such as logout and confirm links). Packs can only narrow access. A starter set ships with v0.
- `purpose` is agent-supplied: length-capped, logged as tainted, never used in a decision.

```toml
[agent.claude-code]
credentials = ["github"]

[credential.github]
mode = "safe-methods"
deny_packs = ["github-security"]
query_visible = ["q", "page"]
session_ttl = "30m"
idle_timeout = "5m"
max_concurrent = 1
on_needs_human = "attend"
```

## Lifetime and revocation (v0)

- Effective lifetime is the minimum of rule, credential and session limits. Durations use a monotonic clock; a backwards wall-clock jump fails closed.
- `revoke session | agent | credential | all` is owner-only and out of band, checked on every call.
- Revocation destroys the browser process and its profile. Removing a credential or changing policy revokes derived sessions. Broker restart ends all sessions.
- Circuit breaker: repeated denials of agent-originated actions, agent-originated matches, or hook failures revoke the session and can suspend the subject. Requests the page makes on its own never count.
- `revoke` and `attend` can be invoked from the agent's uid too; they affect availability only.

## Audit

- Hash-chained JSONL with a forward-secure MAC, written only by the Keeper. The initial MAC key is wrapped to the owner and not kept on the Keeper.
- Scope stated in the spec: in v0 the log is tamper-evident against writers outside the Keeper's uid. Detection of tail truncation by the Keeper itself arrives with signed checkpoints in v0.2.
- Fields: sequence, time, agent id, peer uid and pid, session, credential, origin, method, canonical path, action kind, decision, rule id, policy hash, assurance profile, reason code.
- Never logged: typed text (length only), observation content, query strings, secrets or hashes of secrets.
- `on_event` hook: root-owned path named in the signed manifest, run under its own unprivileged uid with a clean environment and event JSON on stdin. Failure or timeout is itself audited.

## Memory

Requirement (Isolated profile): no principal the agent can act as can read the memory of the Keeper, Driver, Gateway or browser, live or after the fact.

- **Live memory**: every broker process and the browser run under uids the agent cannot act as, so debugger attach, `task_for_pid`, `ptrace` and `/proc/<pid>/mem` are refused by the OS. Processes are also marked non-dumpable and built with the hardened runtime, with no debugging entitlement.
- **Memory written to disk**: core dumps and crash reports are disabled for all four. Secret pages are locked so they cannot be swapped. Linux runs the services with swap off; on macOS, where swap cannot be disabled per process, the install requires encrypted swap and refuses to report Isolated without it. Hibernation images are covered only by full-disk encryption, which `doctor` checks.
- **Lifetime**: the Keeper holds a secret only while releasing it. The Driver holds the session's vault secret in locked memory and zeroises it at session end. TOTP seeds never leave the Keeper.
- **Browser memory**: the typed password can linger in freed browser memory until the session's browser process exits. It sits under the per-session browser uid, the agent has no script or memory primitive into it, and the process and its profile are destroyed at session end.
- **Shared memory and GPU**: no shared-memory segments, sockets or files are created anywhere the agent's uid can open; GPU acceleration is off in the sandboxed browser.
- **Out of scope**: hardware side channels (Spectre-class, Rowhammer, cold boot) and an attacker with root.
- In the Development profile all of this memory is readable by the agent, which is the reason that profile is non-conformant.

## Interception surfaces

- **Browser to site**: HTTPS only, TLS errors fatal. The browser MUST use a bundled root store and ignore user-added trust anchors, system and environment proxy settings, and user-level DNS overrides, so a same-user agent cannot make itself a trusted middlebox.
- **Egress proxy**: tunnel-only (CONNECT pass-through). The broker never terminates TLS and holds no CA key. The listener is bound by the Driver before the browser starts, so the port cannot be squatted; anything else connecting to it gains only allowlisted-host reachability.
- **Internal hops** (Keeper, Driver, Gateway, CDP pipe): inherited descriptors under other uids; nothing to connect to. In the Development profile these are all reachable, which is why it is non-conformant.
- **Owner input** (`add`, `attend`, signing passphrase): keystrokes themselves are not capturable without an OS permission grant. The narrow remaining case is an agent sharing the owner's uid planting a fake `blindfold` or `sudo` in shell config. Low likelihood; closed by running the agent under its own uid (`--dedicated-uid`), and `doctor` flags any alias, function or earlier PATH entry that shadows either command.
- **The agent as messenger**: every human-facing message passes through the agent, so a hijacked agent can ask the owner to paste a password into chat. No protocol control stops this. The tool never requests secrets through the agent, and the docs say so prominently.

## Stack

- Rust for Keeper, Driver and Gateway: zeroisable secrets, locked memory, a small audited dependency set (`cargo-vet`, `cargo-deny`).
- Hand-rolled CDP client over a pipe. Chromium only, pinned by hash, new-headless mode.
- MCP adapter in TypeScript, on the untrusted side.
- Signed, reproducible releases.

## Designed diagrams

The spec's diagrams are designed artefacts, not ASCII. One visual system across all of them: a fixed colour per trust zone, one line style for the path a secret travels and another for agent-visible data, consistent shapes per role, a legend on every diagram, meaning never carried by colour alone, legible in light and dark. Sources are SVG kept beside the spec, and the spec is also published as a designed HTML page.

Diagrams are informative; text and tables govern. The lifecycle diagram is generated from the normative transition table so the two cannot drift.

| Diagram | Lives in | Shows |
|---|---|---|
| Trust zones, abstract | Core | Agent, Broker, Browser, Site, and where a secret can and cannot travel |
| Session lifecycle | Core | States and what the agent may call in each |
| Wire sequence | Core | `initialize`, open, poll, observe and act, a refusal, a revoke |
| Trust zones, reference | Annex | Keeper, Driver, Gateway, browser uid, supervisor, socketpairs |
| Sealed login sequence | Annex | Fill, unseal check and tab swap across Keeper, Driver, browser and site |
| Key hierarchy | Annex | Vault identity, slots, owner signing key, manifest and epoch |
| Request path | Annex | An action through policy, proxy, interception and observation building |

The claimed/not-claimed map stays a table. The ASCII sketches in this plan are placeholders for the diagrams above.

## Verification

- **Canary tap** on the agent socket: sliding-window scan across concatenated messages for vault canaries and every secret the fixture server mints, in all encodings, including error strings and handle ids.
- **Hostile fixture site**: SPA login with no navigation; secret echoed on error; show-password toggle; CSS-masked text input; cloned hidden field; tokens in title, aria-label, alt text, URL path, iframe, shadow DOM, canvas, `alert()`, nested JSON storage and a token split across spans; cookie-echo page; open redirect; popup; back-forward cache; WebSocket write, WebTransport and WebRTC attempts; state-changing GET (allowed and audited without a pack, forbidden with one); reflected-XSS page that re-encodes a cookie (documents the not-claimed boundary); change-password and re-authentication prompts; a same-origin decoy password field; page text that collides with low-entropy values.
- **Scripted hostile agent**, also run as a model-based property test over random action sequences: redaction oracle, modifier keys, `javascript:` navigation, redirect hop, popup escape, mint-and-read a token, policy edit, stale refs, cross-credential use.
- **Isolation probe** run as the agent's uid: memory of each broker process and the browser (debugger attach, `task_for_pid`, `ptrace`, `/proc/<pid>/mem`, forced core dump, crash report, swap and shared-memory inspection, with a canary secret loaded so a successful read is detectable), vault and key files, debug ports, binary and browser-cache swap, fake socket, container-runtime access, core dumps, PATH-hijacked `add`, residue left under a reused browser uid.
- **Fuzzing**: grammar-based HTML with canaries at random DOM locations; protocol parser; URL canonicalisation.
- **Differential**: self-hosted Gitea, Keycloak, Nextcloud and WordPress in CI (gating), behind a recording proxy so the tap knows the secrets those servers mint; real sites nightly (non-gating).
- **Usability**: a stock agent, given only the tool descriptions, recovers from each error code without asking for a secret.
- **Crypto negatives**: record swap, unlisted record, rollback, slot stripping, and log truncation by a writer outside the Keeper uid, with published test vectors.
- The kit is black-box: fixture server, vault seed format, protocol client, machine-readable report. It can be pointed at other implementations.

## Milestones

Relative size: S = 1, M = 3, L = 5.

| # | Milestone | Size | Exit condition |
|---|---|---|---|
| M0 | Spike, five-day timebox: raw CDP, hostile fixture, canary tap, egress proxy, and sandboxed headless Chrome under a macOS LaunchDaemon uid | S | **Kill** if any canary reaches the tap, or a scripted agent completes under 70% of ten read tasks on Gitea, Nextcloud and WordPress under safe-methods with masking on. Also record the false-trip rate of the secret floors and whether interception misses any transport. If the macOS check fails, macOS is Development-only in v0. |
| M1 | Spec v0-draft: requirement IDs, method list, version negotiation, transition table; diagram visual system plus trust zones, lifecycle and sealed login | S | Method list, negotiation rule and transition table written; every MUST has an ID mapped to a kit test |
| M2 | Fixture server and conformance harness, before the broker | M | Kit fails correctly against a deliberately leaky stub |
| M3 | Keeper, record and manifest formats, CLI | M | Crypto negative tests pass |
| M4 | Driver, sealed login, egress proxy, minimal Gateway (socket and state table), request policy | L | Fixture logins pass; seal tests pass |
| M5a | Observation filter and secret matching | L | Byte-leak and kill-on-match cases of the hostile-agent suite pass (this gates the guarantee) |
| M5b | TTL, revoke, circuit breaker, audit, hook | M | Policy and audit tests pass |
| M6 | Isolated-profile installer, `doctor`, crash handling | M | Isolation probe passes on each supported OS |
| M7 | MCP adapter, happy path, usefulness benchmark, remaining diagrams and designed spec page | M | Real agent completes fixture tasks |
| M8 | Fuzzing, differential tests, CI | M, ongoing | |

If the schedule slips, cut in this order: designed HTML page and later diagrams; bulk import, hardware slots, agent-proposed recipes; the forward-secure MAC (keep the hash chain); the Linux installer. Do not cut the macOS installer, deny packs or local revoke. If the M0 macOS check fails, the Linux installer takes the macOS installer's place on the do-not-cut list, so one conformant platform always exists.

New repository; location to be chosen when implementation starts.

---

# Part 3: Future plan

**v0.2, usability**
- Encrypted per-credential profile persistence, with its own derived key and a `state_max_age`, so revocation is a crypto-erase.
- Owner-only headed bootstrap for CAPTCHA and device challenges: the one sanctioned exception to UI-free.
- Signed audit checkpoints to a second sink.

**Revocation tiers beyond local destroy** (the owner's request)
- R1: recipe-driven logout.
- R2: the site's "sign out this device"; OIDC RP-initiated logout once SSO exists.
- R3: device-bound sessions (DBSC), where destroying the bound key stops the session's cookies being refreshed. Only on sites that support it; headless and Linux support is unverified.
- Prior art checked so far: Browserbase, Anchor, Hyperbrowser, Kernel and Notte offer deletion of persisted state, session timeouts or re-authentication; 1Password caps its approved-credential cache at nine hours (per its Claude security page). None was found offering owner-set TTL plus revoke as a protocol guarantee. The search was not exhaustive (AWS AgentCore unchecked), so verify before claiming novelty.

**Later**
- SSO with identity-provider origins as transit-only, and broker-handled consent.
- Passkeys through a broker-owned virtual authenticator.
- Out-of-band step-up approval (`require_approval` with a real hook) and opt-in mid-session re-authentication.
- WebSocket support under policy; screenshots with broker-painted masks; download and upload quarantine.
- Vault Backend Interface 1.0 with 1Password and Bitwarden adapters.
- Remote sandbox: Noise IK with the sandbox key bound into an attestation report; the vault identity never travels.
- Signed community registry for recipes and deny packs.
- WebDriver BiDi and Firefox driver as a second conformance target.
- Strict subresource egress; per-agent uids by default.
- Neutral governance once a second implementer exists; name and trademark search before publishing.

## Open decisions for the owner

1. Accept moving local TTL and revoke into v0 (recommended), or keep all of it on the future list.
2. Accept Rust for the core in place of TypeScript (recommended by three seats; slower to first demo).
3. Accept that the Isolated profile needs a one-time `sudo` install.
4. Final name.

## Panel record

| Seat | Round 1 | Round 2 | Round 3 |
|---|---|---|---|
| Browser internals | Happy with changes | Object (egress, matcher placement, secret set) | Sign off |
| Cryptography | Happy with changes | Sign off | n/a |
| OS isolation | Happy with changes | Object (browser uid, hook uid, enrolment uid) | Sign off |
| AI red team | Happy with changes | Object (secret set, breaker abuse, egress) | Object, one wording fix; applied after the round, not re-reviewed |
| Web authentication | Happy with changes | Sign off | n/a |
| Protocol design | Happy with changes | Object (subject, tripwire carve-out, state table) | Sign off |
| Developer experience | Happy with changes | Sign off | n/a |
| Product strategy | Happy with changes | Sign off | n/a |
| Policy and audit | Happy with changes | Object (read-only overclaim) | Sign off |
| Systems and testing | Happy with changes | Object (matcher placement, M0 criteria, macOS, M4 order) | Sign off |

The four round-2 sign-offs were conditional on text fixes, all applied. The red-team seat's round-3 objection was that two "Claimed" rows were false where an allowed origin already hosts attacker script; the rows were reworded and the case moved to "not claimed" as it asked, and it stated sign-off would follow. Round-3 implementer notes from all seats are folded into the text above.

Facts the panel marked unverified, to settle in M0: exactly which transports CDP request interception misses; whether Chromium masks password values in the accessibility tree; DBSC behaviour in headless and on Linux; whether sandboxed headless Chrome runs under a macOS LaunchDaemon uid.
