# M0 spike results

Throwaway test of the riskiest assumption: can an allowlisted observation channel keep secrets off the agent socket while leaving pages usable? Run with `node run.js` in this folder; raw numbers are in `results.json`.

## Verdict so far

| Kill criterion | Result |
|---|---|
| Any canary reaches the tap on the hostile fixture | **Pass.** 0 of 22 canaries, in plain, URL, hex, base64 (all alignments), base64url, or 12-character chunks |
| Scripted agent completes at least 70% of ten read tasks on Gitea, Nextcloud and WordPress | **Not run.** Needs a container runtime and image downloads |
| Sandboxed headless Chrome under a macOS LaunchDaemon uid | **Not run.** Needs admin rights |

M0 cannot be called go or no-go until the second row is run.

## What was exercised (27 checks, all passing, in both runs)

- Sealed login: classic form, single-page login with no navigation, wrong password that the site echoes back, and a page that mirrors the password into its own text (fails closed with `secret_residue`).
- Agent locked out while sealed: observe and act both return `session_sealed`.
- Hostile page placing the session cookie in visible text, title, alt text, aria-label, link target, URL path, hidden input, input value, data attribute, iframe, closed shadow DOM, canvas, console, `alert()`, base64, hex, split across two elements, and as a 20-character chunk. Also a storage token nested in JSON.
- Policy: POST blocked in safe-methods; redirect hop to another host blocked; popup closed; `javascript:`, `file:`, `data:`, `view-source:` and off-list hosts refused; non-allowlisted key refused; stale ref refused.
- Tripwire: typing the vault password kills the session and suspends the subject; a wrong guess is ordinary typing.

## Findings

1. **Request interception does not see WebSockets.** With interception only, 13 WebSocket connections reached the attacker host. With the egress proxy, none did. The proxy is required, as the plan says.
2. **A new tab can make requests before it is closed.** First run: one fetch, one image and one beacon reached the attacker. Cause confirmed: the popup loaded before the close arrived. Fixed by pausing every new target at creation and closing it without resuming; those three hits are gone.
3. **The first secret floor was too eager.** "Display theme: darkmode-enabled" was withheld on 13 of 15 ordinary reads because it matched a cookie. A token-shape rule (digits with letters, mixed case, or high entropy; every HttpOnly cookie regardless) brought that to 0 of 15 with no leaks. This is tuned on one fixture and needs real-site data.
4. **Chromium did not expose a typed password through the accessibility tree** (5 of 5 logins, Chromium build 1234). The panel had marked this unverified.
5. **The "not claimed" boundaries behave as documented**: a rendered API token is readable, a same-origin script can re-encode a non-HttpOnly cookie past the matcher, and a GET link can change state.

## What this spike is not

- Single Node process, running as the same user as the caller. No isolation of any kind.
- Plain HTTP on localhost, so nothing here says anything about TLS or interception.
- The "agent socket" is an in-process function boundary with a tap, not a real socket.
- No TOTP, no `needs_human`, no lifetime or revoke, no audit chain.
- The broker's matcher and the harness scanner were written separately but by the same author.
