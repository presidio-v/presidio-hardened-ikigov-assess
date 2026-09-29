# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.27.x  | Yes       |
| 0.26.x  | Yes, but see the 0.27.0 audit note below |
| 0.25.x  | Yes, but see both notes below |
| 0.24.x  | Yes, but see both notes below |
| < 0.24  | No        |

> **0.26.x and earlier: fixed in 0.27.0 (2026-09 audit).** One genuine signed evidence-ref
> copied under several item ids verified for each of them, so `--require-evidence` could
> count every item from a single piece of evidence (since 0.13.0). A gate certificate's
> `issuer` was not bound to its signer (since 0.23.0). `verify-bundle` and
> `workshop verify` read manifest-named paths outside the bundle. Treat pre-0.27 outputs
> that show several `evidence-verified` items as needing re-verification with 0.27.0.

> **0.13.0 – 0.25.0: `--require-evidence` fails open (fixed in 0.26.0, S-1).** In those
> releases the flag only filtered `--evidence` inputs; bare `--affirm` and wizard answers
> still counted, and without `--evidence` the flag was not read at all. An assessment,
> report, gate check or signed export produced under the flag could show 100 % and every
> gate OPEN with no verified evidence and no marking. Upgrade, or treat any pre-0.26
> output produced under `--require-evidence` as self-attested unless its per-item
> `provenance` says `evidence-verified`.

> **0.23.x and earlier: the `[mcp]` extra is broken, not merely unsupported.** Those
> releases declare an unbounded `mcp>=1.2.0`, so a fresh install resolves an SDK major
> that removed the module `build_server()` imports, and `iga-mcp` fails at import. The
> core CLI is unaffected. Upgrade, or pin the SDK yourself.

### Supported Python runtimes

| Python | Supported |
|--------|-----------|
| 3.10 – 3.12 | Yes |
| 3.9    | **No** — dropped (enforced in v0.19.2; `requires-python >=3.10`) |

**Enforced (v0.19.2): `requires-python = ">=3.10"`; the CI matrix tests 3.10–3.12.** The security-patched
`urllib3` line (2.7.0+) no longer supports Python 3.9, so on 3.9 the dev/audit
dependency chain stays pinned to a vulnerable `urllib3` with no 3.9-compatible
fix. `urllib3` is *not* a runtime dependency of the core package (so end-user
installs on 3.9 are unaffected today), but to let the entire locked tree —
including CI/audit tooling — resolve to patched releases, v0.9.0 raises
`requires-python` to `>=3.10`. Python 3.9 is also upstream end-of-life as of
October 2025.

## Reporting a Vulnerability

Please report security vulnerabilities by opening a private GitHub Security Advisory
(via the "Security" tab → "Report a vulnerability") rather than a public issue.

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgement within 5 business days. We aim to release a patch
within 30 days of a confirmed vulnerability.

## Security Design

`presidio-hardened-ikigov-assess` implements the following security controls:

- **Input sanitisation** — all CLI parameters (use-case names, risk classes, gate identifiers)
  are validated against strict allow-lists before use. Overlong, malformed, or out-of-range
  inputs are rejected.
- **Output sanitisation** — use-case names and all user-supplied strings are HTML-escaped
  before inclusion in Markdown or JSON report output.
- **Secure logging** — the security event log (`~/.iga/security.log`) records only structural
  metadata (event type, risk class, gate status, language). No use-case content, organisational
  data, or secrets are written to log output.
- **Dependency CVE check** — when `pip-audit` is installed (the `audit` or `dev` extra),
  the tool runs it on each invocation against the installed environment. The check is
  advisory: a *clean*, *unavailable* (pip-audit not installed), and *inconclusive*
  (timeout/error) result are reported distinctly so a non-completing scan is never
  presented as "no vulnerabilities". Suppress with `--no-dep-check` or
  `IGA_NO_DEP_CHECK=1` in offline or CI contexts. Every `iga workshop` command skips it
  automatically, because workshops run on customer sites that are often offline.
- **Rate limiting** — the tool enforces a configurable maximum number of assessments per
  session (`IGA_MAX_ASSESSMENTS` env var, default 100). The CLI uses a *persistent*
  per-session guard (`~/.iga/session.json`) so the limit holds across one-shot invocations;
  a session resets after an idle gap of `IGA_SESSION_IDLE_SECONDS` (default 3600s). The
  long-lived stdio MCP server uses an in-process counter for the lifetime of the server.
  The remote HTTP endpoint does not use that counter: it is shared by every org, so one
  tenant could exhaust it for all. The per-org limit below bounds each org instead.
  The guard counts `iga assess` runs and the MCP assessment tools; read-only views
  (`gate`, `report`, `export`, the gap commands) are not counted.
  Malformed values for these env vars fall back to the documented defaults with a warning
  rather than aborting the tool.
- **Restricted file permissions** — `~/.iga/` is created with mode `700` and the security
  log file with mode `600`.

## External Evidence Verification (v0.13.0)

External evidence-backed affirmation (`iga assess --evidence` / `iga verify-evidence` /
the `iga_assess_with_evidence` MCP tool) lets ikigov attach signed evidence references
(`EvidenceRef`) from peer `presidio-hardened-*` controls to affirmed checklist items. The
controls in force:

- **Fail-closed verification** — a missing, malformed, or invalid signature never passes
  silently as verified; the item stays `evidence` (present, unproven) or, under
  `--require-evidence`, is not affirmed at all. `verify-evidence` exits non-zero on any
  failure.
- **`--require-evidence` is evidence-only (v0.26.0 S-1)** — under the flag an item counts
  as affirmed only if a reference in `--evidence` verifies against `--trust`; a bare
  `--affirm` or wizard answer is *asserted*: recorded, named on stderr, shown in every
  output, never scored. The counted set is a subset of the verified set by construction
  (`evidence.resolve_affirmations`, the single merge point used by every command and the
  MCP tool). Every output marks each item as evidenced / asserted / open, and the signed
  export manifest carries that marking inside the signed bytes.
- **Commitments only** — an `EvidenceRef` carries hashes and opaque ledger URIs, never PII
  or raw organisational data, consistent with the structural-only logging rule. All fields
  are length-bounded, scheme/format-validated, and escaped on export like every other input.
- **Local trust** — signer keys are resolved from a local trust-store file (`--trust`); no
  network key resolution. Signatures are over the canonical `{content_hash, signer}`
  message (byte-matched to the producer and locked by golden test vectors).
- **One ref, one item** — that message does not cover `item_id`, so a genuine signed ref
  copied under other item ids would still verify. A ref whose `(signer, content_hash)` is
  claimed for more than one item therefore verifies for **none** of them: it is reported
  as `reused` and, under `--require-evidence`, counted as asserted. The same holds for
  refs embedded in a gate certificate (`evidence-ref-failure`). Binding `item_id` into the
  signed message needs a family-wide wire-format change and is tracked separately.
- **Algorithm in the trust store (v0.14.0)** — a trust entry is either a bare HMAC-secret
  string (back-compat) or an object `{"alg": "hmac-sha256"|"ed25519",
  "key"|"public_key": "<hex>"}`. `verify_ref` dispatches accordingly. **Ed25519**
  (RFC 8032) public-key verification means a verifier holds only public keys — no shared
  secret with the producer. Ed25519 entries require the `[crypto]` extra; `load_trust_store`
  fails fast with a clear message if it is missing rather than failing verification silently.
- **Key rotation (v0.14.1)** — a signer's trust entry may list multiple keys (`public_key`/`key` as a list); `verify_ref` accepts a match against any, enabling rotation with an overlap window. Revocation is removing the key from the trust store.
- **Structured logging** — `iga-evidence-attached` / `iga-evidence-verified` events record
  reference/verification counts only — no evidence content and no ledger-ref value.

## Evidence-Pack Export (v0.15.0+)

`iga export` / `iga verify-bundle` produce and check a content-hashed, optionally
HMAC-sealed audit bundle. The controls in force:

- **Seal key off argv (v0.16.1)** — the manifest HMAC key is resolved from `--sign-key-file`
  (a file path) or `$IGA_SIGN_KEY`, so the secret stays out of shell history and the process
  list. Inline `--sign-key` remains for convenience but is documented as the least private
  option. The same source must be used for `export` and `verify-bundle`.
- **Fail-closed verification** — any missing member, artifact hash mismatch, or bad seal
  yields `ok=false` and a non-zero exit; hash and signature comparisons are constant-time.


## Workshop Evidence Sovereignty (v0.22.0)

`iga workshop keygen` / `iga workshop sign` / `iga workshop attest` let the
customer anchor workshop leave-behinds while presidio countersigns as assessor:

- **Customer-held owner key** — `workshop keygen` creates a raw Ed25519 private
  key file with mode `0600` and a `.pub` companion. Only the public key is shared
  into the engagement trust store; the owner private key never needs to leave the
  customer's machine.
- **Owner block inside signed content** — `workshop sign` embeds the signer,
  public key, and timestamp in the manifest before signing the canonical manifest
  bytes. Verification checks that an owner-role signature uses the same public key
  embedded in the manifest.
- **Separate assessor attestation** — `workshop attest` emits a
  `workshop-attestation@1` reading wrapped in an `evidence-ref@1` envelope. The
  signed attestation content carries `attests` and `parents[0]` equal to the
  canonical manifest hash, so the assessor statement is a provenance edge rather
  than an ambiguous second manifest signature.
- **Fail-closed verification** — `workshop verify` re-hashes all manifest-listed
  artifacts, validates the leave-behind schema/tool identifier, validates Ed25519
  public-key inputs, and verifies the optional attestation when
  `--require-attestation` is supplied.


## Remote MCP Endpoint (v0.18.0 primitives, v0.19.0 enforcement)

The networked endpoint (`iga-mcp-remote`, `[mcp]` extra) wraps the SDK's streamable-HTTP
app (`MCPServer.streamable_http_app()`, mcp 2.x) in a pure-ASGI guard
(`OrgAuthMiddleware`) that runs **before** the MCP app:

- **Token authentication — enforced.** Every request must carry a `Bearer` token that
  resolves to an org via the token store (`{org: sha256(token)}`); `resolve_org` is
  timing-safe (`hmac.compare_digest`) and fail-closed. Missing/unknown tokens get **401**
  before any MCP processing. Tokens are stored only as sha256 hashes.
- **Per-org rate limiting — enforced.** Each org may make `IGA_MCP_MAX_PER_ORG` requests
  (default 1000) per window of `IGA_MCP_WINDOW_SECONDS` (default 3600); beyond that it
  gets **429** with `Retry-After`, and its count resets when the window elapses. Counts are
  per org, so one tenant cannot exhaust another's budget.
- **Per-org store scoping** — the org's database path is bound on a per-task **context var**
  (concurrency-safe; it replaced the earlier process-global `IGA_DB_PATH` mutation). The org
  id is allow-list validated, so a tenant id cannot traverse out of its store directory.
- **Non-HTTP scopes refused (v0.25.0).** Only `lifespan` reaches the wrapped app
  unauthenticated, because startup and shutdown carry no request identity. WebSocket
  scopes are closed at handshake with **1008** — a valid bearer token does not change
  that, since this guard authenticates HTTP only — and any other scope type is dropped.
  Previously every non-HTTP scope was forwarded straight through, ahead of the token
  check, the rate limiter and the store binding. That was inert only because no WebSocket
  route is mounted, which is a property of what `streamable_http_app()` happens to build
  rather than a guarantee this guard could rely on; a route added upstream would have
  turned it into a silent auth bypass. Regression-tested in `tests/test_remote.py`.

**Isolation scope / known limitation.** The streamable-HTTP transport dispatches tool
execution to a separate **session** task, so the per-request context-var binding does *not*
reach the MCP tools. This is safe today because **all registered MCP tools are stateless**
(none read or write the store), so no per-tenant persisted data is exposed over the endpoint.
**Before exposing any store-backed tool remotely**, isolation must be re-established by binding
the org to the MCP *session* (not the request).

**Transport.** The server speaks plain HTTP and bearer tokens are its only credential, so it
must sit behind a TLS-terminating reverse proxy when reachable beyond the host. `serve()`
binds `127.0.0.1` by default and refuses any non-loopback `--host` unless `--behind-tls-proxy`
acknowledges that proxy. The SDK's DNS-rebinding guard accepts only loopback `Host` headers,
so the proxy must forward to `127.0.0.1` with a loopback `Host`; configurable allowed hosts
and native TLS are deferred until the endpoint is deployed.

## Software Development Lifecycle

This repository is developed under the Presidio hardened-family SDLC. The public report
— scope, standards mapping, threat-model gates, and supply-chain controls — is at
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
