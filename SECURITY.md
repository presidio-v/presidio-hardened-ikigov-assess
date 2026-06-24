# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.21.x  | Yes       |
| < 0.21  | No        |

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
  presented as "no vulnerabilities". Suppress with `--no-dep-check` in offline or CI contexts.
- **Rate limiting** — the tool enforces a configurable maximum number of assessments per
  session (`IGA_MAX_ASSESSMENTS` env var, default 100). The CLI uses a *persistent*
  per-session guard (`~/.iga/session.json`) so the limit holds across one-shot invocations;
  a session resets after an idle gap of `IGA_SESSION_IDLE_SECONDS` (default 3600s). The
  long-lived MCP server uses an in-process counter for the lifetime of the server.
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
- **Commitments only** — an `EvidenceRef` carries hashes and opaque ledger URIs, never PII
  or raw organisational data, consistent with the structural-only logging rule. All fields
  are length-bounded, scheme/format-validated, and escaped on export like every other input.
- **Local trust** — signer keys are resolved from a local trust-store file (`--trust`); no
  network key resolution. Signatures are over the canonical `{content_hash, signer}`
  message (byte-matched to the producer and locked by golden test vectors).
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


## Remote MCP Endpoint (v0.18.0 primitives, v0.19.0 enforcement)

The networked endpoint (`iga-mcp-remote`, `[mcp]` extra) wraps the FastMCP streamable-HTTP
app in a pure-ASGI guard (`OrgAuthMiddleware`) that runs **before** the MCP app:

- **Token authentication — enforced.** Every request must carry a `Bearer` token that
  resolves to an org via the token store (`{org: sha256(token)}`); `resolve_org` is
  timing-safe (`hmac.compare_digest`) and fail-closed. Missing/unknown tokens get **401**
  before any MCP processing. Tokens are stored only as sha256 hashes.
- **Per-org rate limiting — enforced.** A configurable per-org request cap
  (`IGA_MCP_MAX_PER_ORG`) returns **429** once exceeded; counts are per org.
- **Per-org store scoping** — the org's database path is bound on a per-task **context var**
  (concurrency-safe; it replaced the earlier process-global `IGA_DB_PATH` mutation). The org
  id is allow-list validated, so a tenant id cannot traverse out of its store directory.

**Isolation scope / known limitation.** The streamable-HTTP transport dispatches tool
execution to a separate **session** task, so the per-request context-var binding does *not*
reach the MCP tools. This is safe today because **all registered MCP tools are stateless**
(none read or write the store), so no per-tenant persisted data is exposed over the endpoint.
**Before exposing any store-backed tool remotely**, isolation must be re-established by binding
the org to the MCP *session* (not the request). TLS and bind address are deployment
configuration.

## Software Development Lifecycle

This repository is developed under the Presidio hardened-family SDLC. The public report
— scope, standards mapping, threat-model gates, and supply-chain controls — is at
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
