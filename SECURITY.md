# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.8.x   | Yes       |
| < 0.8   | No        |

### Supported Python runtimes

| Python | Supported |
|--------|-----------|
| 3.10 – 3.12 | Yes |
| 3.9    | v0.8.x only — **dropped in v0.9.0** |

**Planned change (v0.9.0): minimum Python rises to 3.10+.** The security-patched
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

## Planned — External Evidence Verification (v0.13.0)

> **Not yet implemented.** The following describes the security model of the planned
> *external evidence-backed affirmation* feature (PRESIDIO-REQ.md, v0.13.0), recorded here
> so the design is reviewable ahead of implementation. It is not present in any released
> version and confers no current guarantee.

When shipped, ikigov will be able to attach signed evidence references (`EvidenceRef`) from
peer `presidio-hardened-*` controls to affirmed checklist items. The intended controls:

- **Fail-closed verification** — a missing, malformed, or invalid hash/signature never
  passes silently as verified; the item downgrades to self-affirmed, or is denied under
  `--require-evidence`.
- **Commitments only** — an `EvidenceRef` carries hashes and opaque ledger URIs, never PII
  or raw organisational data, consistent with the structural-only logging rule. All fields
  are length-bounded, scheme/format-validated, and escaped on export like every other input.
- **Local trust** — signer public keys are resolved from a local trust store
  (`~/.iga/trust/` or `IGA_TRUST_PATH`); there is no network key resolution by default.
  Verification reuses the v0.9.0 detached-signature primitive rather than a second mechanism.
- **Structured logging** — new `iga-evidence-attached` / `iga-evidence-verified` events
  record item IDs and the verification result only — no evidence content and no ledger-ref
  value.

## Software Development Lifecycle

This repository is developed under the Presidio hardened-family SDLC. The public report
— scope, standards mapping, threat-model gates, and supply-chain controls — is at
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
