# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.8.x   | Yes       |
| < 0.8   | No        |

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

## Software Development Lifecycle

This repository is developed under the Presidio hardened-family SDLC. The public report
— scope, standards mapping, threat-model gates, and supply-chain controls — is at
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
