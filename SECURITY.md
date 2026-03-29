# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities via email to the repository maintainer or via
[GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on this repository.

Include:
- A description of the vulnerability and its potential impact
- Steps to reproduce
- Any suggested remediation

You will receive an acknowledgement within 72 hours and a resolution plan within 14 days.

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
- **Dependency CVE check** — on each invocation the tool attempts a `pip-audit` scan of the
  installed environment. Suppress with `--no-dep-check` in offline or CI contexts.
- **Rate limiting** — the tool enforces a configurable maximum number of assessments per
  session (`IGA_MAX_ASSESSMENTS` env var, default 100).
- **Restricted file permissions** — `~/.iga/` is created with mode `700` and the security
  log file with mode `600`.
