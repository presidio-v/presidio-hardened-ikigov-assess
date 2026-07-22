# Architecture

This document describes the high-level design of `presidio-hardened-ikigov-assess`: its
components, how data flows through them, and the trust boundaries the project is
built to enforce. For the security requirements and threat model that motivate
this design, see [SECURITY.md](SECURITY.md) and the assurance case in
[ASSURANCE.md](ASSURANCE.md).

## Overview

`presidio-hardened-ikigov-assess` is a command-line assessment tool (a Typer CLI
distributed on PyPI) that operationalises the Integrated KI-Governance (IKI-Gov)
Reference Model and the EU AI Act for AI use-case governance. It classifies an AI
use case, runs the governance gates, and emits **verifiable gate certificates and
evidence bundles** that a third party can verify *locally and offline* — without
re-running the tool and without access to the assessments database. It is local and
stateful (assessments and a security log are kept under `~/.iga/`) and makes no
outbound network calls in the core assessment path (an optional MCP endpoint is
opt-in). Its central design stance is **local, fail-closed verification: the signed
certificate is the proof**, with no policy-decision service in the trust path.

## Components

| Component | Responsibility |
|---|---|
| `cli` | Typer entrypoint and commands (`assess`, `verify-evidence`, `verify-certificate`, `verify-bundle`, `framework-gap`, `iso-gap`, …). |
| `classification`, `classify`, `euaiact`, `iso` | Risk classification of a use case against the EU AI Act and ISO mappings. |
| `checklist`, `gates`, `scoring` | Governance gate items and the gate-decision computation (OPEN / PARTIAL / BLOCKED). |
| `certificate`, `evidence`, `bundle`, `store`, `sovereignty` | Canonical-JSON + SHA-256 + HMAC detached-signature artifacts, the local assessment store, and offline verification. |
| `sanitize` | Input validation of all user-supplied strings and HTML/Markdown escaping of report output. |
| `security` | Startup dependency/CVE check (`pip-audit`), structured security-event logging, and session rate limiting. |
| `i18n`, `renderer`, `content` | Localised report rendering. |
| `wizard`, `workshop` | Guided assessment flows. |
| `remote`, `mcp_server` | Optional Model Context Protocol endpoint (opt-in; not used by the one-shot CLI path). |
| `trend` | Longitudinal assessment trends. |

## Data / processing flow

A single assessment moves through the components as a fail-closed pipeline:

1. **Input** — a use-case description, item ids, risk class, dates, or files.
2. **Validate** (`sanitize`) — every user string is validated and rejected if
   malformed; nothing is echoed into a report or log without escaping.
3. **Classify** (`classification` / `euaiact` / `iso`) — derive the risk class.
4. **Gate** (`checklist` / `gates` / `scoring`) — compute the gate decision.
5. **Emit** (`certificate` / `evidence` / `bundle`) — serialise to canonical bytes,
   compute a SHA-256 content hash, and attach a detached signature.
6. **Verify** (`verify-*`) — a verifier recomputes the gate decision from the
   certificate alone and checks the signature against a trust store.

The pipeline **fails closed**: any validation, classification, or verification
failure stops processing and does not emit or accept an artifact. The
validate-before-use ordering and the "recompute, then compare" verification
ordering are load-bearing and part of the contract.

## Trust boundaries

- **external input → CLI** — *input-validation boundary*. Use-case text, item ids,
  dates, and file inputs are untrusted; `sanitize.validate_*` rejects malformed
  values and `escape_for_report` / `escape_markdown` escape anything embedded in
  output.
- **tool → emitted certificate / evidence** — *integrity (egress) boundary*.
  Artifacts are canonical-JSON + SHA-256 + detached signature, so any later tamper
  fails verification.
- **untrusted certificate / evidence → verifier** — *input-validation boundary*.
  `verify-certificate` / `verify-evidence` / `verify-bundle` recompute the decision
  and check the signature against a trust store, fail-closed, with no engine in the
  trust path.
- **optional MCP endpoint (`remote` / `mcp_server`) → network** — *egress boundary*.
  Session rate limiting and security-event logging apply; the endpoint is opt-in and
  off in the default one-shot CLI path.
- **tool → local state (`~/.iga/` assessments + `security.log`)** — *filesystem
  egress boundary*. The tool writes only under the user's home directory.
