# Security Assurance Case

This document is the assurance case for `presidio-hardened-ikigov-assess`: an explicit argument
for why the project's security requirements are met. It has four parts, as
required by the OpenSSF Best Practices silver criterion `assurance_case`:

1. the threat model,
2. the trust boundaries,
3. the argument that secure design principles are applied, and
4. the argument that common implementation weaknesses are countered.

It is a summary that links to the authoritative detail in
[`SECURITY.md`](SECURITY.md) (controls, per-version threat tables, reporting) and
[`ARCHITECTURE.md`](ARCHITECTURE.md) (components, flow, boundaries) for
`presidio-v/presidio-hardened-ikigov-assess`.

## 1. Threat model

**Assets.** The integrity and authenticity of two things: (a) the **gate decision**
a use case receives (OPEN / PARTIAL / BLOCKED), which downstream governance relies
on; and (b) the **gate certificate / evidence bundle** the tool emits, which third
parties verify offline as proof of that decision. A forged or altered certificate
that still "verifies" would let a blocked use case pass governance.

| Threat | Control |
|---|---|
| A forged or tampered gate certificate / evidence bundle is presented as genuine. | Canonical-JSON + SHA-256 content hash + detached signature; a verifier recomputes the gate decision from the certificate alone and checks the signature against a trust store — any alteration fails verification (`certificate` / `evidence` / `bundle`). |
| Malicious or malformed assessment input (injection into reports/logs, invalid ids). | `sanitize.validate_*` validates every user string and rejects malformed values; `escape_for_report` / `escape_markdown` escape anything embedded in output — no raw input reaches a report or log. |
| A vulnerable dependency ships in the release. | Startup `pip-audit` CVE check (`security.dep_check_status`), Dependabot, and `pip-audit`/Scorecard in CI. |
| Abuse / runaway automation of the CLI or the optional MCP endpoint. | Persistent cross-process and in-memory session rate limiting (`IGA_MAX_ASSESSMENTS`); security-event logging to `~/.iga/security.log`. |
| Repudiation of an assessment or its provenance. | Signed certificates + the local assessment store give a verifiable, recomputable record. |

**Out of scope (documented, not assumed).** Custody of the signing key is outside
the tool (org key; see `allowed_signers`). The tool does not attest that a use
case's *real-world* claims are true — only that the signed decision recomputes and
the signature verifies. The optional MCP endpoint's network transport security is
the operator's responsibility when they enable it.

## 2. Trust boundaries

Aligned with [ARCHITECTURE.md](ARCHITECTURE.md#trust-boundaries):

- **external input → CLI** — input-validation boundary; `sanitize.validate_*` +
  output escaping.
- **tool → emitted certificate / evidence** — integrity (egress) boundary;
  canonical-JSON + SHA-256 + detached signature.
- **untrusted certificate / evidence → verifier** — input-validation boundary;
  recompute-then-compare + signature check against a trust store, fail-closed.
- **optional MCP endpoint → network** — egress boundary; rate limiting + security
  logging; opt-in, off by default.
- **tool → local state (`~/.iga/`)** — filesystem egress; writes confined to the
  user's home directory.

## 3. Secure design principles applied

**Fail-safe defaults / secure by default.** The assessment and verification
pipelines fail closed — any validation, classification, or signature failure stops
processing and does not emit or accept an artifact. The startup dependency check is
on by default (suppressible only with an explicit `--no-dep-check`).

**Complete mediation.** Every user input passes `sanitize` before use, and every
certificate is verified by recomputing the decision and checking the signature —
there is no path that accepts an artifact on trust. The validate-before-use and
recompute-before-accept orderings are part of the contract.

**Least privilege.** The tool holds no long-lived network credential and opens no
network connection in its core path; it writes only under `~/.iga/`. Signing-key
custody is delegated to the org key (`allowed_signers`), not held in the source tree.

**Defense in depth.** Independent controls cover distinct threats: input validation,
signed + recomputable certificates, startup CVE checking, session rate limiting, and
security-event logging, backed by CodeQL and Scorecard in CI.

**Economy of mechanism.** Cryptographic operations use vetted standard primitives
only — `hashlib` (SHA-256), `hmac`, Ed25519 via the `cryptography` library, and
canonical JSON — with no bespoke crypto.
Being pure Python, the code is memory-safe.

## 4. Common implementation weaknesses countered

| Weakness class | How it is countered |
|---|---|
| **Improper input validation / injection (CWE-20, CWE-74)** | `sanitize.validate_*` validates all user strings; `escape_for_report`/`escape_markdown` HTML/Markdown-escape output. The single `subprocess` use (`security.py`, the fixed-argv `pip-audit` call) is `shell=False` with a static argument list (annotated `# nosec B404`). Checked by CodeQL and Scorecard. |
| **Memory safety (CWE-119 family)** | N/A — pure Python, memory-safe; no manual allocation, no unsafe FFI. |
| **Cryptographic misuse (CWE-327, CWE-916)** | SHA-256 (`hashlib`), `hmac`, and Ed25519 (via the `cryptography` library) over canonical bytes for content hashing and detached signatures — no weak/broken algorithms and no bespoke crypto. The release/trust-store signing keys are supplied from outside the source tree. |
| **Hard-coded / exposed secrets (CWE-798, CWE-532)** | No secret is committed; signing-key custody is delegated to the org key (`allowed_signers`). Security-event logging escapes/structures entries and is scoped to `~/.iga/security.log`. Scorecard Token-Permissions + secret scanning guard the repo. |
| **Insecure network / SSRF (CWE-319, CWE-295)** | The core assessment/verification path opens no network connection. The optional MCP endpoint is opt-in; its transport is the operator's responsibility. No user-supplied URL fetch. |
| **Unsafe deserialization (CWE-502)** | Inputs are JSON/typed structures parsed with the standard library; no `pickle`/`eval` of untrusted data. |
| **Vulnerable dependencies (CWE-1104)** | Startup `pip-audit` CVE check, Dependabot, and `pip-audit`/Scorecard in CI. |

These classes are checked continuously by **CodeQL** and **OpenSSF Scorecard**
on every push and pull request.

## Conclusion

The threats above are each matched to a control; the controls sit at explicit
trust boundaries; the design follows fail-safe, least-privilege, complete-
mediation, defense-in-depth, and economy-of-mechanism principles; and the common
implementation weakness classes are countered by design and checked by automated
analysis. The project's stated security requirements are therefore met, subject
to the documented out-of-scope assumptions.
