# Stability & semver guarantees — presidio-hardened-ikigov-assess

For downstream integrators depending on this project.

## What is the public API

The public API is the **command-line surface**: the three console entry points
`iga` (`presidio_ikigov_assess.cli:app`), `iga-mcp`, and `iga-mcp-remote`, together
with their documented commands and flags (`assess`, `verify-certificate`,
`verify-evidence`, `verify-bundle`, `framework-gap`, `iso-gap`, …), plus
`presidio_ikigov_assess.__version__`. The emitted certificate/evidence record
formats are part of the contract and are covered under "Schema/wire stability"
below. Internal module functions are not public API and may change without notice.

## Versioning rules (semver, pre-1.0 profile)

- **Patch (0.x.Y):** bug fixes, security fixes, dependency floor bumps. No API
  change, no behaviour change except the fixed defect. Safe to auto-upgrade; this
  is the channel security releases ship on.
- **Minor (0.X.0):** additive API (new exports, new optional parameters with
  defaults, new optional extras). Existing code keeps working, including the
  documented public behaviour. Deprecations are announced here (docstring +
  CHANGELOG) at least one minor before any change.
- **Major (1.0.0+):** the only place deprecated surface may be removed.

**Pin guidance for integrators:** pin `presidio_ikigov_assess` to the current minor
in production and run the verification step (below) in your CI on every upgrade.

## Behavioural guarantees (stronger than API stability)

These are security invariants, not just interfaces; weakening any of them is
treated as a breaking change regardless of which version component moves.

- **Fail-closed on malformed input** — `sanitize` rejects invalid use-case text,
  ids, risk classes, gates, and dates rather than proceeding.
- **Recompute-then-verify** — a gate certificate never verifies unless its decision
  recomputes from the certificate alone and its signature checks against the trust
  store; a tampered certificate always fails closed.
- **Output escaping** — user input is HTML/Markdown-escaped before it reaches a
  report or the security log.
- **Dependency check on by default** — the startup CVE check runs unless explicitly
  suppressed with `--no-dep-check`.
- **Session rate limiting** — `IGA_MAX_ASSESSMENTS` is enforced across the one-shot
  CLI and the MCP server.

## Verifying an installation

After `pip install presidio-hardened-ikigov-assess`, run `iga --help` (exit code 0
confirms the CLI is installed). To confirm the verification guarantee end to end,
verify a genuine gate certificate with `iga verify-certificate <file>` (success) and
confirm a modified copy fails: a tampered certificate must return a non-zero exit
and refuse to verify.

## Schema/wire stability

The tool emits gate-certificate and evidence-bundle records as canonical JSON with a
SHA-256 content hash and a detached signature. Record fields are **additive-only**
within a minor line; changing the serialized output for an existing input is a
breaking change (it is a byte-stability contract, since the content hash and
signature depend on it). The classification logic tracks the referenced external
specifications (the EU AI Act and the ISO mappings); when those specs are revised,
the change is versioned and noted in the CHANGELOG.

## Security response

See [SECURITY.md](SECURITY.md). Security fixes ship as patch releases on the
latest minor; any minimum-safe dependency floors are bumped in the same release.
