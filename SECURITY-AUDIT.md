# Security Audit — presidio-hardened-ikigov-assess

**Audit date:** 2026-06-03
**Version audited:** 0.8.0 (`pyproject.toml`), `__version__ = "0.8.0"`
**Scope:** Full source tree under `src/presidio_ikigov_assess/`, tests, GitHub
security configuration, dependency posture, and the mandated Presidio security
extensions in `PRESIDIO-REQ.md` / `SECURITY.md`.
**Method:** Manual code review of all 15 modules, dynamic verification of
selected controls (rate-limit, env parsing, file permissions), `ruff`
lint/format, full `pytest` run (266 passed, 96% coverage), and a `pip-audit`
dependency scan.

---

## Executive summary

The tool is **defensively well-built**. Input is strictly allow-listed, all SQL
is parameterised, the one `subprocess` call is argument-list (no shell), there is
no `eval`/`exec`/`pickle`/`yaml.load`, no secrets are committed, and the secure-
logging discipline (structural metadata only) is enforced by a dedicated test.
No high-severity or critical vulnerabilities were found.

The findings below are concentrated in two areas: (1) a security control that is
**advertised but effectively inert for the CLI** (the per-session abuse guard),
and (2) **robustness / fail-open gaps** in the startup dependency check and an
environment-variable parse. None are remotely exploitable; the threat model is a
local, single-user CLI plus an optional stdio MCP server.

| ID | Severity | Title |
|----|----------|-------|
| M-1 | Medium | Per-session rate limit is inert for the CLI (resets every process) |
| M-2 | Medium | Known-vulnerable dependencies present in the runtime/build environment |
| L-1 | Low | Malformed `IGA_MAX_ASSESSMENTS` crashes the tool at import (availability) |
| L-2 | Low | Startup dependency check fails open on every non-"1" outcome |
| L-3 | Low | File-permission TOCTOU window on `security.log` and `assessments.db` |
| L-4 | Low | `report --output` follows symlinks / traverses / overwrites without guard |
| I-1 | Info | `escape_for_report` is the wrong sanitiser for Markdown and JSON (works only because input is allow-listed) |
| I-2 | Info | No integrity/authenticity protection on the local store or log |
| I-3 | Info | CodeQL workflow runs `continue-on-error: true` |
| I-4 | Info | `SECURITY.md` "Supported Versions" is stale (lists 0.1.x; project is 0.8.0) |
| I-5 | Info | CVE check is best-effort: silently no-ops when `pip-audit` is not installed |

---

## Medium findings

### M-1 — Per-session rate limit is inert for the CLI

**Files:** `security.py:22-23, 95-124`, `cli.py:203`
**Requirement:** PRESIDIO-REQ.md — *"Rate-limit/abuse guard on CLI invocations:
configurable max assessments per session (default: 100)."*

The abuse guard is an in-process module global:

```python
_MAX_ASSESSMENTS: int = int(os.environ.get("IGA_MAX_ASSESSMENTS", "100"))
_session_count: int = 0
```

Each `iga` CLI invocation is a **fresh OS process**, so `_session_count` is
re-initialised to `0` every time and `increment_and_check_session_count()` can
never reach the limit. The control therefore does nothing for the CLI — the very
surface the requirement names.

**Verified dynamically** (with `IGA_MAX_ASSESSMENTS=2`):

```
invocation 1: exit 0 (allowed)
invocation 2: exit 0 (allowed)
invocation 3: exit 0 (allowed)   ← should have been blocked
invocation 4: exit 0 (allowed)
```

The guard *is* meaningful for the long-running MCP server (`mcp_server._guard_session`),
where the process persists — that part is correct.

**Impact:** Low real-world risk (a local user can already run the binary in a
loop), but the documented control gives false assurance and the requirement is
not actually met for the CLI.

**Recommendation:** Either (a) document explicitly that the abuse guard applies
only to the persistent MCP session and adjust the requirement/SECURITY.md
wording, or (b) back the CLI counter with a persistent per-session store (e.g. a
rate file under `~/.iga/` keyed by a session/login id with a time window) if a
real CLI throttle is intended.

### M-2 — Known-vulnerable dependencies in the runtime/build environment

**Files:** `pyproject.toml:26-43`, environment
A `pip-audit` scan of the installed environment reported:

| Package | Version | Advisories |
|---------|---------|-----------|
| `idna` | 3.11 | CVE-2026-45409 |
| `urllib3` | 2.6.3 | PYSEC-2026-142, PYSEC-2026-141 |
| `setuptools` | 68.1.2 | CVE-2024-6345, PYSEC-2025-49 |
| `wheel` | 0.42.0 | CVE-2026-24049 |

These are **transitive / build-time** packages (pulled in via `pip-audit`/`mcp`/
`requests` and the build toolchain), not the project's three declared runtime
deps (`typer`, `rich`, `prompt_toolkit`), which were clean. Still, the package
does not constrain them, and the on-run check (see L-2) would *warn* but not
block. The build environment shipping a vulnerable `setuptools`/`wheel` is the
most relevant supply-chain concern.

**Recommendation:** Refresh the lockfile (`uv.lock`) and CI base image so
`setuptools`/`wheel`/`urllib3`/`idna` resolve to patched releases; let Dependabot
(already configured) keep them current. Consider treating a `pip-audit` finding
as a CI gate, not just an advisory.

---

## Low findings

### L-1 — Malformed `IGA_MAX_ASSESSMENTS` crashes the tool at import

**File:** `security.py:22`

```python
_MAX_ASSESSMENTS: int = int(os.environ.get("IGA_MAX_ASSESSMENTS", "100"))
```

This runs at **module import**, before any command logic or validation. A
non-integer value aborts the whole tool with an uncaught `ValueError`:

```
$ IGA_MAX_ASSESSMENTS=abc iga assess ...
ValueError: invalid literal for int() with base 10: 'abc'
```

A negative/zero value (e.g. `0`) would silently block every assessment instead.
A user-controlled env var should not be able to brick the binary or be
mis-parsed into a denial of service.

**Recommendation:** Parse defensively — catch `ValueError`, fall back to the
default with a stderr warning, and clamp to a sane minimum (e.g. `max(1, n)`).

### L-2 — Startup dependency check fails open on every non-"1" outcome

**File:** `security.py:32-62`
`run_dep_check` returns `True` ("passed") on `TimeoutExpired`, `FileNotFoundError`,
and **any** `pip-audit` exit code other than `1` (including internal/usage
errors). Only a clean exit-1 "vulnerabilities found" yields `False`. A
`pip-audit` that is broken, sabotaged, killed, or that errors out is therefore
indistinguishable from "no vulnerabilities," and the user sees the
green/quiet path.

This is **documented as intentional** ("advisory, fails open"), which is a
reasonable default for an offline-tolerant CLI — but it means the CVE check
provides weaker assurance than the SECURITY.md wording implies.

**Recommendation:** Distinguish "scan clean" from "scan inconclusive" in the
console output (e.g. a distinct dim "dependency check inconclusive" line on
timeout/error) so users aren't led to believe a check ran when it did not.

### L-3 — File-permission TOCTOU window on the log and database

**Files:** `security.py:87-90`, `store.py:60-66`
Both sensitive files are created and *then* hardened:

```python
with _SECURITY_LOG.open("a", ...) as fh:   # created under current umask
    fh.write(...)
_SECURITY_LOG.chmod(0o600)                 # tightened afterwards
```

```python
conn = sqlite3.connect(path)               # file created under current umask
...
path.chmod(0o600)
```

Between creation and `chmod`, the file exists with the process umask (commonly
`0o644`, world-readable). The exposure is **largely mitigated** because the
parent `~/.iga/` directory is created `0o700`, so other local users cannot
traverse into it — but on a shared system the window is still a defence-in-depth
gap (e.g. a pre-existing open dir handle, or a more permissive umask).

**Recommendation:** Create the files atomically with the target mode — e.g.
`os.open(path, O_CREAT|O_WRONLY|O_APPEND, 0o600)` for the log, and pre-create the
DB file `0o600` before `sqlite3.connect`. Belt-and-suspenders with the existing
`chmod`.

### L-4 — `report --output` writes through symlinks / traversal without guard

**Files:** `cli.py:456-457`, `sanitize.py:107-120`
`validate_output_path` deliberately imposes no location allow-list (only length
and null-byte checks), and `report` then does a plain
`Path(out_path).write_text(...)`. This follows symlinks, accepts absolute and
`../` paths, and silently overwrites any existing file the user can write to.

For a local CLI writing to a user-chosen path this is the documented, acceptable
behaviour. It is flagged at **Low** only because, combined with a symlink an
attacker pre-plants in a writable shared directory, `--output` could clobber a
file outside the intended target.

**Recommendation:** Acceptable as-is for the stated threat model; if hardening is
desired, refuse to follow a symlink at the destination and/or require `--force`
to overwrite an existing file.

---

## Informational

### I-1 — `escape_for_report` is the wrong sanitiser for its outputs
`sanitize.escape_for_report` (`html.escape(..., quote=True)`) is applied to the
use-case name before embedding it in **both** Markdown (`renderer.render_markdown`)
and JSON (`renderer.build_payload`).

- For **Markdown**, HTML-escaping does *not* neutralise Markdown/link/image
  injection (`[x](javascript:...)`, table pipes, etc.). The Markdown export is
  safe today **only because** `validate_use_case` already restricts the name to
  `^[a-zA-Z0-9_\-]{1,128}$` and all item text is static framework content. The
  real protection is the input allow-list, not the "output sanitisation."
- For **JSON**, `json.dumps` already escapes correctly; pre-applying
  `html.escape` just turns `&`/`<`/`>` into entity noise (again moot under the
  allow-list).

No vulnerability exists today, but the control is doing less than its docstring
and SECURITY.md claim. If a future version ever relaxes use-case validation or
adds genuine free-text fields, this becomes a real injection vector. Recommend
documenting that input allow-listing is the load-bearing control, and using a
Markdown-appropriate escaper (or rejecting Markdown metacharacters) if free text
is ever introduced.

### I-2 — No integrity/authenticity on the local store or log
`assessments.db` and `security.log` have confidentiality protection (0o600) but
no tamper-evidence; any process running as the user can edit assessment history
or the audit log. Acceptable for a local single-user tool, and the v0.9.0
roadmap (signed evidence packs / content hashes) is the right place to address
audit integrity. Noted so it is a conscious decision.

### I-3 — CodeQL workflow uses `continue-on-error: true`
`.github/workflows/codeql.yml` sets `continue-on-error: true` on the analyze job
(commented as needed for SARIF upload without GitHub Advanced Security). The
trade-off is that a genuinely failing analysis will not fail the build. Confirm
findings are still surfaced in the Security tab when GHAS is available.

### I-4 — `SECURITY.md` "Supported Versions" is stale
`SECURITY.md` lists only `0.1.x` as supported while the project is at `0.8.0`.
Cosmetic, but a vulnerability-disclosure policy that points at a version line
nobody is running undercuts the policy. Update the table.

### I-5 — CVE check is best-effort and optional
`pip-audit` lives in the `[audit]`/`[dev]` extras; a default `pip install` of the
package does **not** include it, so the advertised on-run CVE check silently
degrades to "dependency check unavailable." This is reasonable for a lean core,
but the SECURITY.md phrasing ("on each invocation the tool attempts a pip-audit
scan") slightly oversells it for the common install path.

---

## Controls verified as effective (positive findings)

- **Input validation / allow-listing** — every CLI parameter (use-case, risk
  class, gate, language, format, item IDs, dates, output path) is validated
  against strict allow-lists/regexes in `sanitize.py`, with length bounds and
  null-byte rejection. Item-ID lists are bounded to the 25 known IDs.
- **SQL injection** — none. Every query in `store.py` uses parameter binding
  (`?` placeholders); no string interpolation into SQL.
- **Command injection** — none. The single `subprocess.run` call
  (`security.py:45`) uses an argument list with `sys.executable -m pip_audit`,
  no `shell=True`, and a 45s timeout.
- **Dangerous primitives** — no `eval`, `exec`, `pickle`, `yaml.load`,
  `os.system`, or `__import__` anywhere in `src/`.
- **Secrets** — none committed; the secure-logging path records only structural
  metadata, enforced by `tests/test_security.py::test_log_security_event_no_secrets`.
- **MCP server robustness** — invalid tool input is surfaced as `ToolInputError`
  (a `ValueError` subclass) and the abuse guard is **non-fatal**, so a single bad
  or over-limit request cannot crash the long-running stdio server.
- **Directory hardening** — `~/.iga/` is created `0o700`; log and DB files are
  ultimately `0o600` (see L-3 for the creation-window caveat).
- **Supply-chain config** — `dependabot.yml` (pip + github-actions), CodeQL, and
  a multi-version pytest workflow are all present, satisfying the mandated
  GitHub security files.

## Verification evidence

```
ruff check .            → All checks passed!
ruff format --check .   → 28 files already formatted
pytest tests/           → 266 passed, 96.09% coverage
pip-audit               → 4 transitive/build packages flagged (see M-2)
```

---

*This audit covers the source at commit `06b255e` on branch
`claude/security-audit-2s64K`. It is a point-in-time review and does not
constitute a guarantee of absence of vulnerabilities.*
