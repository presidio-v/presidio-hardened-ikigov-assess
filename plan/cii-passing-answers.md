---
status: working sheet
owner: vstantch
target: OpenSSF Best Practices Badge — passing level
project_url: https://github.com/presidio-v/presidio-hardened-ikigov-assess
---

# CII Best Practices — passing-level answer sheet

Fill-in sheet for <https://www.bestpractices.dev> (passing level). This is a
skeleton: rows already backed by rendered project files are answered; rows that
depend on the specifics of this codebase are left as `FILL` markers for you to
complete after reading the repo. Do not paste a `FILL` marker into the BadgeApp —
resolve it first, honestly, or set the row to N/A with a real reason.

## Before you start

1. **Register the URL as exactly** `https://github.com/presidio-v/presidio-hardened-ikigov-assess`.
   Scorecard does a literal DB string match. A trailing slash, `www.`, or the
   package-index URL returns `NotFound` → score 0 despite a real badge.
2. **Log in with GitHub but decline the org grant.** BadgeApp requests `read:org`
   and no code path consumes it. Entry ownership is internal to its database.
3. **Confirm the community-health and process docs are on `main` first** —
   `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CHANGELOG.md`,
   `SEMVER.md`. Every URL cited below must resolve on `main` before you answer.
4. Record your badge id in `hardening.toml` (`[badge] bestpractices_id`) once the
   project is created; this sheet's silver counterpart references it as
   `0`.

Shorthand below: `REPO` = `https://github.com/presidio-v/presidio-hardened-ikigov-assess`.

---

## Basics — project website content

| Criterion | Status | Justification / URL |
|---|---|---|
| `description_good` | **Met** | `REPO#readme` — the README's opening lines state what the tool does (operationalises the IKI-Gov Reference Model as a CLI for assessing AI use cases) and the governance problem it addresses. |
| `interact` | **Met** | `REPO#readme` — README covers obtaining (presidio_ikigov_assess on the package index), feedback (issues), security reports (`SECURITY.md`), and contributing. |
| `contribution` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md` — documents the fork → branch → PR flow against `main`. |
| `contribution_requirements` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md#requirements-for-acceptable-contributions` — style config, test policy, security-change rules, dependency bar. |

## Basics — FLOSS license

| Criterion | Status | Justification / URL |
|---|---|---|
| `floss_license` | **Met** | `MIT`. |
| `floss_license_osi` | **Met** | `MIT` is OSI-approved (`License :: OSI Approved :: MIT License` in `pyproject.toml`). |
| `license_location` | **Met** | URL: `REPO/blob/main/LICENSE` |

## Basics — documentation

| Criterion | Status | Justification / URL |
|---|---|---|
| `documentation_basics` | **Met** | `REPO#readme` — README covers installation (`pip install …`), a Quick Start with worked commands, and per-command reference for every `iga` subcommand. (No separate `docs/` tree; the README is the reference.) |
| `documentation_interface` | **Met** | The CLI surface is documented in the README (every `iga` subcommand with examples) and the MCP tool surface in the "MCP Server" table; the public API contract and what counts as a breaking change is defined in `REPO/blob/main/SEMVER.md`. |

## Basics — other

| Criterion | Status | Justification / URL |
|---|---|---|
| `sites_https` | **Met** | GitHub and PyPI (the project's homepage/download) are HTTPS. The tool ships no project-run website; the optional MCP endpoint's transport is operator-configured. |
| `discussion` | **Met** | GitHub Issues: `REPO/issues` — searchable, URL-addressable, open, no proprietary client. |
| `english` | **Met** | All docs and issue handling in English. |
| `maintained` | **Met** | Actively maintained: latest release v0.23.0 (2026-07-05), a steady cadence (v0.20.0–v0.23.0 within recent weeks), and green CI. |

## Change control — repository

| Criterion | Status | Justification / URL |
|---|---|---|
| `repo_public` | **Met** | `REPO` |
| `repo_track` | **Met** | git. |
| `repo_interim` | **Met** | Feature and fix branches are pushed between releases; PR-based flow. |
| `repo_distributed` | **Met** | git. |

## Change control — versioning

| Criterion | Status | Justification / URL |
|---|---|---|
| `version_unique` | **Met** | Semver per release, tagged. |
| `version_semver` | **Met** | URL: `REPO/blob/main/SEMVER.md` — documents the semver profile. |
| `version_tags` | **Met** | Every release is a git tag, SSH-signed and GitHub-verified. |

## Change control — release notes

| Criterion | Status | Justification / URL |
|---|---|---|
| `release_notes` | **Met** | URL: `REPO/blob/main/CHANGELOG.md` — Keep a Changelog format, hand-written, not VCS log output. |
| `release_notes_vulns` | **N/A** | No release in the CHANGELOG range (v0.20.0+) fixed a publicly-known vulnerability in the project's own code. Dependency/toolchain CVEs (e.g. the `urllib3`/`setuptools` lines) are handled via `requires-python` and the CI toolchain and documented in `SECURITY.md`, not as project-code advisories. |

## Reporting — bug reports

| Criterion | Status | Justification / URL |
|---|---|---|
| `report_process` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md#reporting-bugs-and-requesting-features` |
| `report_tracker` | **Met** | GitHub Issues. |
| `report_responses` | **Met** | The public repo has received no external bug reports to date (`REPO/issues` is empty); the documented triage path (`CONTRIBUTING.md` + GitHub Issues, maintainer-owned) is in place. Met by the documented, staffed process rather than a backlog of past responses. |
| `enhancement_responses` | **Met** | No external enhancement requests have been filed yet; feature direction is maintainer-driven (release history v0.1.0→v0.23.0). The documented request path (GitHub Issues, `good first issue` label) is in place. |
| `report_archive` | **Met** | URL: `REPO/issues?q=is%3Aissue` — public and searchable. |

## Reporting — vulnerability reports

| Criterion | Status | Justification / URL |
|---|---|---|
| `vulnerability_report_process` | **Met** | URL: `REPO/blob/main/SECURITY.md#reporting-a-vulnerability` |
| `vulnerability_report_private` | **Met** | URL: `REPO/blob/main/SECURITY.md#reporting-a-vulnerability` — private GitHub Security Advisory via the Security tab; acknowledgement and patch targets stated. |
| `vulnerability_report_response` | **N/A** | No externally reported vulnerabilities in the last 6 months; zero GitHub Security Advisories filed. The response process (5-day acknowledgement, 30-day patch target) is documented in `SECURITY.md`. |

## Quality — build system

| Criterion | Status | Justification / URL |
|---|---|---|
| `build` | **Met** | PEP 517 build via `hatchling` (`[build-system]` in `pyproject.toml`): `python -m build` produces the sdist and wheel from source (as in `.github/workflows/publish.yml`). |
| `build_common_tools` | **Met** | Built with common, widely available FLOSS tools: CPython, `pip`, `build`, and `hatchling`. |
| `build_floss_tools` | **Met** | The entire toolchain is FLOSS. |

## Quality — automated test suite

| Criterion | Status | Justification / URL |
|---|---|---|
| `test` | **Met** | Assertion-based `pytest` suite under `tests/` (20 `test_*.py` modules, one per component: certificate, evidence, bundle, sovereignty, sanitize, security, gates, scoring, …), licensed with the project. How to run: `CONTRIBUTING.md#local-verification` and `.github/workflows/pytest.yml`. |
| `test_invocation` | **Met** | `pytest` (configured in `pyproject.toml` `[tool.pytest.ini_options]`, `testpaths = ["tests"]`). |
| `test_most` | **Met** | Enforced statement-coverage floor `--cov-fail-under=80` (`pyproject.toml` addopts and `.github/workflows/pytest.yml`); CI fails below 80%. |
| `test_continuous_integration` | **Met** | GitHub Actions on every push and PR to `main` (`.github/workflows/pytest.yml`), matrix Python 3.10 / 3.11 / 3.12 on `ubuntu-latest`. |

## Quality — new functionality testing

| Criterion | Status | Justification / URL |
|---|---|---|
| `test_policy` | **Met** | URL: `REPO/blob/main/CONTRIBUTING.md#tests` — written policy that functional changes ship with tests and fixes ship with regression tests. |
| `tests_are_added` | **Met** | Worked example: commit `d2d73d8` ("fix: read evidence-pack seal key off argv", v0.16.1) shipped the seal-key-off-argv fix together with its test update under `tests/` in the same commit. Feature commits (v0.20.0–v0.23.0) likewise land with their `test_*.py` modules. |
| `tests_documented_added` | **Met** | The policy is stated in the contribution instructions themselves (`CONTRIBUTING.md#tests`). |

## Quality — warning flags

| Criterion | Status | Justification / URL |
|---|---|---|
| `warnings` | **Met** | `ruff check .` and `ruff format --check .` run in CI (`.github/workflows/pytest.yml`) and reject any finding. |
| `warnings_fixed` | **Met** | CI fails on any finding; `main` is clean. |
| `warnings_strict` | **Met** | `ruff` lint select is `E, F, W, I, N, UP` (pycodestyle, pyflakes, warnings, import-sorting, pep8-naming, pyupgrade), beyond ruff's default `E,F`; ignores are limited to `E501` and `UP045` (`pyproject.toml` `[tool.ruff.lint]`). CI fails on any finding. (Security `S`/bandit rules are not enabled; SAST is covered by CodeQL below.) |

## Security — secure development knowledge

| Criterion | Status | Justification / URL |
|---|---|---|
| `know_secure_design` | **Met** | The maintainer applies documented secure-design principles — fail-safe/fail-closed defaults, complete mediation (validate-before-use, recompute-before-accept), least privilege (no long-lived network credential; writes confined to `~/.iga/`), and defence in depth — set out in `ASSURANCE.md#3-secure-design-principles-applied` and `ARCHITECTURE.md#trust-boundaries`. |
| `know_common_errors` | **Met** | The assurance case enumerates the defended weakness classes with named countermeasures: input validation/injection (CWE-20/74), crypto misuse (CWE-327/916), hard-coded secrets (CWE-798/532), SSRF/insecure network (CWE-319/295), unsafe deserialization (CWE-502), vulnerable dependencies (CWE-1104) — see `ASSURANCE.md#4-common-implementation-weaknesses-countered`. |

## Security — cryptographic practices

<!-- If this project performs NO cryptographic operations of its own, most of these
are N/A — say so explicitly per row rather than leaving them blank. If it does,
resolve each FILL against the actual primitives used. -->

| Criterion | Status | Justification / URL |
|---|---|---|
| `crypto_published` | **Met** | Published standard primitives only: SHA-256 (content hashing), HMAC-SHA256 and Ed25519 (RFC 8032) detached signatures over canonical JSON — used for gate certificates, evidence-refs, bundles, and workshop manifests (`certificate.py`, `evidence.py`, `bundle.py`, `sovereignty.py`). |
| `crypto_call` | **Met** | Primitives are called from vetted libraries — `hashlib` and `hmac` (stdlib) and `cryptography`'s Ed25519 (`[crypto]` extra); no primitive is re-implemented. |
| `crypto_floss` | **Met** | `hashlib`/`hmac` are the FLOSS CPython stdlib; `cryptography` is Apache-2.0/BSD FLOSS. |
| `crypto_keylength` | **Met** | SHA-256 (256-bit digest), HMAC-SHA256, and Ed25519 (128-bit security level) meet NIST 2030 minimums. |
| `crypto_working` | **Met** | No MD4/MD5/single-DES/RC4/Dual_EC_DRBG anywhere in the codebase (verified by source scan); only SHA-256/HMAC-SHA256/Ed25519. |
| `crypto_weaknesses` | **Met** | No SHA-1, no MD5, and no CBC-mode dependency; content hashing is SHA-256 and signatures are HMAC-SHA256 or Ed25519. |
| `crypto_pfs` | **N/A** | Implements no key-agreement/transport protocol of its own; the core path opens no network connection. |
| `crypto_password_storage` | **N/A** | Stores no external-user passwords and authenticates no interactive users. (The optional remote MCP endpoint stores bearer tokens only as SHA-256 hashes, never passwords.) |
| `crypto_random` | **Met** | Ed25519 keypair generation uses `cryptography`'s `Ed25519PrivateKey.generate()` (`sovereignty.py`), which draws from the OS CSPRNG; no hand-rolled or non-cryptographic RNG is used for key material. |

## Security — delivery

| Criterion | Status | Justification / URL |
|---|---|---|
| `delivery_mitm` | **Met** | Distributed over HTTPS via PyPI and GitHub. Publishing is GitHub Trusted Publishing (OIDC, no long-lived token) with PEP 740 provenance attestations (`.github/workflows/publish.yml`). |
| `delivery_unsigned` | **Met** | No hash is fetched over plain HTTP. Release tags are SSH-signed and GitHub-verified. |

## Security — known vulnerabilities

| Criterion | Status | Justification / URL |
|---|---|---|
| `vulnerabilities_fixed_60_days` | **Met** | No known unpatched medium+ vulnerabilities. Audit tooling: `pip-audit` (startup CVE check in `security.py`; `audit`/`dev` extras), Dependabot (`pip` + `github-actions`, weekly), and OpenSSF Scorecard. |
| `vulnerabilities_critical_fixed` | **Met** | Recent dependency alerts were cleared by lockfile refresh (commit `01a4eda`, "refresh uv.lock to clear 9 Dependabot security alerts"); none critical remain open. |

## Security — other

| Criterion | Status | Justification / URL |
|---|---|---|
| `no_leaked_credentials` | **Met** | History scan (68 commits) shows no `.env`, `.pem`, `.key`, `id_rsa`, or credential-shaped file ever added; signing-key custody is the org key held outside the tree (`allowed_signers`). |

## Analysis — static

| Criterion | Status | Justification / URL |
|---|---|---|
| `static_analysis` | **Met** | CodeQL (`.github/workflows/codeql.yml`), security query pack, results to GitHub code scanning. (A separate bandit/ruff-`S` pass is not currently wired into CI; CodeQL is the SAST.) |
| `static_analysis_common_vulnerabilities` | **Met** | CodeQL's security query suite targets the common vulnerability classes (injection, path traversal, unsafe deserialization); it runs on every push/PR and weekly. |
| `static_analysis_fixed` | **Met** | Findings are triaged and fixed before release. |
| `static_analysis_often` | **Met** | CodeQL runs on every push and PR to `main`, plus a weekly scheduled run. |

## Analysis — dynamic

| Criterion | Status | Justification / URL |
|---|---|---|
| `dynamic_analysis` | **Unmet** | No coverage-guided fuzz or sanitiser harness in this repo. The assertion-based `pytest` suite exercises the verify/recompute/fail-closed paths, but that is not dynamic analysis in the fuzzing sense. SUGGESTED at passing (not a blocker); planned action is a fuzz harness over the certificate/evidence verify entry points. |
| `dynamic_analysis_unsafe` | **N/A** | Pure Python, memory-safe; no memory-unsafe component to exercise. |
| `dynamic_analysis_enable_assertions` | **Met** | The `pytest` suite is assertion-based and assertions run enabled in CI (no `-O`); `verify-*` paths assert fail-closed behaviour. |
| `dynamic_analysis_fixed` | **Met** | No unfixed medium+ findings. |

---

## Notes

- Any passing criterion not listed here is answerable **Met** by an existing
  rendered artefact or **N/A** (library vs. website/app). Check
  `SECURITY.md` / `CONTRIBUTING.md` / `ci.yml` before writing anything new.
- Silver (score 7) is generally **not** honestly reachable while a project is
  single-maintainer: `access_continuity` is a silver MUST requiring the project to
  survive the loss of any one person within a week, and `bus_factor`,
  `governance`, and `roles_responsibilities` share that root cause. A second
  person with org access and release capability resolves all four and also moves
  Scorecard's Code-Review check off 0. See the silver sheet for how the reference
  project answered these via organisational continuity rather than a lone
  maintainer.
