---
status: working sheet
owner: vstantch
target: OpenSSF Best Practices Badge — SILVER level (on top of passing)
project_url: https://github.com/presidio-v/presidio-hardened-ikigov-assess
related:
  - cii-passing-answers.md
---

# CII Best Practices — SILVER answer sheet

Fill-in sheet for the **silver** tab at
<https://www.bestpractices.dev/en/projects/13748>. It covers
only the criteria silver *adds* on top of passing; passing answers carry over
unchanged (see `cii-passing-answers.md`).

This is a skeleton: rows backed by rendered project files are answered; rows that
depend on this codebase are left as `FILL` markers. Resolve every `FILL` honestly
before pasting — do not paste a marker into the BadgeApp.

Each row shows the **Status** to set in the dropdown and the **Justification** to
paste. `REPO` = `https://github.com/presidio-v/presidio-hardened-ikigov-assess`.

## Badge embed — no change needed

Silver uses the **same** embed code as passing; the badge image auto-renders the
current level:

```markdown
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13748/badge)](https://www.bestpractices.dev/projects/13748)
```

If the README badge already uses this URL, it upgrades to "silver" automatically
once the badge cache refreshes — no edit required.

## Backing docs

These rendered files back the silver answers; confirm each is on `main`:

- `GOVERNANCE.md` — governance model, roles, continuity
- `ARCHITECTURE.md` — components, core flow, trust boundaries
- `ASSURANCE.md` — consolidated security assurance case (`assurance_case`)
- `allowed_signers` — public release signing key for local tag verification
- `CONTRIBUTING.md` — DCO sign-off requirement
- `SECURITY.md` — reporter credit, how to obtain signing keys, assurance-case link
- `README.md` — 12-month roadmap + links to GOVERNANCE/ARCHITECTURE/ASSURANCE

---

## Governance & continuity

| Criterion | Status | Justification to paste |
|---|---|---|
| `dco` | **Met** | Every commit must carry a DCO `Signed-off-by` line (`git commit -s`); enforced in review. Documented at `REPO/blob/main/CONTRIBUTING.md#licensing-and-developer-certificate-of-origin-dco`. Inbound = outbound `MIT`. |
| `code_of_conduct` | **Met** | Contributor Covenant at `REPO/blob/main/CODE_OF_CONDUCT.md` (standard location). |
| `governance` | **Met** | Governance model documented at `REPO/blob/main/GOVERNANCE.md` — maintainer-led single-steward (PRESIDIO Group), rough-consensus decisions, a security-sensitive-change rule, SEMVER-governed compatibility changes, and escalation to the steward org. |
| `roles_responsibilities` | **Met** | Key roles (steward org, maintainer, security contact, release manager, contributor) documented at `REPO/blob/main/GOVERNANCE.md#roles-and-responsibilities`. |
| `access_continuity` | **Met** | Continuity is a property of the steward organisation, not one person: the repo is owned by the `presidio-v` GitHub org (not a personal account); publishing is Trusted Publishing/OIDC bound to the org repo + a gated `release` environment (no personal token); the release signing key is held in the org password manager and recoverable; the release process is fully documented. URL: `REPO/blob/main/GOVERNANCE.md#project-continuity`. |
| `bus_factor` (SHOULD) | **Met** | PRESIDIO Group is a staffed steward org with more than one person able to assume the maintainer, security-contact, and release-manager roles; release credentials are org-held (OIDC Trusted Publishing + org-vaulted signing key), not tied to one machine. See `REPO/blob/main/GOVERNANCE.md#project-continuity`. |

## Documentation

| Criterion | Status | Justification to paste |
|---|---|---|
| `documentation_roadmap` | **Met** | `README.md` "Roadmap" now includes a **"Planned (next 12 months)"** section describing intended direction (OpenSSF hardening in progress, framework-gap coverage, reproducible builds under evaluation) alongside the shipped-version history. |
| `documentation_architecture` | **Met** | `REPO/blob/main/ARCHITECTURE.md` — components, core-flow pipeline, and trust boundaries; linked from the README. |
| `documentation_security` | **Met** | `REPO/blob/main/SECURITY.md` documents the built-in security controls and per-version threat notes; `REPO/blob/main/ASSURANCE.md` is the consolidated threat model + design rationale; `ARCHITECTURE.md#trust-boundaries` states the trust boundaries. |
| `documentation_quick_start` | **Met** | README "Quick Start" section with copy-paste `iga` command examples (assess, gate, report, iso-gap, certify, verify). |
| `documentation_current` | **Met** | Docs track the current release line; per-version roadmap and hand-written `CHANGELOG.md` are kept in sync with each release. |
| `documentation_achievements` | **Met** | The OpenSSF Best Practices badge is displayed and hyperlinked on the README front page. |

## Change control & reporting

| Criterion | Status | Justification to paste |
|---|---|---|
| `contribution_requirements` | **Met** | `REPO/blob/main/CONTRIBUTING.md#requirements-for-acceptable-contributions` — style, tests, security-change rules, dependency bar. |
| `report_tracker` | **Met** | GitHub Issues: `REPO/issues`. |
| `maintenance_or_update` | **Met** | `REPO/blob/main/SECURITY.md#supported-versions` states which versions are supported and for how long; `REPO/blob/main/SEMVER.md` documents the upgrade path and what counts as a breaking change. |
| `vulnerability_report_credit` | **Met** | `REPO/blob/main/SECURITY.md#reporting-a-vulnerability` — reporters are credited by name in the published advisory and the CHANGELOG entry unless they request anonymity. |
| `vulnerability_response_process` | **Met** | `REPO/blob/main/SECURITY.md#reporting-a-vulnerability` — private GitHub Security Advisory intake, acknowledgement and patch targets stated. |

## Quality & testing

| Criterion | Status | Justification to paste |
|---|---|---|
| `tests_documented_added` | **Met** | `REPO/blob/main/CONTRIBUTING.md#tests` states the policy that changes adding/modifying functionality ship with tests in the same PR. |
| `test_policy_mandated` | **Met** | Formal written policy at `REPO/blob/main/CONTRIBUTING.md#tests`: functionality changes ship with tests; bug fixes include a regression test. Enforced in review and by the coverage gate. |
| `automated_integration_testing` | **Met** | `REPO/blob/main/.github/workflows/pytest.yml` runs the full `pytest` suite on every push and pull request across a Python 3.10 / 3.11 / 3.12 matrix on `ubuntu-latest`. |
| `regression_tests_added50` | **Met** | Policy requires a regression test with every bug fix (`CONTRIBUTING.md#tests`), enforced in review and by the coverage gate. Worked example: `d2d73d8` (seal-key-off-argv fix, v0.16.1) shipped with its test. Bug-fix volume is low and each carried a test, so the >50% bar holds. |
| `test_statement_coverage80` | **Met** | Enforced statement-coverage floor `--cov-fail-under=80` in `pyproject.toml` addopts and `.github/workflows/pytest.yml`; CI fails below 80%. |
| `warnings_strict` | **Met** | `ruff` lint select `E, F, W, I, N, UP` (beyond the default `E,F`), ignores limited to `E501`/`UP045`; CI runs `ruff check .` + `ruff format --check .` and fails on any finding (`.github/workflows/pytest.yml`). |
| `coding_standards` | **Met** | `REPO/blob/main/CONTRIBUTING.md#style` mandates **ruff** (lint + format), configured in `pyproject.toml` `[tool.ruff]` / `[tool.ruff.lint]`. |
| `coding_standards_enforced` | **Met** | The style/lint check runs in CI on every PR (FLOSS enforcement). |
| `installation_common` | **Met** | `pip install presidio-hardened-ikigov-assess` from PyPI (standard package-index install; optional extras `[audit]` / `[crypto]` / `[mcp]`). |
| `installation_development_quick` | **Met** | `REPO/blob/main/CONTRIBUTING.md#local-verification` — documents the one setup path that installs everything needed to build and test. |
| `build_repeatable` (SHOULD) | **Met** | Built via `python -m build` (hatchling) on GitHub-hosted runners with SHA-pinned Actions against a pinned dependency graph (`uv.lock`); deterministic from pinned sources. Not claimed bit-for-bit hermetic. |
| `build_standard_variables` | **N/A** | Pure-Python package; no compiler/linker, so `CC`/`CFLAGS`/`LDFLAGS` do not apply. |
| `build_preserve_debug` | **N/A** | No compiled artefacts; there is no separable debug info to preserve. |
| `build_non_recursive` | **N/A** | No recursive make / subdirectory build; the build is a single PEP 517 invocation. |
| `installation_standard_variables` | **N/A** | Installed via `pip`/`uv` from PyPI; `DESTDIR`-style install conventions do not apply. |

## Dependencies & components

| Criterion | Status | Justification to paste |
|---|---|---|
| `external_dependencies` | **Met** | Runtime and optional dependencies are declared machine-readably in `pyproject.toml`; the dev/CI graph is pinned in `uv.lock`; a CycloneDX SBOM (`sbom.cdx.json`) is generated per release in `.github/workflows/publish.yml`. |
| `updateable_reused_components` | **Met** | All reused components are standard package-index packages installed via the package manager (no vendored copies); Dependabot tracks updates. |
| `interfaces_current` | **Met** | Dependencies are kept current (Dependabot + dependency floors), the public API is tracked in `SEMVER.md`, and the code does not rely on deprecated FLOSS functions where alternatives exist. |

## Security

| Criterion | Status | Justification to paste |
|---|---|---|
| `assurance_case` | **Met** (URL required) | URL: `REPO/blob/main/ASSURANCE.md`. Fully populated (no open FILL markers) with all four required parts — threat model, trust boundaries, secure-design-principles argument, and common-implementation-weakness argument. |
| `implement_secure_design` | **Met** | Fail-safe defaults (validation/classification/signature failure stops processing; startup CVE check on by default); complete mediation (every input through `sanitize`, every certificate recomputed-then-verified); least privilege (no long-lived network credential, writes only under `~/.iga/`); defence in depth (input validation + signed/recomputable certificates + CVE check + rate limiting + event logging); economy of mechanism (vetted stdlib crypto, no bespoke primitives). See `REPO/blob/main/ARCHITECTURE.md` and `ASSURANCE.md#3-secure-design-principles-applied`. |
| `input_validation` | **Met** | Data crossing the untrusted-input boundary is validated before use: `sanitize.validate_*` checks every CLI string (use-case names, risk classes, gate ids) against strict allow-lists/bounds and rejects malformed values; `escape_for_report`/`escape_markdown` escape anything embedded in report output. Evidence/certificate inputs are schema/format-validated and verified fail-closed. See `ARCHITECTURE.md#trust-boundaries`. |
| `hardening` | **Met** | SHA-pinned GitHub Actions in the release/Scorecard workflows; `persist-credentials: false` on checkout; least-privilege workflow `permissions`; Trusted Publishing (no stored PyPI token) behind a gated `release` environment; `~/.iga/` created `0700` and the security log `0600`; structural-only logging (no content/secrets); constant-time comparisons (`hmac.compare_digest`) for token/seal checks. |
| `crypto_weaknesses` | **Met** | Security functions use SHA-256, HMAC-SHA256, and Ed25519 only; no MD5/SHA-1/DES/RC4 for any security purpose (source-scan confirmed). |
| `crypto_algorithm_agility` (SHOULD) | **Met** | The signature format carries an explicit algorithm selector — trust entries declare `{"alg": "hmac-sha256"|"ed25519", …}` and `verify_ref`/certify dispatch on it — so an algorithm can be added or retired as a format-level change; keys rotate via list-valued trust entries. |
| `crypto_credential_agility` | **Met** | No key or secret is hard-coded. All key material is supplied from outside the source tree — trust-store files (`--trust`), `--sign-key-file` / `$IGA_SIGN_KEY`, and customer-generated keys (`workshop keygen`) — and rotates without recompilation (trust entries accept key lists for overlap-window rotation). |
| `crypto_used_network` | **N/A** | The project's own code originates no network communication in the core path. Where network access occurs it is external to the tool: `pip-audit` (optional dependency) fetches advisories over HTTPS, and the optional `iga-mcp-remote` endpoint's transport TLS is operator-configured (`SECURITY.md`). |
| `crypto_tls12` | **N/A** | The tool implements no TLS client of its own; see `crypto_used_network`. |
| `crypto_certificate_verification` | **N/A** | No TLS client originates in the project's code; certificate verification is the concern of `pip`/`pip-audit` and the operator-configured MCP transport. |
| `crypto_verification_private` | **N/A** | The tool transmits no private data over a network of its own; the core path is offline and local. |
| `signed_releases` | **Met** | Release tags are SSH-signed with the org ed25519 key and show **Verified** on GitHub (verified v0.21.0–v0.23.0; GitHub API `verification.verified = true` for v0.23.0); the public key for local `git tag -v` verification is in `REPO/blob/main/allowed_signers`. The build additionally emits PEP 740 / build-provenance attestations and a CycloneDX SBOM per release (`.github/workflows/publish.yml`). |
| `version_tags_signed` | **Met** | Every release is a git tag, SSH-signed with the org key and shown as Verified on GitHub. |
| `sites_password_security` | **N/A** | The project stores no user passwords and runs no user-authenticating website. (The optional remote MCP endpoint stores bearer tokens only as SHA-256 hashes.) |

## Analysis & monitoring

| Criterion | Status | Justification to paste |
|---|---|---|
| `static_analysis_common_vulnerabilities` | **Met** | CodeQL (`REPO/blob/main/.github/workflows/codeql.yml`, security query suite) and OpenSSF Scorecard run on every push/PR (Scorecard also weekly). A separate bandit/ruff-`S` pass is not currently wired into CI; CodeQL is the SAST. |
| `dynamic_analysis_unsafe` | **N/A** | Pure Python, memory-safe; no memory-unsafe component and no fuzzing currently runs. |
| `dependency_monitoring` | **Met** | Dependabot + dependency audit in CI + OpenSSF Scorecard continuously check external dependencies for known vulnerabilities. |

## Accessibility & internationalization

| Criterion | Status | Justification to paste |
|---|---|---|
| `accessibility_best_practices` | **N/A** | Developer CLI/library with no graphical or end-user web UI. |
| `internationalization` | **Met** | The tool is internationalized: all runtime output flows through an `i18n` layer (`t()`), with full English and German locales selectable via `--lang en|de` (localisation sweep completed in v0.21.0). |

---

## Notes

- Any silver criterion **not** listed here carries over unchanged from the passing
  sheet — leave those answers as they already are.
- If BadgeApp shows a silver-only criterion not covered above, it is almost
  certainly answerable **N/A** (library vs. website/app) or **Met** by an existing
  artefact; check `SECURITY.md` / `CONTRIBUTING.md` / `ci.yml` first.
- `bus_factor`, `build_repeatable`, and `crypto_algorithm_agility` are SHOULD
  criteria — "Met" / "N/A" with an honest justification is accepted; none is a
  hard blocker.
- `assurance_case` is the only silver MUST that requires a net-new document
  (`ASSURANCE.md`); resolve its own FILL markers before answering this row.
