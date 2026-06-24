# Changelog

All notable changes to `presidio-hardened-ikigov-assess` are recorded here.
Earlier releases (v0.1.0–v0.19.2) are documented fully in `PRESIDIO-REQ.md`
(version registry and deliberation log). This file covers v0.20.0 onwards.

---

## [0.21.0] — 2026-06-11

### fix(i18n): Markdown report headers localised

`render_markdown` (export + workshop leave-behind path) emitted hard-coded
English table headers (`Field | Value`, `Risk Class`, `Tool Version`,
`Gate | Status | Blocking / Skipped Items`, dimension columns). All headers now
route through `t()` with de+en entries — the customer leave-behind is fully
German under `--lang de`.

### feat(T-B3): `iga workshop` subcommand — offline customer-workshop tool

New `iga workshop run` and `iga workshop verify` commands targeting DACH
customer-workshop use: signed leave-behind artifacts per use case in under
2 minutes, fully offline (air-gapped customer sites), default language German.

#### New module

- **`src/presidio_ikigov_assess/workshop.py`** — `workshop_app` Typer sub-app
  with two commands:

  `workshop run` — reads an `eai-classification/v1` document, resolves each
  (selected) use case's cell→profile, optionally applies pre-filled
  `answers.json`, computes scores/gates, renders a large-format projector view
  (Rich Panels, Gate status rows, risk-class colour coding), and writes a
  per-use-case artifact directory:
  `report.<lang>.md`, `report.json` (full payload + classification provenance
  block), `manifest.json` (schema `presidio-hardened/workshop-leavebehind@1`,
  per-artifact SHA-256, pack content hash, tool version, signed/UNSIGNED flag),
  and `manifest.sig` (Ed25519 detached signature or UNSIGNED marker JSON).

  `workshop verify` — re-hashes artifacts against `manifest.json` and verifies
  the Ed25519 signature; fail-closed (exit 1 on any mismatch).

#### Offline design

`main_callback` in `cli.py` detects `ctx.invoked_subcommand == "workshop"` and
sets `_NO_DEP_CHECK = True` automatically.  The `IGA_NO_DEP_CHECK=1` env-var
bypass is also supported (testable via `monkeypatch`).  Rationale: `pip-audit`
requires network access; at an air-gapped customer site it would hang, time out,
and emit a "inconclusive" warning — the opposite of a smooth projector demo.

#### Ed25519 signing design

- Private key: raw 32 bytes in hex (64 chars), from `--sign-key <file>` or
  `$IGA_WORKSHOP_SIGN_KEY`.  File is mode-checked (warn if not `0600`, no abort).
- Signature is over the **canonical JSON bytes** of `manifest.json` (deterministic
  `json.dumps(sort_keys=True, separators=(",", ":"))` encoded UTF-8), not the
  pretty-printed form — so the customer can reconstruct the signed input from the
  file itself.
- Uses the same `cryptography` optional extra (`[crypto]`) as `evidence.py`
  (`Ed25519PrivateKey` / `Ed25519PublicKey` from
  `cryptography.hazmat.primitives.asymmetric.ed25519`).
- If no key is provided: artifact is written unsigned with an `{"UNSIGNED": true}`
  marker in `manifest.sig` and an explicit `"UNSIGNED": true` field in
  `manifest.json`.  Workshop does **not** fail on missing crypto.
- `workshop verify --pubkey <hex>` verifies the signature; returns
  `{"ok": true/false, "artifacts": {...}, "signature": true/false/null}`.

#### `answers.json` format and validation

`{use_case_id: {"affirm": [...], "skip": [...]}}` — all use-case ids validated
against the classification document; all item ids validated through
`validate_item_ids`; document size-capped at 64 KiB; fail-closed on any error.

#### cli.py changes

- `workshop_app` wired via `app.add_typer(workshop_app, name="workshop")`.
- `main_callback` gains a `ctx: typer.Context` parameter and detects
  `invoked_subcommand == "workshop"` for the dep-check bypass.
- `IGA_NO_DEP_CHECK=1` env-var bypass documented in the callback comment.
- `_ENV_NO_DEP_CHECK = "IGA_NO_DEP_CHECK"` constant added.

#### New tests

- **`tests/test_workshop.py`** — 31 tests covering: full run (files exist),
  manifest schema + SHA-256 verification, UNSIGNED marker, unsigned stderr
  warning, Ed25519 sign/verify round-trip with a generated keypair, wrong-pubkey
  fails, tampered-artifact fails, unsigned artifact verify (signature=None),
  `answers.json` affirm/skip applied, bad item id fails, unknown use-case id
  fails, `--select` single and multiple, non-existent `--select` fails, offline
  dep-check bypass assertion (monkeypatched `dep_check_status` raises if called),
  missing file fails, invalid JSON fails, bad lang fails, wrong schema version
  fails, classification provenance block in `report.json`, German content in
  `report.de.md`, performance (<10 s for 4-use-case medical fixture), English
  run produces `report.en.md`, low-level Ed25519 sign/verify unit tests,
  `$IGA_WORKSHOP_SIGN_KEY` env-var path, German localisation sentinel assertions.

---

### feat(T1.4): Full German localisation sweep

All user-facing runtime output (tables, panels, warnings, errors, disclaimers)
now goes through `t()` so `--lang de` produces fully German output with no
English-only sentinel strings.

#### New i18n.py strings

Workshop strings (de+en): `workshop_panel_title`, `workshop_header_title`,
`workshop_header_use_cases`, `workshop_header_lang`, `workshop_header_signed`,
`workshop_unsigned_marker`, `workshop_cell_label`, `workshop_risk_label`,
`workshop_strict_label`, `workshop_gates_header`, `workshop_artifact_written`,
`workshop_done`, plus all error/warning strings for file reads, key handling,
answers validation, and verify output.

Runtime strings localised in the sweep (de+en):
`evidence_coverage_line`, `export_written`, `verify_bundle_ok`,
`verify_bundle_invalid`, `verify_evidence_no_refs`, `verify_evidence_ok`,
`verify_evidence_fail`, `assessment_cancelled`, `cell_info_line`.

#### cli.py and classify.py changes

- `assess`: wizard cancellation message uses `t('assessment_cancelled', lang)`.
- `assess`: evidence coverage line uses `t('evidence_coverage_line', ...)`.
- `verify-evidence`: item status marks and "no refs" warning use `t(...)`.
- `export`: "Evidence pack written" uses `t('export_written', ...)`.
- `verify-bundle`: artifact marks and signature status use `t(...)`.
- `classify assess`: cell/profile dim line and evidence coverage use `t(...)`.

#### Deliberate exclusions (documented)

- `--help` texts: left in English per the no-existing-pattern rule (Typer help
  text localisation has no existing pattern in this repo; the spec explicitly
  allows this).
- Dep-check output (`dep_check_start`, `dep_check_ok`, etc.): these strings are
  already in `i18n.py` with de+en entries; `_run_dep_check_quietly` keeps `'en'`
  because the dep check fires before any `--lang` argument is parsed. This is an
  explicit design constraint, not an omission.
- Security log events (e.g. `"event": "iga-assessment-complete"`): structural
  metadata, intentionally language-neutral per the secure-logging policy.
- Internal error messages for OS/JSON failures that don't pass through `t()`:
  these surface the raw exception message which is inherently language-neutral.

---

## [0.20.0] — 2026-06-11

### feat: classificator bridge (eai-classification/v1)

Implements task T-B1: a producer-agnostic interchange layer between the
Enterprise AI Classification Framework (eai-classificator research artefact +
partner survey tooling) and the IKI-Gov assessment
engine. The schema is keyed to the *model* (eai-classification/v1), not to any
one tool's output format.

#### New modules

- **`src/presidio_ikigov_assess/classification.py`** — Interchange schema parser.
  Parses and validates `eai-classification/v1` JSON documents. Enforces hard
  input limits (max 200 use cases, 1 MB document), type/level allow-lists,
  id pattern matching `sanitize.py` rules, optional field validation, and the
  ecosystem/L6 normalisation rule. Forward-compatible: unknown fields ignored;
  unknown schema versions fail closed.

- **`src/presidio_ikigov_assess/content/profile.py`** — `ProfilePack` frozen
  dataclass (modelled on `content/pack.py`). Maps all 36 cells T1–T6 × L1–L6
  to risk profiles (risk_presumption, strict, obligations, bilingual notes).
  Validates completeness; `content_hash` over canonical JSON.

- **`src/presidio_ikigov_assess/content/profile_builtin.py`** — Built-in default
  pack with **DRAFT mapping semantics** (founder review required before merge).
  Risk presumption by autonomy: L1–L2 low, L3–L4 medium,
  L5 high, L6 high+strict. Type modifiers: T6 Physical floors at medium from
  L2 and high from L4; T1 Decision floors at medium from L3. All cells carry
  obligations `["iso42001","euaiact"]` and bilingual (de/en) notes.

- **`src/presidio_ikigov_assess/classify.py`** — `iga classify` sub-app.
  Commands: `ingest` (validate + table/JSON output) and `assess` (profile-driven
  full pipeline reusing existing `compute_scores` / `evaluate_all_gates` /
  `render_json` / `store.save_assessment` / `log_security_event`). Profile
  `strict=true` cannot be loosened by flags; `--strict` may further tighten.

#### Modified modules

- **`src/presidio_ikigov_assess/content/loader.py`** — Extended with
  `load_external_profile_packs` and `load_profile_packs`; existing
  `load_external_packs` skips `pack_kind=classification-profile` files so the
  two pack kinds coexist without conflict. Existing ContentPack loading
  unchanged.

- **`src/presidio_ikigov_assess/content/__init__.py`** — Exports new profile
  symbols (`CellProfile`, `ProfilePack`, `ProfileError`, helpers, builtin).

- **`src/presidio_ikigov_assess/cli.py`** — Wires `classify_app` as
  `app.add_typer(classify_app, name="classify")`; version bumped to v0.20.0.

- **`src/presidio_ikigov_assess/i18n.py`** — New bilingual strings for the
  `classify` command group (de + en).

#### New files

- **`schemas/eai-classification.v1.schema.json`** — JSON Schema (draft/2020-12)
  for external partner producers to validate against. Documentation-grade;
  authoritative validation is the Python parser. Note in the schema explains that
  `jsonschema` is not a declared dependency.

- **`tests/test_classify.py`** — 61 tests covering: schema happy path; every
  malformed-field case; unknown-version fail-closed; unknown fields ignored;
  L6/ecosystem normalisation incl. contradiction; size limits; ProfilePack
  completeness (36 cells), `content_hash` stability snapshot; builtin draft
  semantics spot-checks (T6.L4→high, T1.L1→low, all L6→strict); external
  override via `IGA_CONTENT_PATH` tmpdir; loader coexistence of both pack kinds;
  CLI ingest table + quiet JSON; classify assess end-to-end in German with
  `--quiet --save`; security event logged with cell + `pack_content_hash`.

- **`tests/fixtures/medical_classification.json`** — Synthetic medical-domain
  fixture: infusion-pump dosing (T1.L4), infusion-pump predictive (T2.L4),
  dialysis remote service (T2.L3 ecosystem→T2.L6), surgical robotics (T6.L3).

#### Version

`pyproject.toml` and `__init__.py` bumped to **0.20.0**.
`PRESIDIO-REQ.md` updated with v0.20.0 entry.
