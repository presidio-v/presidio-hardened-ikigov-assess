# Changelog

All notable changes to `presidio-hardened-ikigov-assess` are recorded here.
Earlier releases (v0.1.0–v0.19.2) are documented fully in `PRESIDIO-REQ.md`
(version registry and deliberation log). This file covers v0.20.0 onwards.

---

## [0.20.0] — 2026-06-11

### feat: classificator bridge (eai-classification/v1)

Implements task T-B1: a producer-agnostic interchange layer between the
Enterprise AI Classification Framework (eai-classificator research artefact +
partner tooling, e.g. kenza conversational survey) and the IKI-Gov assessment
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
  pack with **DRAFT mapping semantics** (founder review required before merge,
  Humboldt discipline). Risk presumption by autonomy: L1–L2 low, L3–L4 medium,
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
  for external producers (kenza/nusi) to validate against. Documentation-grade;
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
