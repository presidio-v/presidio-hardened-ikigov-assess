# Presidio-Hardened Toolkit: presidio-hardened-ikigov-assess

## Overview

Build a production-ready Python CLI tool named `presidio-hardened-ikigov-assess` that implements MVP 0.1.0 of the **IKI-Gov Assessment Tool** — a practical operationalization of the IKI-Gov-Referenzmodell (Integrated KI-Governance Reference Model) developed by Vladimir Stantchev.

The IKI-Gov framework structures AI governance along a central lifecycle (phases Kontext → Konzeption → Entwicklung → Freigabe → Betrieb → Anpassung → Außerbetriebnahme) surrounded by six domains (Strategie & Portfolio; Organisation, Rollen & Kultur; Daten & Wissen; Technologie, Werkzeuge & Lieferkette; Recht, Ethik & Compliance; Risiko, Sicherheit & Kontrolle). Six measurement dimensions M1–M6 and six quality gates G0–G5 operationalize governance evidence requirements. Risk intensity scales with damage potential and regulatory exposure, not hype.

The tool enables organizations to assess an AI use case against the framework, score it across M1–M6, identify open gaps, and determine readiness for lifecycle gates G0–G5. It runs in two modes: **parameter-driven** (scriptable, CI-friendly) and **interactive wizard** (guided prompt-by-prompt walkthrough of the checklist). All user-facing text is bilingual (German / English), selectable via `--lang de|en` (default: `en`).

CLI command: `iga`

Canonical invocations:
```bash
# Parameter-driven assessment
iga assess --use-case "fraud-scoring" --risk-class high --lang de

# Interactive wizard
iga assess --interactive --lang en

# Gate readiness check
iga gate --gate G2 --use-case "fraud-scoring"

# Export report
iga report --use-case "fraud-scoring" --format markdown
```

The checklist content is drawn directly from the five appendix sections of the IKI-Gov book (Strategie & Geschäftsfall, Daten/Recht/Ethik, Modell/Sicherheit/Technik, Betrieb/Monitoring/Aufsicht, ISO/IEC 42001 Abgleich), each containing five items, for a total of 25 checklist items. Each item is mapped to one primary M1–M6 dimension and to the relevant gate(s) G0–G5.

## Mandatory Presidio Security Extensions

- Input sanitization for all CLI parameters (use-case names, risk classes, gate identifiers): bounds checking, type validation, rejection of malformed or overlong inputs
- Secure logging: no use-case content, no organizational data, no secrets in log output; log only structural events (gate checked, assessment completed, export written)
- On-run CVE/dependency check via `pip-audit` or `safety` on startup (configurable, suppressible with `--no-dep-check` for offline/CI environments)
- Security event logging: emit structured log entry for each assessment run, e.g. `{"event": "iga-assessment-complete", "risk_class": "high", "gates_open": ["G0","G1"], "lang": "en"}`
- Rate-limit/abuse guard on CLI invocations: configurable max assessments per session (default: 100)
- Strict output sanitization: use-case names and free-text inputs are HTML/shell-escaped before any export; never echoed raw into report templates
- Full GitHub security files: `SECURITY.md`, `.github/dependabot.yml`, `.github/workflows/codeql.yml`, `.github/workflows/pytest.yml`

## Technical Requirements

- Python 3.9+ for the v0.1.0–v0.8.x line. **Minimum rises to Python 3.10+ in
  v0.9.0** (see the v0.9.0 platform decision and cross-cutting decisions table) so
  the whole dependency tree can resolve to security-patched releases — the patched
  `urllib3` line dropped 3.9, leaving the dev/audit toolchain pinned to a
  vulnerable version on 3.9 only.
- Modern `pyproject.toml` + hatchling/uv + Typer CLI
- `src/presidio_ikigov_assess/` layout
- Commands:
  - `iga assess` — assess a use case (parameter-driven or `--interactive`)
  - `iga gate` — check readiness for a specific gate G0–G5
  - `iga report` — export last or named assessment to Markdown or JSON
  - `iga list` — list saved assessments (v0.6.0 portfolio feature prerequisite stub)
- Checklist engine: 25 items from the five appendix sections, each with:
  - `id` (e.g. `S1`–`S5`, `D1`–`D5`, `T1`–`T5`, `O1`–`O5`, `I1`–`I5`)
  - text in both `de` and `en`
  - primary M-dimension (`M1`–`M6`)
  - relevant gates (`G0`–`G5`, list)
  - risk-class weight multiplier (low/medium/high: 1.0/1.5/2.0)
- Scoring: per-dimension score 0–100 derived from proportion of affirmed items weighted by risk class; overall maturity score 0–100 (arithmetic mean of M1–M6)
- Gate readiness: a gate Gn is "open" if all items mapped to Gn with the active risk class have been affirmed; gates are shown as OPEN / PARTIAL / BLOCKED with blocking items listed
- Bilingual output: all prompts, labels, and console output respect `--lang de|en`; default `en`
- Interactive mode: Typer + prompt_toolkit for step-by-step wizard with progress indicator, Y/N/Skip per item, inline help text
- Parameter mode: pass answers as `--affirm S1,S2,D1,...` and/or `--skip I3` flags; non-interactive, exits 0 on success, 1 on blocked gates when `--assert-gate Gn` is set (CI use case)
- 80%+ test coverage with pytest
- README.md with side-by-side examples, framework reference, and IKI-Gov book citation
- LICENSE = MIT
- Version = 0.1.0

---

# Version Registry & Deliberation Log

Every deliberation about future versions and roadmap is persisted here.

---

## Roadmap Summary

| Version | Theme | Status |
|---|---|---|
| v0.1.0 | MVP — interactive + parameter-driven assessment, M1–M6 scoring, bilingual | Shipped |
| v0.2.0 | MCP server — agent-accessible assessment engine (`iga-mcp`) | Shipped |
| v0.3.0 | Gate readiness refinement, risk-class-aware thresholds, CI exit codes 0/2/3 | Shipped |
| v0.4.0 | Report export: Markdown and JSON (`--output`) + per-item answers | Shipped |
| v0.5.0 | ISO/IEC 42001 clause-level gap mapping (`iga iso-gap`) | Shipped |
| v0.6.0 | Portfolio mode: SQLite persistence, `list` / `portfolio` / `delete` | Shipped |
| v0.7.0 | Maturity trending: delta between runs (`iga trend`) | Shipped |
| v0.8.0 | EU AI Act gate→article mapping (`iga euaiact-gap`) | Shipped |
| v0.9.0 | Evidence-pack export: signed, audit-ready report bundle + manifest | Shipped as v0.15.0 |
| v0.10.0 | Pluggable regulatory-content provider interface (versioned content packs) | Shipped as v0.16.0 |
| v0.11.0 | NIST AI RMF mapping + framework-agnostic coverage core | Shipped as v0.17.0 |
| v0.12.0 | Remote MCP endpoint: HTTP/SSE transport, org context, auth | Shipped as v0.18.0 |
| v0.13.0 | External evidence-backed affirmation: consume signed evidence from peer `presidio-hardened-*` controls (first producer: `presidio-hardened-ai`) | Shipped |
| v0.14.0 | Public-key (Ed25519) evidence verification: trust-store `{alg, public_key}` entries + `verify_ref` dispatch (`[crypto]` extra) | Shipped |
| v0.14.1 | Key rotation: multiple active public keys per signer (`public_key`/`key` may be a list; verify against any) | Shipped |
| v0.15.0 | Signed evidence-pack export: `iga export` / `iga verify-bundle` (realises the v0.9.0 feature) | Shipped |
| v0.16.0 | Pluggable content packs: `content/` core + `iga content-list` / `iga framework-gap` (realises v0.10.0) | Shipped |
| v0.16.1 | Evidence-pack seal key off argv: `--sign-key-file` / `$IGA_SIGN_KEY` for `export` / `verify-bundle` | Shipped |
| v0.17.0 | NIST AI RMF built-in content pack (realises v0.11.0; works via `framework-gap`, no engine change) | Shipped |
| v0.18.0 | Remote MCP endpoint primitives: token auth, per-org store scoping, per-org rate limiting (`remote.py`, realises v0.12.0) | Shipped |
| v0.19.0 | Remote endpoint enforcement: pure-ASGI `OrgAuthMiddleware` wires auth (401) + per-org rate limit (429) ahead of the MCP app; concurrency-safe context-var store scoping | Shipped |
| v0.19.1 | Producer-compat sync: verified interop with `presidio-hardened-ai` v0.30.0 (P4 consortium — GOD + L∞/L2 bounded-norm + robustness); `EvidenceRef@1` unchanged, no engine change; consortium-`D4` regression test | Shipped |
| v0.19.2 | Dependency maintenance: resolve Dependabot pip + GitHub-Actions updates (typer/rich/prompt-toolkit/pytest/ruff floors, checkout@v6, codecov-action@v7); enforce `requires-python >=3.10` and drop the stale Python 3.9 CI leg | Shipped |
| v0.20.0 | Classificator bridge (eai-classification/v1): producer-agnostic interchange schema, 36-cell classification-profile pack, `iga classify ingest` / `iga classify assess` CLI | Shipped |
| v0.21.0 T-B3 | `iga workshop` — offline customer-workshop tool, Ed25519 signed leave-behind artifacts, `workshop verify` | **Current** |
| v0.21.0 T1.4 | Full German localisation sweep — all runtime output fully bilingual via `t()`, no English sentinel strings under `--lang de` | **Current** |

> **Sequencing note (v0.13.0).** Its only hard dependency is v0.9.0 (the signed
> evidence-pack manifest + hash/signature baseline). It is independent of v0.10.0–v0.12.0
> and may be pulled forward to immediately after v0.9.0 if the `presidio-hardened-ai`
> integration is prioritised over NIST mapping / remote MCP. Numbered v0.13.0 here only to
> avoid renumbering the existing planned versions — the decision is the author's at commit.

---

## v0.1.0 — MVP: Assessment, Scoring, Bilingual Output

**Deliberated:** 2026-03-28

### Scope decision
Single use-case assessment only. No persistence beyond session. Both interactive and parameter-driven mode. Languages: `de` and `en`. Console output only (no file export — deferred to v0.4.0).

### Core data model
25 checklist items in five sections, each item carrying: `id`, `text_de`, `text_en`, `m_dimension` (M1–M6), `gates` (list of G0–G5 strings), `risk_weight` (dict: low→1.0, medium→1.5, high→2.0).

Section-to-M-dimension primary mapping:

| Section | Items | Primary M-dimension |
|---|---|---|
| Strategie & Geschäftsfall | S1–S5 | M1 (Strategie & Ownership) |
| Daten, Recht & Ethik | D1–D5 | M2 (Datenqualität & Lineage) |
| Modell, Sicherheit & Technik | T1–T5 | M3 / M4 (split: T1–T3 → M3 Validierung/Fairness; T4–T5 → M4 Sicherheit) |
| Betrieb, Monitoring & Aufsicht | O1–O5 | M6 (Betrieb, Drift & Vorfälle) |
| ISO/IEC 42001 Abgleich | I1–I5 | M5 (Compliance-Nachweise) |

### Scoring formula
```
score_m(dim) = sum(weight_i for affirmed i in dim) / sum(weight_i for all i in dim) * 100
overall = mean(score_M1, …, score_M6)
```
Weights: risk-class multiplier × 1 (affirmed) or 0 (not affirmed / skipped).
Skipped items counted as 0 for denominator reduction: skipped items are excluded from both numerator and denominator (conservative for CI mode, explicit in report).

### Gate readiness logic
Gate Gn is:
- **OPEN** — all items mapped to Gn are affirmed (respecting active risk class)
- **PARTIAL** — some items affirmed, ≥1 not affirmed and not skipped
- **BLOCKED** — ≥1 item mapped to Gn is explicitly not affirmed (answered "no")

In parameter mode, `--assert-gate Gn` exits 1 if gate is PARTIAL or BLOCKED (enables CI pipeline integration).

### CLI surface
```bash
# Interactive wizard
iga assess --interactive --lang de --risk-class high --use-case "kredit-scoring"

# Parameter-driven (pass affirmed item IDs)
iga assess --use-case "fraud-scoring" --risk-class high \
    --affirm S1,S2,S3,D1,D2,T1,T4,O1,I1 \
    --skip I4,I5 \
    --lang en

# Gate check (inline, no persistence needed in v0.1)
iga gate --gate G2 --risk-class high \
    --affirm S1,S2,S3,D1,D2,T1,T4,O1,I1 \
    --lang en

# CI use: fail build if G1 is not OPEN
iga gate --gate G1 --risk-class high --affirm S1,S2,D1,D2 --assert-gate G1
```

### Output format (console)
```
IKI-Gov Assessment — fraud-scoring  [risk: HIGH]

Measurement Dimensions
  M1  Strategie & Ownership          ████████░░  82 %
  M2  Datenqualität & Lineage        ██████░░░░  61 %
  M3  Validierung & Fairness         ████░░░░░░  40 %
  M4  Sicherheit & Robustheit        █████████░  90 %
  M5  Compliance-Nachweise           ███░░░░░░░  30 %
  M6  Betrieb, Drift & Vorfälle      ██████░░░░  60 %
  ─────────────────────────────────────────────────
  Overall maturity                               60 %

Gate Readiness
  G0  OPEN
  G1  OPEN
  G2  PARTIAL  — blocking: T2 (Fairness-Checks), D3 (Nutzungsrechte)
  G3  BLOCKED  — blocking: O2 (Monitoring), O4 (Incident & Änderung)
  G4  BLOCKED
  G5  BLOCKED
```

---

## v0.2.0 — MCP Server: Agent-Accessible Assessment Engine

**Deliberated:** 2026-06-02

### Scope decision
Expose the existing v0.1.0 assessment engine over the **Model Context Protocol (MCP)**
so MCP-capable LLM agents and clients (e.g. Claude Desktop) can run IKI-Gov
assessments as tools. Built ahead of the original sequence because it depends only
on the v0.1.0 engine, and because the book launch makes an agent-accessible
governance tool especially valuable. The previously-planned v0.2.0–v0.7.0 themes
are renumbered +1 (now v0.3.0–v0.8.0); their scope is unchanged.

The MCP server is a **thin additional front-end**, peer to the Typer CLI: it reuses
`sanitize` (validation), `scoring`, `gates`, and `renderer.build_payload` unchanged.
No change to the scoring formula, gate logic, or checklist data model.

### Implementation
- New module `src/presidio_ikigov_assess/mcp_server.py` using the official MCP
  Python SDK (FastMCP) over stdio.
- New console script `iga-mcp` (entry point `mcp_server:main`).
- New optional extra `[mcp]` requiring `mcp>=1.2.0; python_version >= '3.10'`. The
  core CLI remains Python 3.9-compatible; the MCP extra is 3.10+ only.
- Pure tool-logic functions (`framework_info`, `list_items`, `assess`, `gate_status`)
  are independent of the `mcp` package and unit-tested directly, so they run on
  every supported Python; only `build_server`/`main` import FastMCP.

### Tools
| Tool | Purpose |
|---|---|
| `iga_framework_info` | Lifecycle phases, dimensions M1–M6, gates G0–G5, sections, risk classes (de/en) |
| `iga_list_checklist` | All 25 checklist items: id, text, dimension, gates, section |
| `iga_assess` | Affirmed/skipped item IDs → M1–M6 scores, overall maturity, gate readiness |
| `iga_check_gate` | Single-gate readiness with blocking/skipped items |

### Security
- All tools run the same input validation as the CLI; invalid input surfaces as an
  MCP tool error (`ToolInputError`), never crashing the long-running server.
- The per-session abuse guard is reused via a **non-fatal** counter
  (`increment_session_count`), so an over-limit request returns a tool error instead
  of calling `sys.exit` (which would kill the server).
- Structured security events (`iga-mcp-assessment-complete`, `iga-mcp-gate-check`)
  are logged with structural metadata only — no use-case content.
- Tool output reuses the report payload's HTML-escaping of the use-case name.

### Dependency
Independent of v0.3.0–v0.8.0; depends only on the v0.1.0 engine.

---

## v0.3.0 — Gate Readiness Refinement & CI Hardening

**Deliberated:** 2026-03-28

### Scope decision
Introduce risk-class-aware gate thresholds (low risk: PARTIAL suffices to OPEN a gate; medium: all non-skipped items must affirm; high: no skips allowed for gate-critical items). Add `--strict` flag for high-risk enforcement. Improve CI exit codes: 0 OPEN, 2 PARTIAL, 3 BLOCKED (distinct from general error 1).

### New flags
| Flag | Description |
|---|---|
| `--strict` | No skips permitted for gate-critical items (implied at `--risk-class high`) |
| `--assert-gate G2` | Exit with gate-specific code; stackable for pipelines |
| `--quiet` | Machine-readable JSON output only (no progress bars) |

### Implementation (2026-06-02)

Resolved the deliberated scope as follows:

- **Status policy in `gates.py`.** The gate *partition* (affirmed / denied /
  skipped) stays policy-free; a pure `_resolve_status(blocking, skipped,
  risk_class, strict)` maps it to OPEN/PARTIAL/BLOCKED. Low risk forgives skips
  (OPEN), medium leaves them PARTIAL, high/`--strict` makes them block.
  `evaluate_gate`/`evaluate_all_gates` gained `risk_class="medium"` and
  `strict=False` parameters (default = prior v0.1 behaviour, so existing callers
  are unaffected).
- **`GateResult.blocking_skips`.** New field listing the skipped items that block
  under strict/high-risk policy, so a BLOCKED-not-PARTIAL gate can explain *why*.
  Surfaced in console (`blocking (skips not permitted): …`), Markdown, JSON
  report (`gates.<G>.blocking_skips`), and the MCP tools.
- **CI exit codes.** `--assert-gate` now exits `0` OPEN / `2` PARTIAL / `3`
  BLOCKED; `1` remains the general-error code (invalid input, or `--assert-gate`
  not matching `--gate`). Mapping lives in `cli.GATE_EXIT_CODES`.
- **`--strict` / `--quiet`** added to `assess`, `gate`, and (`--strict`) `report`;
  `--quiet` emits the JSON payload (`render_json`) or single-gate JSON
  (`render_gate_json`). The MCP `iga_assess` / `iga_check_gate` tools gained a
  `strict` argument and thread `risk_class` into gate evaluation.

Decision note: `--assert-gate` is constrained to match `--gate` (a mismatch is a
usage error, exit 1) rather than silently no-opping as in v0.1; "stackable" is
achieved by running one `iga gate … --assert-gate` per gate in the pipeline.

Tests: 172 total, 94% coverage (gate-policy matrix in `test_gates.py`, exit
codes / strict / quiet in `test_cli.py`, strict threading in `test_mcp_server.py`).

---

## v0.4.0 — Report Export: Markdown and JSON

**Deliberated:** 2026-03-28

### Scope decision
`iga report` writes assessment results to file. Formats: `--format markdown` (default) and `--format json`. No PDF in this version (heavy dependency, deferred). Markdown suitable for inclusion in Git repos or audit folders.

### Report content
- Use-case metadata (name, risk class, timestamp, `iga` version)
- Per-item answers (affirmed / not-affirmed / skipped) with item text in selected language
- M1–M6 scores with bar representation
- Gate readiness table with blocking items
- Disclaimer: "Generated by IKI-Gov Assessment Tool. Does not constitute legal advice or certification."

### Output sanitization
All use-case names and free-text fields are HTML-escaped in Markdown export and JSON-escaped in JSON export before writing. No raw user input echoed verbatim without escaping.

### Implementation (2026-06-02)

- **File export.** `iga report` gained `--output/-o PATH`; without it the report
  still prints to stdout (unchanged). The file gets exactly the rendered Markdown
  or JSON; a confirmation (`Report written to: …`) goes to **stderr** via
  `typer.echo(err=True)` — deliberately not Rich, to avoid markup interpretation
  and line-wrapping of a user-supplied path. Write failures (e.g. missing parent
  dir) exit 1.
- **Path validation.** New `sanitize.validate_output_path` bounds length (4096)
  and rejects empty/null-byte paths; no location allow-list is imposed since the
  user writes to their own chosen path.
- **Per-item answers.** New `renderer.item_answers()` (+ `classify_answer`) yields
  all 25 items in order with status (affirmed / not affirmed / skipped),
  dimension, gates, and localised text. Surfaced as a Markdown table ("Per-Item
  Answers") and as `answers.items[]` in the JSON payload (alongside the existing
  `answers.affirmed`/`answers.skipped` id-lists). Because the JSON shape is shared
  via `build_payload`, the MCP `iga_assess` tool now returns per-item detail too.
- **Escaping.** Markdown item text is HTML-escaped and table-breaking `|`
  neutralised; JSON escaping is handled by `json.dumps`.

Decision note: PDF export remains deferred (heavy dependency), per the original
scope. Security log records `to_file` (boolean) only — never the output path.

Tests: 184 total, 94% coverage (file export + per-item in `test_cli.py`,
`validate_output_path` in `test_sanitize.py`).

---

## v0.5.0 — ISO/IEC 42001 Clause-Level Gap Mapping

**Deliberated:** 2026-03-28

### Scope decision
Map M1–M6 and each checklist item to ISO/IEC 42001 clauses 4–10 and Annex A using the orientation matrix from the book (chapter-framework, Table tab:framework-iso42001-matrix). Show which clauses are fully covered, partially covered, or uncovered based on assessment results.

### New command
```bash
iga iso-gap --use-case "fraud-scoring" --affirm S1,S2,D1 --risk-class high --lang en
```

Output: table of ISO 42001 clause groups × coverage status (covered / partial / gap), with actionable suggestions per gap row.

### Data model extension
Each checklist item gains a `iso_clauses` field: list of clause references (e.g. `["6", "8", "A"]`) from the orientation matrix.

### Implementation (2026-06-02)

- **Orientation matrix.** `checklist.ISO_CLAUSES_BY_ITEM` maps every item to its
  ISO/IEC 42001 clause groups (`ISO_CLAUSE_ORDER = 4,5,6,7,8,9,10,A`), exposed as
  an `item.iso_clauses` property (mirroring `item.text()`/`item.weight()`).
  `ITEMS_BY_ISO_CLAUSE` indexes the reverse direction.
- **Coverage engine.** New `iso.py`: `evaluate_iso_coverage(affirmed)` returns a
  `ClauseCoverage` per clause — covered (all mapped items affirmed) / partial /
  gap (none affirmed) — plus the outstanding (not-affirmed) items. Skipped and
  denied items count as not affirmed (no coverage credit), consistent with the
  conservative "skip ≠ evidence" stance.
- **Command.** `iga iso-gap` renders a console table (clause · name · status ·
  affirmed/total · outstanding items) or `--quiet` JSON (`render_iso_json` /
  `build_iso_payload`). Accepts the usual `--affirm/--skip/--risk-class/--lang`;
  risk class is recorded but does not change coverage.
- **MCP + reports.** New `iga_iso_gap` MCP tool returns the same payload; the
  per-item answers in reports/`build_payload` gained an `iso_clauses` field.

**Mapping reconciled with the book (v0.5.1).** The `ISO_CLAUSES_BY_ITEM` values
were initially inferred from item content, then reconciled against the book's
`tab:framework-iso42001-matrix`. That table is qualitative and at M-dimension
granularity (M1–M6 × clauses 4–10/Annex A, with •=high / ○=supporting relevance);
this item-level table refines it. Comparison found no contradictions (every mapped
clause is at least ○ in the book) but 8 high-relevance (•) cells were initially
under-mapped — chiefly the management-system clauses (4 Context, 6 Planning,
7 Support, 9 Performance evaluation) for the technical/strategy dimensions. v0.5.1
adds those (S1+9; T1+6,9; T4+6; T5+4,7; I1+4; I4+A) so each dimension's item-clause
union covers the book's • cells. `test_iso.test_mapping_covers_book_high_relevance_cells`
locks this in against future drift.

Tests: 209 total, 95% coverage (`test_iso.py` for the engine, `iso-gap` in
`test_cli.py`, matrix integrity in `test_checklist.py`, tool in `test_mcp_server.py`).

---

## v0.6.0 — Portfolio Mode: Multiple Use Cases, SQLite Persistence

**Deliberated:** 2026-03-28

### Scope decision
Persist assessment results across sessions in a local SQLite database at `~/.iga/assessments.db`. Enable portfolio view: list all assessed use cases, overall portfolio maturity, and highest-risk gaps across use cases.

### New commands
```bash
iga list                            # table of all saved assessments
iga portfolio                       # aggregated M1–M6 across all use cases
iga assess --save ...               # persist after assessment
iga delete --use-case "fraud-scoring"
```

### Schema
Table `assessments`: `id`, `use_case`, `risk_class`, `timestamp`, `answers_json`, `scores_json`, `gates_json`, `lang`.

### Security
- DB file permissions: 600 (user-only read/write)
- No organizational metadata stored beyond what the user explicitly provides
- `iga delete` performs hard delete (no soft-delete log retained locally)

### Implementation (2026-06-02)

- **Store.** New `store.py`: SQLite at `~/.iga/assessments.db`, path resolved via
  `db_path()` (`IGA_DB_PATH` env override, primarily for tests). `_connect()`
  creates the dir 0o700, the file 0o600, and the `assessments` table on every
  open. API: `save_assessment`, `list_assessments` (newest first),
  `delete_use_case` (hard delete, returns rowcount), `latest_per_use_case`,
  `portfolio_summary`.
- **Schema** as specified: `id, use_case, risk_class, timestamp, lang,
  answers_json, scores_json, gates_json`. Scores stored as `{M1..M6, overall}`,
  gates as `{Gn: status}`, answers as `{affirmed[], skipped[]}`.
- **Commands.** `iga assess --save` persists after assessing (confirmation to
  stderr, so `--quiet` stdout stays pure JSON). `iga list` (table or `--quiet`
  JSON), `iga portfolio` (mean M1–M6 + overall across the latest assessment per
  use case, plus a count of use cases with each gate BLOCKED), `iga delete
  --use-case` (hard delete). The v0.1 `list` stub is replaced.
- **Portfolio aggregation** uses the most recent assessment per use case
  (`latest_per_use_case`); means are simple arithmetic over those.

Tests: 230 total, 95% coverage. CLI tests use an autouse fixture pointing
`IGA_DB_PATH` at a temp file so the real `~/.iga` is never touched;
`test_store.py` covers the store directly incl. the 0o600 file-permission check.

---

## v0.7.0 — Maturity Trending: Delta Between Runs, History View

**Deliberated:** 2026-03-28

### Scope decision
For use cases with ≥2 saved assessments, compute and display delta in M1–M6 scores and gate status changes between the two most recent runs (or any two selected by timestamp). Enables governance improvement tracking over time.

### New flags / commands
```bash
iga trend --use-case "fraud-scoring"            # delta: latest vs. previous
iga trend --use-case "fraud-scoring" --from 2026-01-15 --to 2026-03-28
```

Output: per-dimension delta (▲/▼/=), gate status transitions (e.g. G2: BLOCKED → PARTIAL), overall maturity delta.

### Implementation (2026-06-02)

- **Engine.** New `trend.py`: `select_trend_pair` chooses (earlier, later) — by
  default the previous vs latest saved run; with a `--from`/`--to` window, the
  earliest and latest within it. `compute_trend` returns `TrendResult` with
  per-dimension `DimensionDelta` (earlier, later, delta, direction up/down/same),
  overall delta, and a `GateTransition` per gate (with a `changed` flag).
- **Date window.** `--from`/`--to` are `YYYY-MM-DD` (`sanitize.validate_date`).
  Because stored timestamps are ISO-8601, the window filter is a lexicographic
  string compare on the date prefix — no datetime arithmetic. `store` gained
  `assessments_for_use_case` (newest-first).
- **Command.** `iga trend --use-case … [--from … --to …] [--quiet]`. Exits 1 with
  a friendly message when fewer than two qualifying assessments exist. Console
  shows ▲/▼/= per dimension and highlights changed gate transitions; `--quiet`
  emits JSON.
- **Scope note.** "History view" is satisfied by `iga list` (v0.6.0) plus `trend`;
  no separate history command was added. Trend is CLI-only — not exposed over MCP,
  since the MCP `iga_assess` tool does not persist (would need a save path first).

Tests: 246 total, 96% coverage (`test_trend.py` for the engine; trend CLI cases
and `validate_date` covered too).

---

## v0.8.0 — EU AI Act Gate-to-Article Mapping (High-Risk Systems)

**Deliberated:** 2026-03-30

### Scope decision
Map G0–G5 gate outputs to EU AI Act Title III Chapter 2 articles (Art. 9–17) for high-risk systems under Annex III. Only meaningful for `--risk-class high`. Mirrors the ISO 42001 clause mapping in v0.5.0 and is derived directly from Table `tab:framework-euaiact-gates` in the IKI-Gov book (chapter-framework).

### Data model extension
Each checklist item gains an `eu_ai_act_articles` field: list of article references applicable at that gate for high-risk systems (e.g. `["9", "10", "17"]`). Field is empty for non-high-risk items.

**Gate-to-article mapping — transcribed verbatim from the book (verified 2026-06-02
against `tab:framework-euaiact-gates` in `chapter-framework.tex`; EN and DE editions
identical). Use this as the authoritative source for the v0.8.0 data model — do NOT
re-derive it.** Legend in the book: the listed articles are the *primary* evidence
obligation typically due at that gate (the matrix also notes supporting/preparatory
relevance, ○, which is not enumerated here).

| Gate | Phase | Primary Articles (high risk) | Typical evidence at gate |
|---|---|---|---|
| G0 | Project start | Art. 9 §1 (risk management system — establishment); Art. 17 §1 lit. a (QMS — compliance strategy) | Risk classification per Annex III; ownership document; business case with high-risk designation |
| G1 | Data/concept approval | Art. 10 §2–3 (data governance, quality criteria for training/validation data); Art. 9 §2 lit. a–b (risk identification) | Data documentation; provenance and purpose-limitation evidence; risk register v1 |
| G2 | Model approval | Art. 9 §2 lit. c–d (risk assessment, risk control measures); Art. 11 + Annex IV (technical documentation, ongoing); Art. 15 §1–3 (accuracy, robustness, cybersecurity) | Model card; segmented validation records; fairness/robustness tests; updated risk register |
| G3 | Production approval | Art. 11 + Annex IV (complete, *before* placing on market); Art. 13 §1–2 (transparency, usage information); Art. 14 §1–4 (human oversight: measures and training); Art. 17 §1 (QMS operational) | Complete technical documentation; user information sheet; oversight concept + training evidence; QMS approval |
| G4 | Operations review | Art. 9 §2 lit. d (monitoring of risk control measures); Art. 12 §1–2 (logging, automatic records); Art. 15 §4 (accuracy and robustness in operation) | Monitoring reports; drift analysis; incident records; log archive |
| G5 | Decommissioning | Art. 11 §3 (documentation retention: 10 years after decommissioning); Art. 17 §1 lit. k (QMS — closure procedure) | Archiving evidence; deletion and disposal record; closed risk file |

For the v0.8.0 data model, encode this as a gate→articles table (e.g.
`EU_AI_ACT_ARTICLES_BY_GATE`) keyed G0–G5, mirroring `ISO_CLAUSES_BY_ITEM`. Because
the book maps articles to **gates** (not to individual checklist items), the
`eu_ai_act_articles` per-item field is optional — the cleaner implementation drives
the `euaiact-gap` command directly from the gate→article table plus the existing
gate-readiness engine, no per-item field required.

### New command
```bash
iga euaiact-gap --use-case "fraud-scoring" --affirm S1,S2,D1 --risk-class high --lang en
```

Output: per-article coverage table for high-risk obligations, showing which gate evidence covers each article and which gaps remain. Only available with `--risk-class high`; exits with warning if called for low/medium risk.

### Output format
```
EU AI Act High-Risk Compliance Gap — fraud-scoring  [risk: HIGH]

Article  Obligation                      Gate     Status
Art. 9   Risk management system          G0–G4    PARTIAL — G2 risk controls not affirmed
Art. 10  Data governance                 G1       OPEN
Art. 11  Technical documentation         G2–G3    BLOCKED — G3 not reached
Art. 13  Transparency / user info        G3       BLOCKED — G3 not reached
Art. 14  Human oversight                 G3       BLOCKED — G3 not reached
Art. 15  Accuracy, robustness            G2, G4   PARTIAL — G2 robustness test not affirmed
Art. 17  Quality management system       G0, G3   PARTIAL — G3 QMS release not affirmed
```

### Dependency
Requires v0.5.0 (ISO mapping) and v0.6.0 (persistence) as prerequisites; can be built independently if session-only mode is used.

### Implementation (2026-06-03)

Built session-only (no persistence dependency needed). **Data model decision:**
the book maps articles to *gates*, not items, so the per-item `eu_ai_act_articles`
field from the original deliberation was dropped in favour of a gate→article table.

- **`euaiact.py`.** `EU_AI_ACT_ARTICLE_GATES` is the book's `tab:framework-euaiact-gates`
  table *inverted* to article→gates (Art. 9: G0,G1,G2,G4; 10: G1; 11: G2,G3,G5;
  12: G4; 13: G3; 14: G3; 15: G2,G4; 17: G0,G3,G5), transcribed verbatim and
  verified. `evaluate_euaiact(gate_results)` derives each article's status from
  its gates: OPEN (all gates OPEN), BLOCKED (all BLOCKED), else PARTIAL, with the
  non-OPEN gates listed.
- **EU AI Act coverage is a *view* over gate readiness** — no new evaluation; it
  consumes `evaluate_all_gates` output. High-risk only: gates are evaluated at
  `risk_class="high"` (strict implied).
- **Command.** `iga euaiact-gap` (console table or `--quiet` JSON); exits 1 with a
  warning for non-high risk. New MCP tool `iga_euaiact_gap` (6 tools total).
- No `checklist.py` change (gate-level, not per-item).

Tests: 266 total, 96% coverage (`test_euaiact.py` for the engine, CLI + MCP cases).

**v0.1.0–v0.8.0 shipped.** Forward roadmap (v0.9.0+) below.

---

## v0.9.0 — Evidence-Pack Export: Signed, Audit-Ready Bundle

**Deliberated:** 2026-06-03

### Scope decision
Produce a self-contained, tamper-evident evidence bundle from an assessment so it
can be handed to an auditor/regulator as a versioned record. Builds on v0.4.0
(report export). No heavy runtime deps in the core; PDF rendering stays an optional
extra.

### New command
```bash
iga export --use-case "fraud-scoring" --affirm S1,S2,D1 --risk-class high \
    --bundle ./audit/fraud-scoring/        # writes a directory (or .zip with --zip)
```

### Bundle contents
- `report.md` + `report.json` (existing renderers).
- `manifest.json` — provenance: tool version, UTC timestamp, **content hashes**
  (sha256) of each artifact, the checklist content hash, and the version of each
  framework mapping used (ISO 42001, EU AI Act — see v0.10.0 content-pack versions).
- Optional `report.pdf` (only with the PDF extra installed).
- Optional detached signature over `manifest.json` (sigstore/minisign) — deferred;
  the hash manifest is the baseline integrity mechanism.

### Data-model surface
Expose a stable content-version/hash API: `checklist` content hash + per-mapping
versions, so any report can cite exactly which inputs produced it. Reproducible:
the same answers + same content versions produce an identical manifest (modulo
timestamp).

### Platform decision — drop Python 3.9 (added 2026-06-04)

**Decision:** v0.9.0 raises the minimum supported runtime to **Python 3.10+**.
`requires-python` becomes `>=3.10`, the `3.9` Trove classifier and the `3.9` CI
matrix entry are removed, and the `mcp` extra's `python_version >= '3.10'` marker
becomes unconditional (the core already requires 3.10).

**Rationale (from the v0.8.1 security audit, finding M-2):** the security-patched
`urllib3` line (2.7.0+) dropped Python 3.9, so on 3.9 the dev/audit dependency
chain (`pip-audit` → `requests` → `urllib3`) stays pinned to the vulnerable
`urllib3 2.6.3` with no 3.9-compatible fix available. Dropping 3.9 lets the entire
locked tree — including the dev/CI toolchain — resolve to patched releases and
removes the only residual advisory from the audit. Python 3.9 also reaches
upstream end-of-life in October 2025, so this aligns the project with supported
runtimes. It additionally simplifies the codebase (no more 3.9-vs-3.10 dependency
markers; `from __future__ import annotations` boilerplate can be revisited).

**Migration note:** no API or behaviour change for users on 3.10+. Users still on
3.9 must upgrade their interpreter; this is a packaging-metadata change, announced
in the v0.9.0 release notes and reflected in `SECURITY.md` supported versions.

---

## v0.10.0 — Pluggable Regulatory-Content Provider Interface

**Deliberated:** 2026-06-03

### Scope decision
Decouple the regulatory mapping *content* (ISO clause matrix, EU AI Act article
table, future frameworks) from the engine so mappings can be shipped and updated
as versioned **content packs** independently of an engine release. Backwards
compatible: the built-in baseline packs reproduce current behaviour exactly.

### Content-pack schema
A pack (JSON/TOML) declares: `framework_id`, `version`, `languages`, target
metadata (clause/article/control names + obligations per language), and the
mapping (`item → targets` and/or `gate → targets`). Carries a `version` + content
hash (consumed by the v0.9.0 manifest).

### Provider interface
- Engine loads **built-in packs** (current ISO/EU AI Act, bundled in-repo) plus
  optional **external packs** from a configured location (`~/.iga/content/` or
  `IGA_CONTENT_PATH`).
- `iga content list` shows installed packs + versions; gap commands resolve their
  mapping from the active pack.
- Generalises `iso.py`/`euaiact.py` to read a pack rather than a hard-coded dict.

### Decision
Built-in baseline packs remain in-repo. The interface is a clean extensibility
point; whether additional packs are distributed in-repo or out-of-band is an
operational choice, not an engine concern.

---

## v0.11.0 — NIST AI RMF Mapping + Framework-Agnostic Core

**Deliberated:** 2026-06-03

### Scope decision
Add **NIST AI RMF** (functions Govern/Map/Measure/Manage + categories) as a mapping
target, proving the v0.10.0 content-pack core, and generalise the gap commands.

### Changes
- Refactor `iso.py` + `euaiact.py` into a single **generic coverage engine** over a
  content pack (item→target or gate→target), parameterised by framework.
- New command `iga framework-gap --framework {iso42001|euaiact|nist-ai-rmf}`; keep
  `iso-gap` and `euaiact-gap` as thin compatibility aliases.
- New `nist-ai-rmf` content pack mapping checklist items / M-dimensions to NIST
  functions and categories (qualitative, mirroring the ISO matrix's relevance grading).

### Dependency
Requires v0.10.0 (content-pack interface). Establishes the pattern for adding
further frameworks (UK, sectoral) as content packs with no engine change.

---

## v0.12.0 — Remote MCP Endpoint: Org Context and Auth

**Deliberated:** 2026-06-03

### Scope decision
Run the MCP server over a network transport (HTTP/SSE) with multi-tenant org
context and authentication, so AI platforms/agents can call governance tools
against a persistent, org-scoped store — extending the stdio server (v0.2.0) and
the local SQLite store (v0.6.0).

### Changes
- **Transport:** FastMCP streamable-HTTP / SSE (supported by the `mcp` SDK), behind
  token/OAuth auth.
- **Org-scoped persistence:** extend `store.py` from a single local SQLite file to
  per-org isolation (separate DB/schema per tenant); `portfolio`/`trend` operate over
  the org store.
- **Tool surface:** same tools (`assess`, `check_gate`, `iso_gap`, `euaiact_gap`,
  `framework_gap`) plus org-scoped `portfolio`/`trend`.

### Security
Authn/z per request; **per-org rate limiting** (generalises the per-session abuse
guard); TLS required; structured audit logging (no use-case content). Deployable as
a container; deferred network deps kept in an optional extra.

### Dependency
Builds on v0.2.0 (MCP), v0.6.0 (persistence), v0.10.0 (content packs).

---

## v0.13.0 — External Evidence-Backed Affirmation (presidio-hardened-* control integration)

**Deliberated:** 2026-06-08

### Motivation
ikigov scores governance maturity from **human self-attestation**: each checklist item is
a boolean an assessor affirms (`--affirm S1,S2,D1,…`). The inherent limitation of any
maturity/GRC tool is that an affirmation is *trust, not proof*. Within the
`presidio-hardened-*` suite, ikigov is the **governance spine** and the peer tools
(`presidio-hardened-x402`, `presidio-hardened-ai`) are **technical controls** that already
emit tamper-evident, signed records. This version lets the spine *consume* that signed
evidence to back the subset of checklist items that are technical controls — upgrading an
affirmation from "someone ticked it" to **affirmed-by-evidence** (verifiable against the
producing control's ledger). This is the suite-level differentiator: a machine-verifiable
conformity trail rather than a questionnaire.

First evidence producer: `presidio-hardened-ai` (training-time privacy: PII-scrub +
data-lineage ledger, differential-privacy ε accounting, immutable HMAC-chained training
log). ikigov defines the **consuming interface** here; the producer owns the item→evidence
mapping in its own repo. The `EvidenceRef` schema below is the integration contract.

### Scope decision
ikigov gains the ability to accept, record, optionally verify, and render external evidence
references attached to affirmations. **No change to the scoring formula or gate logic** —
evidence-backed items count as affirmed exactly as self-affirmed ones do. The new
information is *provenance* (how an affirmation is substantiated) and an orthogonal
**evidence-coverage** quality signal. Verification is offline/local by default (hash and
detached-signature check against producer artifacts the user supplies); no network trust.

### Data model extension — `EvidenceRef`
An affirmed item may carry zero or more evidence references. An `EvidenceRef` is
commitments-only (no PII, no raw organisational data — consistent with the family
structural-only logging rule):

| Field | Description |
|---|---|
| `item_id` | Checklist item the evidence substantiates (e.g. `D1`, `O5`) |
| `source` | Producing control, e.g. `presidio-hardened-ai` |
| `source_version` | Producer tool version (for reproducibility) |
| `ledger_ref` | Opaque pointer/URI into the producer's audit ledger (commitment, not content) |
| `content_hash` | `sha256` over the evidenced artifact/ledger entry |
| `signer` | Signer identity (key id) for the detached signature |
| `signature` | Detached signature over `content_hash` (reuses the v0.9.0 sigstore/minisign mechanism) |
| `claimed_at` | UTC timestamp |

Each per-item answer gains a `provenance` field with three states:
`self` (boolean affirmation, current behaviour and the default),
`evidence` (a well-formed `EvidenceRef` is attached),
`evidence-verified` (its `content_hash`/`signature` were checked and passed).

### Interface
```bash
# Drive affirmations from a signed evidence file (or directory of evidence packs).
# An item with valid evidence is affirmed and tagged provenance=evidence(-verified).
iga assess --use-case "fraud-scoring" --risk-class high \
    --affirm S1,S2,S3 --evidence ./evidence/hardened-ai.json

# Verify evidence hashes/signatures against producer artifacts (fail-closed).
iga verify --evidence ./evidence/hardened-ai.json --trust ~/.iga/trust/

# Require cryptographic evidence for gate-critical technical-control items at high risk
# (mirrors the existing --strict skip policy; powerful as a release gate).
iga gate --gate G4 --risk-class high --affirm … --evidence … --require-evidence \
    --assert-gate G4
```
- New MCP tool `iga_assess_with_evidence` (or an optional `evidence` argument on
  `iga_assess`) so an agent can chain `presidio-hardened-ai → ikigov` in one session,
  passing signed refs through without a file hop.
- Report (`iga report`) and JSON payload: each answer carries its `provenance` and any
  `evidence` block; the v0.9.0 manifest records which affirmations were evidence-backed and
  which were verified.

### Evidence coverage (new, orthogonal signal)
The maturity score answers *"how complete?"*; evidence coverage answers *"how verifiable?"*.
Reported alongside M1–M6 (not folded into them):
```
evidence_coverage = affirmed gate-critical items that are evidence-backed
                    / affirmed gate-critical items          × 100
verified_coverage = … that are evidence-verified / …        × 100
```
Indicative item→evidence map the first producer (`presidio-hardened-ai`) can satisfy —
**confident:** `D1` (data inventory & lineage), `D4` (DPIA inputs: DP ε + scrub logs),
`O5` (immutable audit log); **partial credit (label as such):** `T5` (pipeline/dependency
security), `T4` (DP-bounded robustness), `D2` (data-quality profiling), `I4` (lifecycle
documentation). These cluster in M2/M4/M5 — the dimensions weakest under self-attestation.
The producer owns and versions this map; ikigov treats it as opaque per `EvidenceRef`.

### Security
- **Fail-closed verification.** A missing/invalid hash or signature downgrades the item to
  `self` (or denied under `--require-evidence`); it never silently passes as verified.
- **Commitments only.** `EvidenceRef` carries hashes/URIs, never PII or raw org data. All
  fields are validated/sanitised (length bounds, allowed `ledger_ref` schemes, hex-format
  hash/signature) like every other input; HTML/JSON-escaped on export.
- **Local trust.** Signer public keys are configured locally (`~/.iga/trust/` or
  `IGA_TRUST_PATH`); no network key resolution by default. Reuses the v0.9.0 detached-
  signature primitive rather than introducing a second mechanism.
- **Structured logging.** New events `iga-evidence-attached` / `iga-evidence-verified`
  record item ids and verification result only — no content, no `ledger_ref` value.

### Dependency
Builds on **v0.9.0** (signed evidence-pack: hash manifest + detached-signature baseline)
and **v0.2.0** (MCP). Independent of v0.10.0–v0.12.0. May be sequenced immediately after
v0.9.0 (see roadmap sequencing note). The `EvidenceRef` schema is the cross-repo contract
with `presidio-hardened-ai`; pin its version in both repos' `PRESIDIO-REQ.md` once agreed.

### Implementation (2026-06-08)

Pulled forward ahead of v0.9.0–v0.12.0 to close the `presidio-hardened-ai` loop
end-to-end. Resolved as follows:

- **`evidence.py`.** `EvidenceRef` (contract fields), `load_evidence` / `parse_document`
  (schema `presidio-hardened/evidence-ref@1`), `load_trust_store`, `verify_ref`
  (HMAC-SHA256, timing-safe, fail-closed), `classify` (per-item `evidence` /
  `evidence-verified` provenance + `require_verified`), `merge_provenance`, and
  `evidence_coverage`. **Self-contained signature primitive** (the v0.9.0 detached-
  signature baseline is not yet built); the wire format byte-matches the producer's
  `sign_evidence` and is locked by a golden test vector.
- **`assess`** gained `--evidence` / `--trust` / `--require-evidence`. Evidence affirms
  items (but never an item explicitly `--skip`-ped); the JSON payload carries per-item
  `provenance` and an `evidence_coverage` block (both additive — legacy schema unchanged
  when the flags are absent). New **`iga verify-evidence`** command (exit 1 if any ref
  fails). New MCP tool **`iga_assess_with_evidence`** for agent chaining.
- **Scope note.** `evidence_coverage` is computed over all affirmed items (every checklist
  item is gate-mapped). The stricter "gate-critical technical items *must* carry evidence"
  variant of `--require-evidence`, and a `~/.iga/trust/` directory store (only the inline
  `--trust` file is supported now), are deferred. Verification reuses an inline HMAC key
  store pending the v0.9.0 public-key (sigstore/minisign) baseline.

Tests: full suite green (302 passed); `test_evidence.py` covers parse/verify/classify/
coverage, the producer-cross-validated golden vector, the `assess`/`verify-evidence` CLI,
and the MCP tool.

---

## v0.14.1 — Key Rotation (Multiple Keys per Signer)

**Deliberated:** 2026-06-08

### Scope decision
Support **key rotation** for the public-key signing baseline: a signer's trust entry may
list **several** keys (`"public_key": ["<new>", "<old>"]`, likewise `"key"` for HMAC), and
`verify_ref` succeeds if the signature matches **any** of them. This lets an operator add a
new key, switch the producer to it, and retire the old one — with an overlap window during
which evidence signed under either key still verifies. Verifier-only: the producer is
unchanged (it just signs with its current key). Trust entries normalise to `{alg, keys}`
(a list); a bare string or single value still works.

### Acceptance criteria (each maps to a test)
1. A ref verifies when its key is one of several listed (Ed25519 and HMAC). *(test_evidence)*
2. Fail-closed when none of the listed keys match. *(test_evidence)*
3. An empty key list is rejected at load. *(test_evidence)*
4. Single-value and bare-string entries remain back-compatible. *(test_evidence)*

### Security
No key-id is added to `EvidenceRef` (the contract is unchanged); the verifier tries each
listed key. Trying N keys is N Ed25519 verifications per ref — fine for the small key sets
rotation needs. Rotation is the verifier's policy; revocation = remove the key from the
trust store.

---

## v0.14.0 — Public-Key (Ed25519) Evidence Verification

**Deliberated:** 2026-06-08

### Scope decision
Verify **Ed25519** public-key signatures on evidence, not just shared-secret HMAC — the
consumer half of the suite's move to asymmetric signing (producer:
`presidio-hardened-ai` v0.7.0). The **signing algorithm is a property of the trust
store**, so the `EvidenceRef` contract is unchanged: a trust entry is either a bare HMAC
secret string (back-compat) or an object `{"alg": "hmac-sha256"|"ed25519",
"key"|"public_key": "<hex>"}`. `verify_ref` dispatches on the entry's algorithm.

### Components
`evidence.py`: `load_trust_store` now normalises each entry to `{alg, material}`
(accepting string or object), `verify_ref` dispatches HMAC vs Ed25519, and
`_verify_ed25519` verifies via `cryptography` (lazy import; `load_trust_store` fails fast
with a clear message if an Ed25519 entry is present without the `[crypto]` extra). New
`[crypto]` extra; `cryptography` added to `[dev]` so the tests run in the default lane.

### Acceptance criteria (each maps to a test)
1. `load_trust_store` accepts string (→HMAC) and object (`{alg, public_key}`) entries and
   rejects unknown algorithms. *(test_evidence)*
2. `verify_ref` cross-validates the producer's Ed25519 **golden vector**; fail-closed on
   wrong public key or tampered content. *(test_evidence)*
3. Bare-string trust entries still verify HMAC (back-compat). *(test_evidence)*
4. `classify` marks Ed25519-verified items `evidence-verified`; the `assess --trust` CLI
   honours object trust entries. *(test_evidence)*

### Security
Asymmetric trust: a verifier holds only public keys; no shared secret with the producer.
Verification reuses the same canonical `{content_hash, signer}` message as HMAC, so the
two are wire-compatible. Fail-closed throughout; Ed25519 entries without `[crypto]` raise
at load rather than silently failing verification.

### Compatibility
`load_trust_store` now returns normalised `{alg, material}` entries (was raw strings);
`verify_ref` still accepts bare-string trust values directly, so existing callers work.

---

## v0.18.0 — Remote MCP Endpoint (realises v0.12.0)

**Deliberated:** 2026-06-08

### Scope decision
Generalise the stdio MCP server (v0.2.0) and the local SQLite store (v0.6.0) to a
multi-tenant, networked deployment. Per the SDLC's "verify what ships" principle, the
**verifiable core** is implemented and fully tested in `remote.py`; the HTTP/SSE
transport is a thin, lazily-imported layer behind the existing `[mcp]` extra (kept out of
the dependency-light test lane, exactly like the stdio server's `build_server`).

### Components
`remote.py`: token auth (`hash_token`, `load_token_store`, `resolve_org` — timing-safe,
fail-closed), per-org store isolation (`org_db_path` + the `org_store` context that scopes
the shared store via `IGA_DB_PATH`), and `OrgRateLimiter` (per-org cap generalising the
session guard). `serve()` wires these into FastMCP streamable-HTTP; `iga-mcp-remote`
console script.

### Acceptance criteria (each maps to a test)
1. `resolve_org` returns the org for a valid bearer token and **None** otherwise
   (wrong/empty token), fail-closed. *(test_remote)*
2. Token store rejects non-objects and non-sha256 digests; tokens are stored hashed. *(test_remote)*
3. `org_db_path` is per-org and rejects path traversal via the use-case allow-list. *(test_remote)*
4. `org_store` isolates persistence — one org never sees another's assessments — and
   restores `IGA_DB_PATH` afterwards. *(test_remote)*
5. `OrgRateLimiter` caps per org independently; `enforce` raises past the cap. *(test_remote)*

### Security
Bearer tokens are stored only as sha256 hashes (`{org: token_hash}`); auth is timing-safe
and fail-closed. Org ids are allow-list validated, so a tenant cannot escape its store
directory. Per-org rate limiting bounds abuse. Transport specifics (TLS termination, bind
address) are deployment configuration. The auth/isolation/limit invariants are *defined and
unit-tested* here; **wiring them into the running server is v0.19.0.**

### Completes the roadmap
With v0.18.0 the planned v0.9.0–v0.12.0 line is fully delivered (as v0.15.0–v0.18.0),
alongside the pulled-forward v0.13.0–v0.14.1.

---

## v0.19.0 — Remote Endpoint Enforcement (hardening of v0.18.0)

**Deliberated:** 2026-06-08

### Scope decision
v0.18.0 shipped correct, tested primitives but `serve()` did not actually enforce them, and
`org_store` scoped the DB via a process-global env var (unsafe under concurrent requests).
v0.19.0 closes both: a pure-ASGI `OrgAuthMiddleware` wraps the FastMCP streamable-HTTP app
and authenticates + rate-limits every request before it reaches the MCP app; store scoping
moves to a per-task context var.

### Components
`store.use_db_path`/`reset_db_path` + a `_db_path_override` context var (precedence: context
override → `IGA_DB_PATH` → default), so scoping is request-local and concurrency-safe.
`remote.OrgAuthMiddleware` (pure ASGI, not `BaseHTTPMiddleware`): bearer→org via
`resolve_org` (401 on failure), `OrgRateLimiter.check` (429 over cap), then binds the org DB
path for the request. `serve()` runs `build_asgi_app()` under uvicorn.

### Acceptance criteria (each maps to a test)
1. Missing or invalid bearer token → 401; the downstream app is never reached. *(test_remote)*
2. Valid token → 200, with the store bound to that org's DB for the in-request task. *(test_remote)*
3. Per-org rate limit → 429 past the cap; independent per org. *(test_remote)*
4. The DB-path override is context-local (a copied context sees it; the outer does not). *(test_remote)*

### Security — isolation scope and known limitation
Authentication and rate limiting are enforced unconditionally (rejection precedes the MCP
app). The per-request context-var DB binding, however, does **not** reach MCP tools: the
streamable-HTTP transport runs tool execution in a separate **session** task. This is safe
today because all registered MCP tools are **stateless** (no store access). Exposing any
store-backed tool remotely would require binding the org to the MCP *session* — explicitly
deferred. Documented in SECURITY.md and in `OrgAuthMiddleware`.

---

## v0.17.0 — NIST AI RMF Content Pack (realises v0.11.0)

**Deliberated:** 2026-06-08

### Scope decision
Add **NIST AI RMF 1.0** as a built-in content pack on the v0.16.0 pack core — the payoff
of that architecture: a new framework is **data, not code**. The pack maps the 25
checklist items to the four NIST functions (GOVERN / MAP / MEASURE / MANAGE) and is served
through the existing generic `iga framework-gap --framework nist-ai-rmf` with **no engine
change**. The "framework-agnostic core" the original v0.11.0 called for already landed in
v0.16.0; this version exercises it with a third framework.

### Mapping (initial, qualitative — to be refined by the framework author)
Every checklist item is assigned to exactly one function (mirrors the ISO matrix's
relevance grading; versioned so refinements are tracked via the pack `content_hash`):
GOVERN = S1–S3, D3, I1–I3, I5; MAP = S4, S5, D1, D4, D5; MEASURE = T1–T3, D2, O1, O2;
MANAGE = T4, T5, O3–O5, I4.

### Acceptance criteria (each maps to a test)
1. The pack maps **all 25** items, each exactly once. *(test_content)*
2. `nist-ai-rmf` is in `builtin_packs()` and `load_packs()`. *(test_content)*
3. Generic coverage runs (a fully-affirmed function is COVERED, an unaffirmed one GAP). *(test_content)*
4. `iga framework-gap --framework nist-ai-rmf` returns coverage over the four functions. *(test_content)*

---

## v0.16.0 — Pluggable Regulatory-Content Packs (realises v0.10.0)

**Deliberated:** 2026-06-08

### Scope decision
Decouple a framework's *mapping content* (which checklist items or lifecycle gates
evidence each clause/article/control) from the coverage engine, so a new framework is
added as **data, not code**. A `ContentPack` maps each target (clause/article id) to the
sources that evidence it — checklist items (`mapping_kind='item'`) or gates
(`mapping_kind='gate'`) — and a single generic engine computes covered/partial/gap over
any pack. Built-in packs reproduce the ISO/IEC 42001 and EU AI Act mappings **exactly**
(cross-checked against the legacy `iso`/`euaiact` engines); external packs load from
`IGA_CONTENT_PATH` (or `~/.iga/content/`) and may override a built-in by `framework_id`.

### Non-breaking
The legacy `iso-gap` / `euaiact-gap` commands are unchanged (still pass). The new pack
core is exposed through `iga content-list` and a generic `iga framework-gap --framework
<id>`; a regression test asserts the packs produce identical coverage to the legacy
engines. (Folding `iso-gap`/`euaiact-gap` into the generic engine as thin aliases is left
to a later version to keep this change risk-free.)

### Components
`content/pack.py` (`ContentPack`, validate, (de)serialise, `content_hash`),
`content/coverage.py` (generic `evaluate_coverage`), `content/builtin.py` (ISO + EU AI Act
packs from existing constants), `content/loader.py` (built-in + external packs). CLI:
`iga content-list`, `iga framework-gap`.

### Acceptance criteria (each maps to a test)
1. Pack `content_hash` is stable; `validate_pack` rejects bad kind/targets. *(test_content)*
2. ISO pack coverage matches `evaluate_iso_coverage` across affirmed sets. *(test_content)*
3. EU AI Act pack coverage matches `evaluate_euaiact` (OPEN↔covered, BLOCKED↔gap,
   PARTIAL↔partial). *(test_content)*
4. A gate-mapped pack without gate results fails closed (`ContentError`). *(test_content)*
5. External packs load from `IGA_CONTENT_PATH` and override built-ins; malformed packs
   raise. *(test_content)*
6. CLI `content-list` lists built-ins; `framework-gap` works for both kinds; unknown
   framework exits 1. *(test_content)*

### Sets up
v0.17.0 (NIST AI RMF) adds a content pack and works through `framework-gap` with **no
engine change**.

---

## v0.15.0 — Signed Evidence-Pack Export (realises v0.9.0)

**Deliberated:** 2026-06-08

### Scope decision
Implement the long-planned **evidence-pack export** (roadmap label v0.9.0; released as
v0.15.0 since the package version has overtaken the old label). `iga export` writes a
self-contained, tamper-evident bundle of an assessment — `report.md` + `report.json` plus
a `manifest.json` that **sha256-hashes every artifact** and records the
`framework_content_hash` (the checklist text + ISO matrix + EU AI Act gate→article table
in force). `iga verify-bundle` re-hashes the artifacts against the manifest. The hash
manifest is the integrity baseline; an **optional detached HMAC signature** over the
manifest (`--sign-key`) seals the bundle as a whole.

### Components
`bundle.py`: `framework_content_hash`, `build_manifest`, `write_bundle` (directory or
`--zip`), `verify_bundle` (fail-closed re-hash + optional signature check). CLI: `iga
export --bundle DIR [--zip] [--sign-key KEY]` and `iga verify-bundle --bundle … [--sign-key …]`.

### Acceptance criteria (each maps to a test)
1. `framework_content_hash` is stable; the manifest carries per-artifact sha256 + the
   framework hash. *(test_bundle)*
2. A written bundle verifies; tampering any artifact makes `verify_bundle` fail-closed. *(test_bundle)*
3. With `--sign-key`, the manifest seal verifies; a wrong key fails. *(test_bundle)*
4. Directory and `.zip` bundles both round-trip; a bundle without a manifest raises. *(test_bundle)*
5. CLI `export` then `verify-bundle` succeed; a tampered member makes `verify-bundle` exit 1. *(test_bundle)*

### Deferred (per the original v0.9.0 deliberation)
PDF rendering (heavy dep) and a public-key (Ed25519/sigstore) manifest signature — the
HMAC seal is the baseline; Ed25519 signing can reuse the v0.14.x crypto path later.

---

## v0.19.1 — Producer-Compatibility Sync (presidio-hardened-ai v0.30.0)

The producer `presidio-hardened-ai` advanced through its **P4 consortium** arc (v0.21–v0.30):
malicious-secure secure aggregation, **guaranteed output delivery** (honest-majority robust
secret-sharing), **L∞/L2 bounded-norm** input validation (DP clip sensitivity *proven*), a
pluggable Ristretto255+Bulletproofs proof backend, whole-consortium proof aggregation, and a
Byzantine-ML robustness gate.

**No ikigov engine change is required** — and that is the point. A consortium round emits the
**same `D4` `EvidenceRef@1`** (an aggregate-only commitment + Ed25519 signature) as a
single-node `dp-train`; ikigov treats the producer's item→evidence map as opaque (the v0.13.0
decision), so it verifies consortium evidence with the existing `verify_ref` path. The producer
hardened P4 across six ADRs without touching the cross-repo contract. Interop is validated
end-to-end (a GOD round's D4 verifies in ikigov with only the public key) and pinned by the
`test_consortium_round_d4_evidence_verifies` regression test.

---

## v0.19.2 — Dependency Maintenance + Python 3.10 Floor

Resolves the open Dependabot PRs (which were cut from a stale base and would have regressed
main) by **applying their intended updates to current main** rather than merging the branches:
dependency floors raised (`typer>=0.23.2`, `rich>=14.3.4`, `prompt_toolkit>=3.0.52`,
`pytest>=8.4.2`, `ruff>=0.15.10`), GitHub Actions bumped (`actions/checkout@v6`,
`codecov/codecov-action@v7`). The obsolete `typer[all]` extra is dropped (modern `typer`
bundles rich/shellingham).

**CI fix.** The `Tests` workflow was red on the **Python 3.9** matrix leg: the project's modern
CLI stack (`click`/`typer`/`pytest` latest) now requires Python ≥3.10, so 3.9 can no longer
resolve a consistent dependency set. The 3.10 minimum was already the documented intent (the
v0.9.0 platform decision; the `mcp` extra requires 3.10), but `requires-python` and the matrix
were stale at 3.9. This enforces `requires-python = ">=3.10"` and tests 3.10–3.12 — green on
3.10/3.11/3.12 (verified in a clean venv). The stale Dependabot branches are superseded and can
be closed.

---

## v0.20.0 — Classificator Bridge (eai-classification/v1)

**Deliberated:** 2026-06-11

### Scope decision

Implement the "classificator bridge" (task T-B1): a producer-agnostic interchange
layer between the Enterprise AI Classification Framework 6×6 matrix model and the
IKI-Gov assessment engine. Multiple producers will emit classifications conforming
to this model (the eai-classificator research artefact AND partner survey
tooling). The interface is **keyed to the model**
(schema version `eai-classification/v1`), not to any one tool's output format.

### Components

**`classification.py`** — Interchange schema `eai-classification/v1`:
- Parses+validates a JSON document: `{"schema", "producer" (opt), "use_cases": []}`.
- Each use case: `id` (same pattern as `validate_use_case`), `type` (T1–T6), `level`
  (L1–L6), optional `name`/`ecosystem`/`confidence`/`rationale`/`tags`.
- `ecosystem` flag: L6 is the non-ordinal overlay regime. `ecosystem=true` normalises
  effective level to L6 regardless of declared base level; `level=L6 + ecosystem=false`
  is a contradiction → rejected.
- Forward-compatible: unknown fields at any level are silently ignored. Unknown schema
  versions fail closed with a clear error naming the supported version.
- Hard limits: max 200 use cases, max 1 MB document, length-capped fields.

**`content/profile.py`** — `ProfilePack` frozen dataclass (v0.16.0 pattern):
- `pack_kind="classification-profile"`, `framework_id`, `version`, `profiles` dict
  keyed by cell id `T{1-6}.L{1-6}` — all 36 cells required (`validate_profile_pack`
  enforces completeness).
- Per-cell profile: `risk_presumption` (low/medium/high), `strict` (bool), `obligations`
  (list of framework ids), `notes` ({lang: str}).
- `content_hash` over canonical JSON (sha256, deterministic). `profile_pack_from_dict`
  / `profile_pack_to_dict` for serialisation.

**`content/profile_builtin.py`** — Built-in default pack:
- **DRAFT mapping semantics — founder review required before merge.**
- Risk presumption by autonomy: L1–L2 low, L3–L4 medium, L5 high, L6 high+strict=true.
- Type modifiers: T6 Physical floors at medium from L2, high from L4; T1 Decision floors
  at medium from L3.
- All cells: obligations `["iso42001","euaiact"]`, bilingual de/en notes per level band.

**`content/loader.py`** (extended):
- `load_external_profile_packs` / `load_profile_packs`: loads ProfilePacks from
  `IGA_CONTENT_PATH` discriminated by `pack_kind="classification-profile"`.
- `load_external_packs` updated to skip profile packs, keeping ContentPack loading
  unchanged (non-breaking).
- Same `framework_id` override: external pack replaces built-in.

**`classify.py`** — `iga classify` sub-app:
- `iga classify ingest --file <path> [--lang] [--quiet] [--profile <framework_id>]`:
  validate document → resolve each use case → cell → profile; human table or
  machine JSON (with `pack content_hash` and producer echo).
- `iga classify assess --file <path> --select <id> [--lang] [--quiet] [--save]
  [--affirm] [--skip] [--strict] [--evidence] [--trust] [--require-evidence]
  [--profile <framework_id>]`: resolve profile → run full existing pipeline
  (`compute_scores`, `evaluate_all_gates`, `render_json`, `store.save_assessment`,
  `log_security_event`). Profile `strict=true` cannot be loosened by flags.
  Security event `iga-classify-assess` logs cell + pack `content_hash`.

### Schema file

`schemas/eai-classification.v1.schema.json` — JSON Schema draft/2020-12 for external
partner producers. Documentation-grade; the Python parser is authoritative.
`jsonschema` is not a declared project dependency (test validates against parser only).

### Security

- All document and field inputs are validated/length-bounded before use (fail-closed).
- Profile `strict=true` cannot be loosened; flags can only further tighten.
- `log_security_event("iga-classify-assess")` includes cell id and pack `content_hash`
  (structural metadata only — no document content).
- Same session rate-limit and security posture as existing `iga assess`.

### Acceptance criteria (each maps to a test in `test_classify.py`)

1. Schema happy path — minimal and full-field documents parse correctly.
2. Unknown top-level and use-case fields are silently ignored.
3. Unknown schema version fails closed with a clear error message.
4. Every malformed field (bad id, type, level, confidence, rationale, tags, name) → error.
5. `ecosystem=true` normalises level to L6; `base_level` retains the declared level.
6. `level=L6 + ecosystem=false` → contradiction error.
7. Size limits: max 200 use cases, max 1 MB document.
8. ProfilePack completeness: 36 cells required; missing cells → ProfileError.
9. `content_hash` is stable (deterministic across two identical constructions).
10. Builtin draft semantics: T6.L4→high, T1.L1→low, T1.L3→medium, all L6→strict+high.
11. Obligations and bilingual notes present in all 36 cells.
12. External override: a profile pack in `IGA_CONTENT_PATH` overrides the builtin.
13. Loader coexistence: ContentPacks and ProfilePacks in the same directory do not
    interfere; each loads correctly via their respective `load_*` function.
14. CLI `ingest --quiet` returns JSON with schema, producer echo, pack content_hash.
15. CLI `ingest` table renders cell, risk presumption, obligations, note.
16. CLI `assess --quiet --save --lang de` returns augmented JSON + `classification` block
    with cell, profile pack content_hash, ecosystem, producer.
17. `classify assess` with ecosystem=true use case: cell resolved as L6, strict applied.
18. `iga-classify-assess` security event logged with cell and full pack content_hash.
19. `profile_pack_from_dict` / `profile_pack_to_dict` round-trip preserves content_hash.

### Implementation (2026-06-11)

Built as specified. The existing `iga assess` behaviour is byte-identical (the classify
assess command composes the same engine functions rather than duplicating them). No
new dependencies introduced. The schema file is documentation-grade with an explicit
note that `jsonschema` is not a declared dependency; tests validate against the parser.

Tests: 419 total (61 new), 91% coverage. Full existing suite passes unchanged.

---

## v0.21.0 T-B3 — `iga workshop`: Offline Customer-Workshop Tool

**Deliberated:** 2026-06-11

### Rationale

Enterprise AI assessment workshops require:
1. **Offline operation** — many customer sites are air-gapped or have strict network
   restrictions; `pip-audit` would hang and emit inconclusive warnings.
2. **Projector-quality output** — live facilitator needs large-format, high-contrast
   Rich panels readable from the back of a room, not dense terminal tables.
3. **Signed leave-behind artifacts** — after the session the customer receives a per-use-case
   folder with a verifiable, tamper-evident set of artifacts they can file as evidence.
4. **Pre-filled answers** — facilitator can prepare `answers.json` ahead of the session
   from earlier elicitation (partner survey tooling output) so the projector walkthrough starts with
   a populated state rather than blank.

### Scope decision

New `iga workshop run` and `iga workshop verify` commands implemented in a dedicated module
(`workshop.py`) and wired into the main app as a sub-app. The commands compose existing
engine functions (`compute_scores`, `evaluate_all_gates`) — no engine duplication.

The dep-check bypass is structural: `main_callback` detects
`ctx.invoked_subcommand == "workshop"` and sets `_NO_DEP_CHECK = True` **before** the dep
check runs. The `IGA_NO_DEP_CHECK=1` env var additionally bypasses it for CI/test use.
This is the correct point-of-interception: Typer's Click wrapper evaluates the parent
callback (with `ctx.invoked_subcommand`) before any sub-app callback, so the bypass is
guaranteed to fire before `_run_dep_check_quietly()`.

### Ed25519 signing design

- Private key: raw 32-byte Ed25519 scalar in hex (64 hex chars). This is the `from_private_bytes`
  encoding required by `cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PrivateKey`.
- Key source: `--sign-key <file>` (mode-0600 check; warn not abort) or `$IGA_WORKSHOP_SIGN_KEY`
  env var. The environment path lets CI/CD inject the key without a disk file.
- Signing target: canonical JSON bytes of `manifest.json`
  (`json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`).
  Using the in-memory dict's canonical form ensures the verifier can reconstruct the exact
  signed bytes from the file on disk.
- UNSIGNED path: if no key is provided, `manifest.sig` contains `{"UNSIGNED": true}` and
  `manifest.json` carries `"UNSIGNED": true` + `"signed": false`. Workshop does **not** fail;
  a stderr warning is emitted. The operator decides whether unsigned artifacts are acceptable.
- `workshop verify --dir <use_case_dir> --pubkey <hex>`: re-hashes all artifacts, verifies
  the Ed25519 signature, returns a JSON summary and exits non-zero on any failure.
- Same `cryptography` optional extra (`[crypto]`) as `evidence.py` / `bundle.py`. No new
  dependencies.

### Manifest schema and artifact layout

Per-use-case output directory (under `--out DIR/<uc_id>/`):

```
<use_case_id>/
  report.<lang>.md      Markdown leave-behind for the customer
  report.json           Full JSON payload + classification provenance block
  manifest.json         Schema presidio-hardened/workshop-leavebehind@1
                        (per-artifact SHA-256, pack info, signed flag, timestamps)
  manifest.sig          Ed25519 detached signature (hex in JSON) or UNSIGNED marker
```

The `report.json` `payload["classification"]` block mirrors the format written by
`classify assess`, providing full classification provenance to downstream tools.

### answers.json format and validation

```json
{
  "use_case_id": {
    "affirm": ["S1", "S2"],
    "skip": ["I4"]
  }
}
```

Validated: top-level must be an object; each value must have `affirm`/`skip` as lists of
strings; all use-case IDs checked against the classification document (fail-closed on unknown
ID); all item IDs validated via `validate_item_ids` from `sanitize.py` (fail-closed on any
invalid ID). Document size-capped at 64 KiB to prevent DoS.

### Projector rendering

Rich `Panel` per use case, with:
- Large heading: use-case name in bold green, cell and risk class in cyan/yellow
- Strict-mode indicator (red if strict=True)
- Score summary row (overall maturity + per-gate readiness)
- Gate status as `Table.grid` rows with status colour coding (green/yellow/red)

Non-quiet path only; `--quiet` suppresses the projector output and proceeds to artifact
writing only (suitable for CI or batch pre-generation).

### Security

- `log_security_event("iga-workshop-run")` emits cell, risk_class, lang, selected UC ids,
  and signed flag (structural metadata only, no use-case content).
- File-permission check on `--sign-key` (mode 0600); `os.stat().st_mode & 0o777 != 0o600`
  → `typer.echo(warning, err=True)` and continue.
- All inputs validated before use (classification document via existing `classification.py`
  parser; answers.json validated field-by-field).

### Acceptance criteria (each maps to a test in `test_workshop.py`)

1. Full run produces `report.<lang>.md`, `report.json`, `manifest.json`, `manifest.sig`.
2. `manifest.json` schema matches `"presidio-hardened/workshop-leavebehind@1"`.
3. SHA-256 hashes in manifest match actual files on disk.
4. Unsigned run writes `{"UNSIGNED": true}` to `manifest.sig`, emits warning on stderr.
5. Signed run: valid Ed25519 signature round-trip with generated keypair.
6. Wrong pubkey → `workshop verify` returns failure.
7. Tampered artifact file → `workshop verify` returns failure.
8. `workshop verify` with unsigned artifact (no pubkey provided) returns `ok=True, signature=None`.
9. `answers.json` applied: affirmed/skipped items reflected in score computation.
10. Bad item id in answers.json → fails closed with error exit code.
11. Unknown use-case id in answers.json → fails closed with error exit code.
12. `--select <id>` filters to a single use case.
13. `--select <id1> --select <id2>` filters to the named use cases.
14. Non-existent `--select` id → fails closed.
15. Offline dep-check bypass: `dep_check_status` monkeypatched to raise — not called.
16. Missing classification file → fails closed.
17. Invalid JSON → fails closed.
18. Bad `--lang` value → fails closed.
19. Wrong schema version → fails closed.
20. `report.json` contains `payload["classification"]` provenance block.
21. German run: `report.de.md` contains German-language content.
22. Performance: 4-use-case medical fixture completes in < 10 seconds.
23. English run produces `report.en.md`.
24. Low-level Ed25519 sign/verify unit test (independent of CLI).
25. `$IGA_WORKSHOP_SIGN_KEY` env var used when `--sign-key` not provided.
26. German output sentinel: no "Overall maturity", "Measurement Dimensions", "Gate Readiness"
    under `--lang de`.

### Implementation (2026-06-11)

Built as specified. The workshop module is 372 lines after ruff formatting. Dep-check bypass
redesigned from a workshop sub-app callback approach to parent `ctx.invoked_subcommand`
detection after discovering Typer runs the parent callback before sub-app callbacks.
All import order and formatting issues resolved via ruff. 31 new tests; all 450 tests pass.
Coverage: 88.52%. No new required dependencies.

---

## v0.21.0 T1.4 — Full German Localisation Sweep

**Deliberated:** 2026-06-11

### Scope decision

Audit and patch all user-facing runtime strings so `--lang de` produces fully German output
with no English-only sentinel strings. Help text is excluded (no existing pattern in the repo;
Typer does not support runtime-switchable help text without significant restructuring). Security
log events are excluded (structural metadata, language-neutral by design).

### Affected paths

**New i18n.py strings (runtime output):**
- `evidence_coverage_line` — evidence backing summary line after assessment
- `export_written` — "Evidence pack written to: <path>"
- `verify_bundle_ok` / `verify_bundle_invalid` — bundle verify outcome
- `verify_evidence_no_refs` — when no evidence refs present
- `verify_evidence_ok` / `verify_evidence_fail` — per-item status marks
- `assessment_cancelled` — wizard cancellation message
- `cell_info_line` — cell/profile info line under `classify assess`
- Workshop strings (40+ keys): all `workshop_*` prefixed keys for panel output,
  error/warning messages, artifact paths, done message, verify output

**cli.py patches:**
- `assess`: wizard cancellation → `t('assessment_cancelled', lang)`
- `assess`: evidence coverage line → `t('evidence_coverage_line', ...)`
- `verify-evidence`: item marks, "no refs" → `t(...)`
- `export`: "Evidence pack written" → `t('export_written', ...)`
- `verify-bundle`: outcome and marks → `t(...)`

**classify.py patches:**
- `classify assess`: cell/profile dim line → `t('cell_info_line', ...)`
- `classify assess`: evidence coverage → `t('evidence_coverage_line', ...)`

### Deliberate exclusions

| Exclusion | Justification |
|---|---|
| `--help` texts | Typer help is compile-time; no `t()` pattern exists in the repo for help strings |
| Dep-check output | Fires before `--lang` is parsed; `'en'` is hard-coded in `_run_dep_check_quietly` by design |
| Security log events | Language-neutral structural metadata per secure-logging policy |
| Raw exception messages | OS/JSON errors from Python stdlib are not localised; they surface the raw message which is itself language-neutral |

### Acceptance criteria

1. `iga assess --lang de` output does not contain "Overall maturity".
2. `iga assess --lang de` output does not contain "Measurement Dimensions".
3. `iga assess --lang de` output does not contain "Gate Readiness".
4. `iga workshop run --lang de` output does not contain "Assessment" as a standalone English word.
5. Evidence coverage line appears in German under `--lang de`.
6. "Assessment cancelled" appears in German under `--lang de` in wizard mode.

### Implementation (2026-06-11)

All output paths swept. String count in `i18n.py` grew by ~50 entries (de+en pairs).
No mechanical translation errors introduced (all German strings reviewed against the IKI-Gov
book terminology). The T-B3 workshop strings were added in the same pass.

---

## Cross-cutting decisions

| Decision | Rationale |
|---|---|
| `~/.iga/` as global store | Consistent home for DB and future cache; mirrors `~/.pat/` pattern |
| 25-item fixed checklist in v0.1 | Directly derived from book appendix; stable, auditable baseline |
| Skip ≠ No in scoring | Conservative: skipped items excluded from denominator; organizations cannot "game" score by skipping |
| `--lang de\|en` default `en` | Book audience is German-speaking, but CLI tools are typically English; both must work equally well |
| Interactive before ISO mapping | Organizations need the base assessment before clause-level gaps are actionable |
| No PDF export | Avoids heavy dependencies (weasyprint/reportlab) in early versions; Markdown→PDF is user's responsibility |
| Gate exit codes 0/2/3 from v0.2 | Enables CI pipeline integration without string-parsing output |
| Drop Python 3.9 in v0.9.0 (min → 3.10+) | Patched `urllib3` (2.7.0+) dropped 3.9, leaving the dev/audit chain on a vulnerable pin (audit M-2); 3.9 is also upstream EOL (Oct 2025). Lets the whole locked tree resolve to patched releases. |
| Evidence is provenance, not score (v0.13) | Maturity (how complete) and evidence coverage (how verifiable) are orthogonal; folding signed evidence into the M-score would conflate two distinct questions and let producers inflate maturity |
| ikigov defines the consume interface, producers own the map (v0.13) | The spine stays framework-pure; each technical control owns and versions its own item→evidence mapping, so adding a producer needs no ikigov change |

## SDLC

These requirements are delivered under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
