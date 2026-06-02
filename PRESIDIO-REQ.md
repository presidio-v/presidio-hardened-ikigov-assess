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

- Python 3.9+
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
| v0.6.0 | Portfolio mode: multiple use cases, SQLite persistence | Planned |
| v0.7.0 | Maturity trending: delta between assessment runs, history view | Planned |
| v0.8.0 | EU AI Act gate-to-article mapping for high-risk systems | Planned |

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

⚠️ **Mapping is a derived approximation.** The values in `ISO_CLAUSES_BY_ITEM`
were inferred from each item's content (the I-items cite their clauses directly;
the rest mapped by theme), not transcribed from the book's authoritative
`tab:framework-iso42001-matrix`. Reconcile that table against the dict — it is the
single edit point and the engine is generic over it.

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

---

## v0.8.0 — EU AI Act Gate-to-Article Mapping (High-Risk Systems)

**Deliberated:** 2026-03-30

### Scope decision
Map G0–G5 gate outputs to EU AI Act Title III Chapter 2 articles (Art. 9–17) for high-risk systems under Annex III. Only meaningful for `--risk-class high`. Mirrors the ISO 42001 clause mapping in v0.5.0 and is derived directly from Table `tab:framework-euaiact-gates` in the IKI-Gov book (chapter-framework).

### Data model extension
Each checklist item gains an `eu_ai_act_articles` field: list of article references applicable at that gate for high-risk systems (e.g. `["9", "10", "17"]`). Field is empty for non-high-risk items.

Gate-to-article primary mapping (from book Table tab:framework-euaiact-gates):

| Gate | Primary Articles |
|---|---|
| G0 | Art. 9 §1, Art. 17 §1 lit. a |
| G1 | Art. 10 §2–3, Art. 9 §2 lit. a–b |
| G2 | Art. 9 §2 lit. c–d, Art. 11 + Annex IV, Art. 15 §1–3 |
| G3 | Art. 11 + Annex IV (complete), Art. 13 §1–2, Art. 14 §1–4, Art. 17 §1 |
| G4 | Art. 9 §2 lit. d, Art. 12 §1–2, Art. 15 §4 |
| G5 | Art. 11 §3, Art. 17 §1 lit. k |

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

## SDLC

These requirements are delivered under the family-wide Presidio SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
