# presidio-hardened-ikigov-assess

**IKI-Gov Assessment Tool** — operationalises the IKI-Gov-Referenzmodell (Integrated KI-Governance Reference Model) as a practical CLI tool for assessing AI use cases against a structured governance framework.

The IKI-Gov framework structures AI governance along a central lifecycle
(Kontext → Konzeption → Entwicklung → Freigabe → Betrieb → Anpassung → Außerbetriebnahme)
surrounded by six domains and measured across six dimensions (M1–M6) with six quality gates
(G0–G5).

Reference: Stantchev, V. *IKI-Gov-Referenzmodell* — Integrated KI-Governance Reference Model.

---

## Installation

```bash
pip install presidio-hardened-ikigov-assess

# With dependency CVE checking
pip install "presidio-hardened-ikigov-assess[audit]"
```

---

## Quick Start

```bash
# Parameter-driven assessment
iga assess --use-case "fraud-scoring" --risk-class high --lang en \
    --affirm S1,S2,S3,D1,D2,T1,T4,O1,I1

# Interactive wizard (step-by-step)
iga assess --interactive --lang de --risk-class high --use-case "kredit-scoring"

# Gate readiness check
iga gate --gate G2 --risk-class high \
    --affirm S1,S2,S3,D1,D2,T1,T4,O1,I1 --lang en

# CI pipeline gate assertion (exit 0 OPEN / 2 PARTIAL / 3 BLOCKED)
iga gate --gate G1 --risk-class high --affirm S1,S2,D1,D2 --assert-gate G1

# Strict mode: skipped gate-critical items count as blocking
iga gate --gate G2 --risk-class high --affirm S1,S2 --skip D3 --strict --assert-gate G2

# Machine-readable JSON (scriptable, no progress bars)
iga assess --affirm S1,S2,S3 --quiet
iga gate --gate G0 --affirm S1,S2 --skip S3 --quiet

# Export report to Markdown (stdout)
iga report --use-case "fraud-scoring" --risk-class high \
    --affirm S1,S2,S3,D1,D2,T1 --format markdown

# Export report to JSON
iga report --use-case "fraud-scoring" --affirm S1,S2 --format json

# Write the report to a file (Markdown or JSON)
iga report --use-case "fraud-scoring" --affirm S1,S2,T4 --output audit/fraud-scoring.md
iga report --use-case "fraud-scoring" --affirm S1,S2 -f json -o fraud-scoring.json

# List saved assessments (persistence in v0.6.0)
iga list
```

### Example output

```
IKI-Gov Assessment — fraud-scoring  [risk: HIGH]

Measurement Dimensions
  M1  Strategie & Ownership          ████████░░   80.0 %
  M2  Data Quality & Lineage         ██████░░░░   60.0 %
  M3  Validation & Fairness          ████░░░░░░   40.0 %
  M4  Security & Robustness          █████████░   90.0 %
  M5  Compliance Evidence            ███░░░░░░░   30.0 %
  M6  Operations, Drift & Incidents  ██████░░░░   60.0 %
  ──────────────────────────────────────────────────────
       Overall maturity                           60.0 %

Gate Readiness
  G0  OPEN
  G1  OPEN
  G2  PARTIAL  [skipped: D3]
  G3  BLOCKED  — blocking: T5 (A security review of the model pipeline…)
  G4  BLOCKED
  G5  BLOCKED
```

---

## Checklist

25 items derived from the five appendix sections of the IKI-Gov framework:

| Prefix | Section | M-Dimension |
|--------|---------|-------------|
| S1–S5 | Strategie & Geschäftsfall | M1 Strategie & Ownership |
| D1–D5 | Daten, Recht & Ethik | M2 Datenqualität & Lineage |
| T1–T3 | Modell, Sicherheit & Technik | M3 Validierung & Fairness |
| T4–T5 | Modell, Sicherheit & Technik | M4 Sicherheit & Robustheit |
| O1–O5 | Betrieb, Monitoring & Aufsicht | M6 Betrieb, Drift & Vorfälle |
| I1–I5 | ISO/IEC 42001 Abgleich | M5 Compliance-Nachweise |

---

## Scoring

```
score_m(dim) = sum(weight_i for affirmed items in dim)
               / sum(weight_i for non-skipped items in dim) × 100

overall = arithmetic mean(M1, M2, M3, M4, M5, M6)
```

Risk-class multipliers: `low` = 1.0 · `medium` = 1.5 · `high` = 2.0.
Skipped items are excluded from both numerator and denominator (conservative).

---

## Gates

| Gate | Lifecycle transition |
|------|---------------------|
| G0 | Kontext → Konzeption |
| G1 | Konzeption → Entwicklung |
| G2 | Entwicklung → Freigabe |
| G3 | Freigabe → Betrieb |
| G4 | Betrieb → Anpassung |
| G5 | Anpassung → Außerbetriebnahme |

**Status:** **OPEN** (all affirmed) · **PARTIAL** (some skipped, none denied) · **BLOCKED** (≥1 denied)

### Risk-class-aware thresholds (v0.3.0)

How skips are treated depends on the active risk class:

| Risk class | Skipped gate-critical items |
|------------|-----------------------------|
| `low` | forgiven — a gate with skips but no denials is **OPEN** |
| `medium` | tolerated — the gate is **PARTIAL** until they are affirmed |
| `high` | not permitted — skips **BLOCK** the gate (strict by default) |

`--strict` forces high-risk behaviour at any risk class. When a skip blocks a gate,
it is reported separately (`blocking_skips`) so the reason for a BLOCKED-not-PARTIAL
gate is explicit.

### CI exit codes

`--assert-gate Gn` exits with a status-specific code so pipelines can branch without
parsing output:

| Exit code | Meaning |
|-----------|---------|
| `0` | gate OPEN |
| `2` | gate PARTIAL |
| `3` | gate BLOCKED |
| `1` | general error (invalid input, gate mismatch) |

`--quiet` (`-q`) on `assess` and `gate` emits machine-readable JSON only.

---

## MCP Server

The assessment engine is also available as a [Model Context Protocol](https://modelcontextprotocol.io)
server, so MCP-capable LLM agents and clients can run IKI-Gov assessments as tools.

```bash
# Install with the MCP extra (requires Python 3.10+)
pip install "presidio-hardened-ikigov-assess[mcp]"

# Run the server over stdio
iga-mcp
```

Register it with an MCP client (e.g. Claude Desktop) by adding to the client's config:

```json
{
  "mcpServers": {
    "iki-gov-assess": {
      "command": "iga-mcp"
    }
  }
}
```

### Tools

| Tool | Purpose |
|------|---------|
| `iga_framework_info` | Describe the model: lifecycle phases, dimensions M1–M6, gates G0–G5, sections, risk classes (de/en) |
| `iga_list_checklist` | Return all 25 checklist items with IDs, text, dimension, gates, and section |
| `iga_assess` | Score a use case from affirmed/skipped item IDs → M1–M6 scores, overall maturity, gate readiness |
| `iga_check_gate` | Evaluate readiness for a single gate G0–G5 with blocking/skipped items |

All tools share the CLI's input validation and output sanitisation, return the same
structured JSON schema as `iga report --format json`, and respect the per-session
abuse guard (returning a tool error rather than terminating the server when exceeded).

---

## Security

See [SECURITY.md](SECURITY.md) for the full security policy.

Security controls built into the tool:
- Input validation for all CLI parameters (type, bounds, allow-list)
- HTML-escaping of all user-supplied strings in report output
- Structured security event log at `~/.iga/security.log` (no content logged, structural metadata only)
- On-startup CVE check via `pip-audit` (suppress with `--no-dep-check`)
- Session rate limiting (default: 100 assessments; override via `IGA_MAX_ASSESSMENTS`)

---

## Roadmap

| Version | Theme | Status |
|---------|-------|--------|
| v0.1.0 | MVP — interactive + parameter-driven assessment, M1–M6 scoring, bilingual | Released |
| v0.2.0 | MCP server — agent-accessible assessment engine (`iga-mcp`) | Released |
| v0.3.0 | Gate readiness refinement, CI exit codes 0/2/3, `--strict` flag | Released |
| v0.4.0 | Report export to file (`--output`) with per-item answers | Current |
| v0.5.0 | ISO/IEC 42001 clause-level gap mapping | Planned |
| v0.6.0 | Portfolio mode: multiple use cases, SQLite persistence | Planned |
| v0.7.0 | Maturity trending: delta between assessment runs | Planned |
| v0.8.0 | EU AI Act gate-to-article mapping for high-risk systems | Planned |

Full version deliberation log: [PRESIDIO-REQ.md](PRESIDIO-REQ.md)

---

## Development

```bash
# Install in editable mode with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Lint and format
ruff format .
ruff check . --fix
```

---

## License

MIT — see [LICENSE](LICENSE).

---

## SDLC

This repository is developed under the Presidio hardened-family SDLC:
<https://github.com/presidio-v/presidio-hardened-docs/blob/main/sdlc/sdlc-report.md>.
