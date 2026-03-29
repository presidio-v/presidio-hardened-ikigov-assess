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

# CI pipeline gate assertion (exits 1 if G1 not OPEN)
iga gate --gate G1 --risk-class high --affirm S1,S2,D1,D2 --assert-gate G1

# Export report to Markdown (stdout)
iga report --use-case "fraud-scoring" --risk-class high \
    --affirm S1,S2,S3,D1,D2,T1 --format markdown

# Export report to JSON
iga report --use-case "fraud-scoring" --affirm S1,S2 --format json

# List saved assessments (persistence in v0.5.0)
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

25 items drawn from the five appendix sections of the IKI-Gov framework:

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

Status: **OPEN** (all affirmed) · **PARTIAL** (some skipped, none denied) · **BLOCKED** (≥1 denied)

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
| v0.1.0 | MVP — interactive + parameter-driven assessment, M1–M6 scoring, bilingual | Current |
| v0.2.0 | Gate readiness refinement, CI exit codes 0/2/3, `--strict` flag | Planned |
| v0.3.0 | Report export to file (Markdown and JSON) | Planned |
| v0.4.0 | ISO/IEC 42001 clause-level gap mapping | Planned |
| v0.5.0 | Portfolio mode: multiple use cases, SQLite persistence | Planned |
| v0.6.0 | Maturity trending: delta between assessment runs | Planned |

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
