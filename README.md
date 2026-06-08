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

# With Ed25519 public-key evidence verification
pip install "presidio-hardened-ikigov-assess[crypto]"
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

# ISO/IEC 42001 clause-level coverage gap analysis
iga iso-gap --use-case "fraud-scoring" --risk-class high --affirm S1,S2,S3,I1,I2
iga iso-gap --affirm S2,S3,I1,I2 --quiet   # machine-readable JSON

# EU AI Act high-risk obligations (Art. 9–17) — high-risk systems only
iga euaiact-gap --use-case "fraud-scoring" --affirm S1,S2,S3,S4,S5,D1,D5
iga euaiact-gap --affirm S1,S2 --quiet

# Persist assessments and view the portfolio (SQLite at ~/.iga/assessments.db)
iga assess --use-case "fraud-scoring" --risk-class high --affirm S1,S2,S3 --save
iga list                                   # table of saved assessments
iga portfolio                              # aggregated M1–M6 + blocked gates
iga trend --use-case "fraud-scoring"       # delta vs the previous saved run
iga delete --use-case "fraud-scoring"      # hard-delete

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

## ISO/IEC 42001 Coverage

`iga iso-gap` maps the assessment to ISO/IEC 42001 clause-level coverage. Each
clause group (clauses 4–10 and Annex A controls) is reported as **covered** (all
mapped checklist items affirmed), **partial**, or **gap**, with the outstanding
items listed per incompletely-covered clause:

```
ISO/IEC 42001 Coverage Gap Analysis — fraud-scoring  [risk: HIGH]

  4   Context of the organization      PARTIAL    (1/2)  — Outstanding items: S4
  5   Leadership                       COVERED    (4/4)
  8   Operation                        GAP        (0/13) — Outstanding items: D1, D2, …
  A   Annex A (Controls)               GAP        (0/12) — Outstanding items: …
```

Skipped and denied items count as *not affirmed* (no coverage credit). The
item→clause matrix is derived from the IKI-Gov orientation table
(`tab:framework-iso42001-matrix`) and centralised in `checklist.ISO_CLAUSES_BY_ITEM`.
Use `--quiet` for machine-readable JSON.

---

## EU AI Act (High-Risk Systems)

`iga euaiact-gap` maps gate readiness to the EU AI Act obligations for high-risk
systems (Title III Ch. 2, Articles 9–17). Each article is reported OPEN / PARTIAL /
BLOCKED based on the readiness of the gates that generate its evidence:

```
EU AI Act High-Risk Compliance Gap — fraud-scoring  [risk: HIGH]

  Art. 9   Risk management system     G0, G1, G2, G4   PARTIAL  — G2 BLOCKED, G4 BLOCKED
  Art. 10  Data and data governance   G1               OPEN
  Art. 11  Technical documentation    G2, G3, G5       BLOCKED  — G2/G3/G5 BLOCKED
```

The gate→article mapping is transcribed verbatim from the IKI-Gov book
(`tab:framework-euaiact-gates`) and lives in `euaiact.EU_AI_ACT_ARTICLE_GATES`.
The command is for high-risk systems only (exits with a warning for low/medium
risk); `--quiet` emits JSON.

> This tool does not constitute legal advice or a conformity assessment.

---

## Persistence & Portfolio

`iga assess --save` persists an assessment to a local SQLite database at
`~/.iga/assessments.db` (override with the `IGA_DB_PATH` env var). The portfolio
commands then work across saved use cases:

| Command | Purpose |
|---------|---------|
| `iga list` | Table of all saved assessments (use case, risk, overall, timestamp) |
| `iga portfolio` | Mean M1–M6 and overall maturity across the latest assessment per use case, plus a count of use cases with each gate BLOCKED |
| `iga trend --use-case X` | Per-dimension delta (▲/▼/=), overall maturity change, and gate transitions between two saved runs (latest vs previous, or a `--from`/`--to` window) |
| `iga delete --use-case X` | Hard-delete all saved assessments for a use case |

`list` and `portfolio` support `--quiet` for JSON. Only what you provide is stored
(use-case name, risk class, language, answers/scores/gates); the database file is
created with `0600` permissions and the `~/.iga` directory with `0700`. `delete` is
a hard delete — no soft-delete log is retained.

---

## External Evidence

Affirmations can be backed by **signed evidence** emitted by peer `presidio-hardened-*`
controls (first producer: `presidio-hardened-ai`), upgrading an item from *self-attested*
to *evidence-backed* — or cryptographically **verified** against a local trust store.
Verification is fail-closed: a missing, malformed, or wrong signature never counts as verified.

```bash
# Affirm items from an evidence document, verifying signatures against a trust store
iga assess --use-case "fraud-scoring" --risk-class high \
    --evidence evidence.json --trust trust.json

# Fail-closed: only references that verify against --trust affirm their item
iga assess --use-case "fraud-scoring" --risk-class high \
    --evidence evidence.json --trust trust.json --require-evidence

# Verify a document on its own (exit 0 only if every reference verifies)
iga verify-evidence --evidence evidence.json --trust trust.json
```

An **evidence document** is the producer's `EvidenceRef` JSON:

```json
{
  "schema": "presidio-hardened/evidence-ref@1",
  "use_case": "fraud-scoring",
  "evidence": [
    {
      "item_id": "D1",
      "source": "presidio-hardened-ai",
      "source_version": "0.2.0",
      "ledger_ref": "pai-ledger:seq/0",
      "content_hash": "abc123def456",
      "signer": "presidio-hardened-ai",
      "signature": "2e7af6d2…",
      "claimed_at": "2026-06-08T00:00:00+00:00"
    }
  ]
}
```

A **trust store** maps each signer to its key. An entry is either a bare HMAC secret
(back-compat) or an object declaring the algorithm and key material:

```json
{
  "presidio-hardened-ai": "shared-hmac-secret",
  "peer-control": { "alg": "ed25519", "public_key": "<64-hex-char public key>" }
}
```

For **key rotation**, `public_key` (or `key` for HMAC) may be a **list** — a signature
verifies if it matches any listed key, so a new key can run alongside the old one during an
overlap window; revoke by removing the key from the store:

```json
{
  "peer-control": { "alg": "ed25519", "public_key": ["<new public key>", "<retiring key>"] }
}
```

Ed25519 (RFC 8032) public-key verification lets a verifier hold **only public keys** — no
shared secret with the producer — and requires the `[crypto]` extra. Signatures are over the
canonical `{content_hash, signer}` message; signer keys are resolved from the local trust
store only (no network). Evidence references carry hashes and opaque ledger URIs, never PII.

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
| `iga_assess_with_evidence` | Score a use case from signed `EvidenceRef` documents, verifying signatures against a trust store (HMAC or Ed25519) |
| `iga_check_gate` | Evaluate readiness for a single gate G0–G5 with blocking/skipped items |
| `iga_iso_gap` | Map affirmed items to ISO/IEC 42001 clause coverage (covered / partial / gap) |
| `iga_euaiact_gap` | Map to EU AI Act high-risk obligations Art. 9–17 (OPEN / PARTIAL / BLOCKED) |

All tools share the CLI's input validation and output sanitisation, return the same
structured JSON schema as `iga report --format json`, and respect the per-session
abuse guard (returning a tool error rather than terminating the server when exceeded).

---

## Evidence-Pack Export (v0.15.0)

Export a signed, audit-ready bundle of an assessment and verify it later:

```bash
# Write report.md + report.json + manifest.json (sha256 of each artifact + framework hash).
iga export --use-case fraud-scoring --risk-class high --affirm S1,S2,D1 \
    --bundle audit/fraud-scoring/ --sign-key "$SEAL_KEY"

# Re-hash artifacts against the manifest (and check the optional HMAC seal).
iga verify-bundle --bundle audit/fraud-scoring/ --sign-key "$SEAL_KEY"
```

The `manifest.json` content-hashes every artifact and records a `framework_content_hash`
pinning the checklist + ISO/EU AI Act mappings that produced the assessment, so any later
edit is detected by `verify-bundle`. Use `--zip` to emit a `.zip`. (PDF rendering and a
public-key manifest signature are deferred; the hash manifest + optional HMAC seal are the
integrity baseline.)

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
| v0.4.0 | Report export to file (`--output`) with per-item answers | Released |
| v0.5.0 | ISO/IEC 42001 clause-level gap mapping (`iga iso-gap`) | Released |
| v0.6.0 | Portfolio mode: persistence, `list`, `portfolio`, `delete` | Released |
| v0.7.0 | Maturity trending: delta between saved runs (`iga trend`) | Released |
| v0.8.0 | EU AI Act gate→article mapping for high-risk systems (`iga euaiact-gap`) | Released |
| v0.13.0 | External evidence-backed affirmation: `iga assess --evidence` / `verify-evidence` + `iga_assess_with_evidence` (first producer: `presidio-hardened-ai`) | Released |
| v0.14.0 | Public-key (Ed25519) evidence verification: trust-store `{alg, public_key}` entries + `verify_ref` dispatch (`[crypto]` extra) | Current |

### Planned

| Version | Theme | Status |
|---------|-------|--------|
| v0.9.0 | Evidence-pack export: signed, audit-ready report bundle + manifest | Planned |
| v0.10.0 | Pluggable regulatory-content provider interface (versioned content packs) | Planned |
| v0.11.0 | NIST AI RMF mapping + framework-agnostic coverage core | Planned |
| v0.12.0 | Remote MCP endpoint: HTTP/SSE transport, org context, auth | Planned |

> **v0.13.0–v0.14.0 pulled forward** ahead of v0.9.0–v0.12.0 to close the
> `presidio-hardened-ai` evidence loop end-to-end (the producer already emits the
> contract format). v0.13.0 ships an HMAC verification primitive; v0.14.0 adds
> Ed25519 public-key verification (optional `[crypto]` extra) so a verifier can
> hold only public keys. The broader v0.9.0 signed evidence-pack remains planned.

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
