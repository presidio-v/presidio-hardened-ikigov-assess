# Changelog

All notable changes to `presidio-hardened-ikigov-assess` are recorded here.
Earlier releases (v0.1.0–v0.19.2) are documented fully in `PRESIDIO-REQ.md`
(version registry and deliberation log). This file covers v0.20.0 onwards.

---

## [0.24.0] — 2026-08-02

Maintenance and supply-chain release. No new assessment surface: the fuzz
harnesses, the fail-closed parser guards they found, and a dependency ceiling
that unbreaks the `[mcp]` extra.

### Added

- **Coverage-guided fuzzing (Atheris)** — new top-level `fuzz/` directory with
  property fuzzers for the two untrusted-input boundaries:
  `fuzz_classification.py` (`parse_classification_bytes`: decode → JSON →
  validate → normalise, L6/ecosystem invariants, determinism) and
  `fuzz_evidence.py` (`load_evidence` / `load_trust_store` fail-closed contract,
  ref field/hex invariants, `expected_signature` determinism, `verify_ref`
  round-trip). New `fuzz` extra (`atheris>=3.1.0`; Linux/py3.12-only) and a
  hardened `fuzz.yml` workflow: read-only token, SHA-pinned actions, time-boxed
  per-PR smoke run plus weekly scheduled soak. Takes the OpenSSF Scorecard
  Fuzzing check from 0 to 10.

### Fixed

- **Fail-closed guards at the JSON boundaries** (found while constructing the
  fuzz harnesses): `parse_classification_bytes` raised raw `UnicodeDecodeError`
  on invalid UTF-8 bytes, `UnicodeEncodeError` on lone-surrogate strings, and
  `RecursionError` on pathologically nested JSON instead of
  `ClassificationError`; `load_evidence` and `load_trust_store` likewise leaked
  `RecursionError` instead of `EvidenceError`. All now fail closed with the
  documented exception types (regression-tested).
- **`[mcp]` extra unbroken** — `mcp` is capped to `>=1.2.0,<2`. mcp 2.0.0
  (2026-07-28) relocated `mcp.server.fastmcp`, which `build_server()` imports, so
  the previously unbounded floor resolved to a breaking major: every
  `pip install "presidio-hardened-ikigov-assess[mcp]"` since that date produced an
  `iga-mcp` that died at import. Anyone on 0.23.0 wanting the MCP server needs
  this release, or a manual `mcp<2` pin. The 2.x port is separate work; the cap
  is lifted with it. `uv.lock` is refreshed to mcp 1.29.0 in the same change,
  which also clears GHSA-vj7q-gjh5-988w (never reachable here — this codebase
  runs stdio or streamable-HTTP and never imports `mcp.server.websocket`).

## [0.23.0] — 2026-07-05

**T-B5 · Gate certificates — "the certificate is the proof"** (v0.23.0 arc).
A gate decision (`OPEN` / `PARTIAL` / `BLOCKED`) becomes a compact, signed
artifact any third party verifies locally against a trust store, without
running ikigov-assess and without the assessments database — the product-form
of the Computational Jurisprudence program (Stantchev, arXiv 2026): local
verification, no engine in the trust path, fail-closed. Additive only; existing
public APIs and workshop-manifest verification are unbroken.

### Added

- **`presidio-hardened/gate-certificate@1`** (`certificate.py`) — a signed gate
  certificate carrying `schema`, `use_case`, `framework_content_hash`, `gate`,
  `risk_class`, `decision`, the **sufficient affirmation set** (per gate item:
  `affirmed` / `skipped` / `denied`, with any signed evidence-ref embedded
  verbatim so the certificate carries its own grounding), the **decision
  predicate inputs** (gate item ids, risk class, effective strict flag,
  predicate content hash) so a verifier recomputes the decision from the
  certificate alone, `assessed_at`, `issuer`, and a detached `signature`.
  Canonical-JSON + SHA-256 + detached Ed25519/HMAC-SHA256, reusing the family
  conventions in `evidence.py` / `sovereignty.py`. The signature covers the
  canonical bytes of the document **minus the `signature` field**.
- **`iga certify`** — emit a signed gate certificate after a gate evaluation
  (embeds verified evidence-refs; DE/EN output; `--output` or stdout). When
  `--evidence` is supplied, `--trust` is required and every evidence-ref is
  verified before embedding; a failing ref rejects the certify run.
- **`iga verify-certificate`** — verify a certificate against a trust store,
  **fail-closed with distinct reasons** (`unknown-schema`, `bad-signature`,
  `unknown-issuer`, `evidence-ref-failure`, `predicate-content-mismatch`,
  `decision-mismatch`): it verifies the issuer signature, re-verifies every
  embedded evidence-ref against the verifier's trust store, and recomputes the
  gate decision from the embedded predicate inputs — **never reading the
  assessments DB** (certificate + trust store only).
- **Named workshop delegation chain** (`sovereignty.build_delegation_chain` /
  `verify_delegation_chain`) — the customer-signature → manifest-hash →
  presidio-attestation lineage exposed as an explicit ordered chain (each link:
  `role`, `signer`, `signs`, `reference`). `iga workshop verify --show-chain`
  walks it link-by-link with a distinct failure reason per link;
  `--require-chain` fails closed unless an owner link is present. **Additive and
  derived**: assembled at verify time from existing artifacts, so pre-v0.23.0
  manifests (which carry no chain) verify unchanged.

### Notes

- No overclaiming: a gate certificate proves the gate decision under the
  declared predicate and embedded evidence; it does **not** prove the underlying
  controls are effective. `assurance_tier` (evidence-ref@2 / presidio-evidence
  ADR-0003) is a **planned** field — evidence-ref@1 here does not model tiers,
  so certificates do not carry one.

---

## [0.22.0] — 2026-07-04

**T-B4 · Workshop evidence sovereignty — "customer anchors, presidio attests"**
(v0.22.0 arc; deliberated 2026-07-02, O5 resolution; implemented 2026-07-03).
The T-B3 leave-behind was presidio-anchored (facilitator held the only key).
This arc inverts custody: the customer signs their own workshop evidence with
a key generated on their hardware; presidio countersigns as assessor in a
separate attestation document, chained to the manifest via the ADR-0002
provenance-parents convention (L-EV-6 first instance).

### Added

- **`iga workshop keygen`** (R1) — customer Ed25519 keypair on customer
  hardware: private key to a 0600 file (never leaves the machine), `.pub`
  companion, printed `trust-store@1` snippet for the engagement trust store
  (R4). Refuses overwrite without `--force`.
- **`iga workshop sign`** (R1) — customer-side owner signing: embeds the
  additive `owner` block (signer, public key, timestamp) *inside* the signed
  manifest content (stays within `workshop-leavebehind@1` per evidence
  ADR-0001 D5), writes a role-tagged `manifest.sig` (`role: owner`), warns
  when replacing a facilitator signature (fallback tier 2 → tier 1). Key via
  `--key` or `$IGA_WORKSHOP_OWNER_KEY`.
- **`iga workshop attest`** (R2) — presidio-side countersignature as a
  **separate document**, not a second signature over the same bytes: a
  `presidio-hardened/workshop-attestation@1` payload (`role`, `attests`,
  `parents`, `engagement`, `scope`, `workshop_date`) in a signed
  `evidence-ref@1` envelope. `attests`/`parents[0]` carry the manifest's
  canonical content hash — the provenance-DAG edge. Fail-closed: no key, no
  attestation. Offline-capable (needs only the manifest hash). **Schema
  frozen by the family golden vector** (`presidio-evidence
  vectors/workshop-attestation/`); the conformance test pins the vector's
  content hash and deterministic Ed25519 signature byte-for-byte.
- **`iga workshop verify` extensions** — reports signature role and owner
  block; owner-pubkey consistency check (fail-closed when the verifying key
  does not match the embedded owner block); `--require-attestation
  --attestation-pubkey <hex>` verifies the attestation chain (structure,
  hash recompute, signature via the family trust-store path, role, manifest
  binding); `--lang de|en` (replaces hardcoded German output).
- **Leave-behind additions** (R3/R4) — every use-case folder now ships
  `sign.py` (self-contained standalone owner signer for customers who cannot
  install `iga`; stdlib + `cryptography` only), `SIGNING.md` (bilingual USB
  signing-ceremony runbook), and `assessor.pub` (presidio assessor public key,
  derived from `--sign-key` or supplied via `--assessor-pubkey`) — all
  content-hashed in the manifest.
- **`sovereignty.py`** — core module (keypair generation, family Layer-1
  signing, attestation build/verify, standalone-signer template); attestation
  envelope verification deliberately bypasses the checklist-item `item_id`
  domain check (correct domain: `workshop-attestation/<engagement>`) while
  reusing the family cryptographic path (`verify_ref`, timing-safe,
  fail-closed).
- **Tests** — 18 new in `test_sovereignty.py` (golden-vector byte-identity,
  keygen permissions, dual-signature round-trips, tamper/wrong-key/missing
  fail-closed paths, schema/public-key/version remediation regressions,
  standalone-signer subprocess ceremony, bilingual i18n coverage); full suite
  468 passed.

---

## [0.21.1] — 2026-06-24

First public **PyPI** release. No functional change versus 0.21.0 — the source is
equivalent; this cut packages the public-launch hygiene and the release infrastructure.

### Going public
- Scrubbed internal/partner references and moved the internal audit out of the public
  tree (the repo went public on 2026-06-24).
- README: added a **The book** section sourcing the IKI-Gov model to the forthcoming
  Springer monograph (*AI and IT-Governance* / *KI und IT-Governance*); prose pass to trim
  em-dash overuse.

### Build & release
- Trusted-Publishing workflow (`.github/workflows/publish.yml`): OIDC, no stored secrets,
  SBOM + PEP 740 attestations, fired by a signed `v*` tag.
- CodeQL analysis no longer masks failures (`continue-on-error` dropped) now that Advanced
  Security is available on the public repo.
- Documented the fail-open swallows and screened the `pip-audit` subprocess with justified
  `# nosec` markers (no behaviour change).
- Packaging metadata: corrected the repository URL to the `presidio-v` org and dropped the
  stale Python 3.9 classifier (the package already requires ≥3.10).

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
