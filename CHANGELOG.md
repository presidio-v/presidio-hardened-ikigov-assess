# Changelog

All notable changes to `presidio-hardened-ikigov-assess` are recorded here.
Earlier releases (v0.1.0–v0.19.2) are documented fully in `PRESIDIO-REQ.md`
(version registry and deliberation log). This file covers v0.20.0 onwards.

---

## [0.27.0] — 2026-09-30

Remediation of an in-depth security audit (2026-09-30) across four surfaces: signing and
verification, the network and MCP surface, parsers and files, and the supply chain. Each
fix carries a regression test that reproduces the finding.

### Upgrade notes

Several fixes deliberately turn a former pass into a failure. Check these before upgrading
a pipeline that relies on them:

- `iga workshop verify` exits 1 on an UNSIGNED leave-behind. Pass `--allow-unsigned` to
  accept hash consistency alone; the JSON result reports `authenticated`.
- An evidence document that claims one signed ref for several items verifies none of them.
  A producer must emit one ref, with its own `content_hash`, per item.
- `iga verify-certificate --min-evidence-tier` fails on a certificate without embedded
  refs (`no-evidence-for-tier-floor`), and a certificate whose `issuer` is not its signer
  fails (`issuer-signer-mismatch`). Certificates issued by `iga certify` always pass the
  second check.
- An external content or profile pack that reuses a built-in `framework_id` is refused
  unless `--allow-builtin-override` or `IGA_ALLOW_BUILTIN_OVERRIDE=1` is set.
- `iga-mcp-remote` refuses a non-loopback `--host` without `--behind-tls-proxy`, no longer
  applies `IGA_MAX_ASSESSMENTS` across orgs, and limits each org per window
  (`IGA_MCP_WINDOW_SECONDS`, default 3600).
- JSON outputs gain keys (`reused_refs_not_verified`, per-ref `reused`, `authenticated`);
  the evidence block inside a signed export manifest changes accordingly, so a pack
  exported by 0.27.0 is not byte-identical to one exported by 0.26.0 from the same input.

### Security

- **One signed evidence-ref counts for at most one item.** The evidence-ref signature
  covers `{content_hash, signer}` but not `item_id`, so one genuine ref copied under all
  25 item ids verified 25 times, and `--require-evidence` counted 25/25 items and opened
  every gate from a single piece of evidence. A ref claimed for more than one item now
  verifies for none of them, in every command, `verify-evidence`, the MCP tool and
  refs embedded in gate certificates. Reuse is reported (`reused_refs_not_verified`).
- **A gate certificate's `issuer` must be its signer** (`issuer-signer-mismatch`). Any key
  in the verifier's trust store could previously mint a certificate naming another issuer.
- **`--min-evidence-tier` fails closed on a certificate with no embedded ref**
  (`no-evidence-for-tier-floor`) instead of passing vacuously.
- **`workshop verify` fails on an UNSIGNED leave-behind** unless `--allow-unsigned`; its
  JSON result reports `authenticated`.
- **Bundle and leave-behind verification read only plain, regular members up to 8 MiB.**
  Manifest names like `../x` or `/etc/x`, symlinked members and devices could read files
  outside the bundle as a hash oracle or exhaust memory.
- **No writer follows a planted symlink** (`export`, `workshop run/sign/attest`, `keygen`).
- **File-derived strings are stripped of control characters and Rich markup** before
  reaching the console, so a crafted manifest cannot erase its own `FAIL` line or print a
  styled fake `OK`.
- **An external pack may replace a built-in `framework_id` only when allowed**
  (`--allow-builtin-override` / `IGA_ALLOW_BUILTIN_OVERRIDE=1`), and an allowed override is
  announced on stderr. Pack files are capped at 1 MB and deep nesting is a `ContentError`.
- **Allow-list patterns anchor with `\Z`**, so a trailing newline no longer passes.
- **Remote endpoint:** the process-wide assessment counter, which one tenant could exhaust
  for every org, no longer applies there; the per-org limit is a real window
  (`IGA_MCP_WINDOW_SECONDS`, `Retry-After` on 429) instead of a lifetime counter; and
  `serve()` refuses a non-loopback bind without `--behind-tls-proxy`.

### Fixed

- **The MCP server reports its version in the handshake.** `initialize` returned
  `serverInfo.version: ""` because `MCPServer` defaults the version to an empty string;
  it now reports the package version. A test reads it from a real stdio handshake.

### Build

- **The release build uses a hash-pinned backend** (`hatchling` and its closure in
  `release-build.txt`, `python -m build --no-isolation`).
- **`publish.yml` attests `dist/` before anything installs unpinned packages;** the SBOM
  moves to its own job and describes the wheel's runtime closure, not the build tooling.
- **A manual MCP Registry publish runs only from `main`.**
- Every checkout sets `persist-credentials: false`.

- **`hatchling` is bounded to `>=1.31,<2`** instead of floating unbounded. The floor is
  the version that built 0.25.0. The range cannot stop metadata changes inside a major:
  hatchling 1.32 moved to Metadata-Version 2.5, which the pinned twine 6.2.0 rejected and
  failed the first v0.26.0 tag build. `pytest.yml` therefore gains a *Build and check
  metadata* job that runs the release build and `twine check --strict` on every PR, so
  a backend/twine mismatch shows up before a tag.

### Documentation

- `SECURITY.md` documents the one-ref-one-item rule, the remote transport model, the
  dependency-check bypasses and the rate guard's scope. The CII `build_repeatable` answer
  no longer claims `uv.lock` pins the published artefact.

## [0.26.0] — 2026-09-29

Two arcs. **S-1** closes a fail-open in `--require-evidence` (Security, below).
**T-B6** adds certificate lineage, validity, grounding and tiers. Both are additive
for users who do not pass `--require-evidence`: scores, gates and exit codes are
unchanged, and every pre-v0.26 certificate and evidence document verifies unchanged.
Deliberations: `PRESIDIO-REQ.md` v0.26.0 S-1 and T-B6.

### Security

- **`--require-evidence` no longer fails open** (S-1; affects every release from
  0.13.0 through 0.25.0). The flag was documented as "Fail-closed: only evidence that
  verifies against --trust affirms its item", but it only filtered `--evidence` inputs:
  a bare `--affirm` (or a wizard answer) still counted, and without `--evidence` the flag
  was never read. `iga assess --affirm <all 25> --require-evidence --trust '{}'` therefore
  reported 100 % and every gate OPEN, and a signed `iga export` pack from the same
  answers carried no marking at all. Now a single merge point
  (`evidence.resolve_affirmations`) applies the policy in every command: under the flag
  an item counts **only** if a reference in `--evidence` verifies against `--trust`;
  a self-attested item without one is **asserted**, named on stderr, shown in every
  output as `asserted (not counted)`, and excluded from scores and gates. Nothing
  verifies with no `--evidence`, no `--trust`, an empty store, an unknown signer, a
  wrong key or a tampered signature. The same two commands now report 0 % with every
  gate BLOCKED. Reported 2026-09-28; the lab that pins 0.21.1 and 0.25.0 for
  20.10.–03.11.2026 is unaffected because no published version is changed.
- **Every output marks each item** as evidenced / asserted / open, whatever flags
  produced it: per-item `provenance` is always present on affirmed and asserted rows,
  JSON carries `answers.asserted` and `evidence_coverage.{require_evidence,
  asserted_not_counted}`, `gate` and the gap commands carry an `evidence` block, the
  Markdown report gains an *Evidence* column and a summary line, and the signed export
  manifest carries the `evidence` block inside the signed bytes.
- `--evidence` / `--trust` / `--require-evidence` are now accepted by `gate`, `report`,
  `export`, `framework-gap`, `iso-gap` and `euaiact-gap` (previously `assess`,
  `certify` and `classify assess` only), so the release-gate use
  `iga gate --require-evidence --assert-gate` promised in the v0.13.0 deliberation works.
- `certify --require-evidence` (previously a documented no-op) drops bare affirmations
  and writes `require_evidence: true` into the signed certificate.

### Added

- **`parents` on gate certificates** (`iga certify --parent <hex>`, repeatable) —
  ADR-0002 provenance parents inside the signed content: the content hashes of the
  classification document and workshop manifest a decision rests on. Rewiring
  lineage after signing breaks the issuer signature. Validated fail-closed (family
  hex rule, no duplicates, present means non-empty); omitted when empty.
- **`not_after` on gate certificates** (`iga certify --valid-days N`) — a signed
  validity bound. Expiry is the format's only revocation, by design: no list, no
  accumulator, no coordination. `iga verify-certificate` fails closed past it with
  the new reason `expired`; `--at <UTC>` verifies as of a given instant. Absent
  bound = no expiry.
- **`grounding` on gate certificates** — `self` if any affirmed gate item lacks an
  embedded evidence-ref, else `evidence-verified`. Recomputed at verification
  (`grounding-mismatch`); `--min-grounding evidence-verified` fails closed on any
  self-attested item (`grounding-below-minimum`).
- **`evidence-ref@2` accepted** (presidio-evidence ADR-0003). A ref's declared
  `assurance_tier` (`attested` | `optimistic` | `zk`) is honoured only under `@2`,
  defaults to `attested`, is inert under `@1` (matching the family golden vector
  `evidence-ref-v2/valid-v1-with-extra-tier`), and fails closed when unknown. The
  signed message is unchanged, so `@1` and `@2` refs verify identically.
- **Tier surfacing in certificates.** Embedded refs carry their declared tier; the
  verifier reports the weakest (`evidence_tier_min`) and `--min-evidence-tier`
  demands a floor (`evidence-tier-below-minimum`). The certificate's own
  `assurance_tier` is `attested`; any other value is rejected
  (`unsupported-assurance-tier`), so a future zk gate certificate cannot be
  mistaken for one this verifier can check.
- `verify-certificate --quiet` JSON gains `grounding`, `evidence_tier_min`,
  `not_after`, `parents`; the security log records grounding and the weakest tier.
- Bilingual strings for every new reason and error.
- **Listed in the MCP Registry as `io.github.presidio-v/presidio-hardened-ikigov-assess`.**
  `server.json` describes the stdio server; `publish.yml` now calls a new
  `mcp-registry.yml` workflow after the PyPI publish, which logs in with GitHub OIDC
  and publishes it. OIDC takes the `io.github.presidio-v` namespace from the repository
  owner, because the `mcp-publisher` device login currently mints tokens without org
  namespaces even for org Owners (modelcontextprotocol/registry#1527, #1649). The
  workflow can also be run by hand from `main` to republish.
- **`presidio-hardened-ikigov-assess` console script**, an alias of `iga-mcp`. Registry
  clients launch `uvx --from presidio-hardened-ikigov-assess[mcp] <identifier>`, and uvx
  runs the script named after the identifier.
- `README.md` carries the `mcp-name` marker the registry reads from the PyPI project
  page to prove namespace ownership, so the first listing is the first release that
  ships it. `tests/test_server_json.py` fails CI when `server.json` drifts from the
  package version, exceeds the 100-character description limit, or loses the marker.


### Changed

- `verify_certificate()` gains keyword-only `now`, `min_grounding`,
  `min_evidence_tier`; check order is now schema → signature → tier → predicate →
  validity/lineage shape → evidence-refs (+ tier floor) → decision → grounding.
  Existing reasons and their order relative to each other are unchanged.

---

## [0.25.0] — 2026-08-02

### Added

- **`iga --version` / `iga -V`** — prints the installed version and exits. Eager, so it
  answers before the startup CVE check runs: asking which version is installed must work
  offline and return immediately. Previously the only way to read the version was
  importing `__version__` or reading `tool_version` out of a workshop manifest.

### Changed

- **Ported to the mcp 2.x SDK; the `[mcp]` extra now requires `mcp>=2,<3`.** mcp 2.0.0
  removed `mcp.server.fastmcp` and replaced it with `mcp.server.mcpserver.MCPServer`. The
  surface `build_server()` uses is unchanged across that rename — `instructions=`, the
  `@server.tool()` decorator, `run()` defaulting to stdio, `streamable_http_app()` — so the
  port is the import and the class name. **This raises the floor: mcp 1.x no longer works
  with the extra.** No compatibility shim, deliberately — a dual-path import would double
  the untested surface for a dependency touched in exactly one place. All seven MCP tools
  register unchanged.
- The `cli.py` callback docstring no longer carries a hardcoded version. It had drifted to
  `v0.22.0` and could never be noticed, because `typer.Typer(help=...)` takes precedence
  over the callback docstring, so the literal was never rendered.

### Fixed

- **WebSocket auth bypass in `OrgAuthMiddleware`** (`iga-mcp-remote`, `[mcp]` extra).
  Every non-HTTP ASGI scope was forwarded straight to the wrapped MCP app — ahead of the
  bearer-token check, the per-org rate limiter, and the per-org store binding. Only
  `lifespan` passes through now, because startup and shutdown carry no request identity;
  WebSocket scopes are closed at handshake with 1008 regardless of any token presented,
  and other scope types are dropped. **Not known to be exploitable in any shipped
  release**: `streamable_http_app()` mounts a single `/mcp` route and no WebSocket route,
  so nothing sat behind the gap. It is fixed because that was a property of what the SDK
  happens to build, not a guarantee the guard could rely on — and the 2.x port changes
  exactly that surface. Regression-tested.

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
