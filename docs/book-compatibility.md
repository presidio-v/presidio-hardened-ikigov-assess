<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 PRESIDIO Group -->
# Book compatibility

Anhang B of *KI und IT-Governance* (Stantchev, Springer, ISBN 978-3-662-74093-4) documents
`iga` as of **v0.1.0**, with the proof corrections of October 2026 applied. The tool has moved
on since then. This page records, claim by claim, how the current release relates to the
printed text, so a reader working from the book knows what still holds and what changed.

`tests/test_book_example.py` runs the book's commands verbatim and asserts the lines a reader
compares against the page. A release that breaks one of them fails CI.

## Commands and flags

Every command printed in Anhang B runs unchanged:

| Book | Status |
|---|---|
| `pip install presidio-hardened-ikigov-assess`, extra `[audit]` | unchanged |
| `iga assess --interactive --lang de --risk-class high --use-case …` | unchanged; answer keys Y / N / S are accepted under `--lang de` too (the German prompt shows J / N / Ü) |
| `iga assess --use-case … --risk-class … --affirm … --skip … --lang en` | unchanged |
| `iga gate --gate G2 …` | unchanged |
| `iga report … --format markdown` (console output) | unchanged; `--output FILE` added in v0.4.0 |
| `iga gate --gate G1 … --assert-gate G1` | unchanged; exit codes see below |
| `--no-dep-check`, `IGA_MAX_ASSESSMENTS` (default 100), `~/.iga/security.log` | unchanged |

Python 3.10 or newer is required (the printed text, after correction, says the same).

## Behaviour that changed after v0.1.0

| Since | Change | Effect on a book reader |
|---|---|---|
| v0.3.0 | `--assert-gate` exits 0 OPEN / 2 PARTIAL / 3 BLOCKED; 1 is now reserved for errors. v0.1.0 exited 1 for anything not OPEN. | A pipeline that only tests for non-zero still works. |
| v0.3.0 | `high` is strict: a skipped gate-critical item blocks the gate (`--strict` forces this at any class). | This is the rule the book states. v0.1.0 did not enforce it, so the uncorrected example (high, G2 PARTIAL) matched the old code but not the printed rule. |
| v0.3.0 | `low` forgives skips: a gate with skips and no denials is OPEN, not PARTIAL. | The book's PARTIAL definition holds for `medium`. |
| v0.4.0 | Report export to file (`--output`). | Additive. |
| v0.6.0 | Persistence (`--save`, SQLite, file mode 0600). | Additive. |
| v0.13.0 | Assessment output adds an evidence line under the overall score (extended in v0.26.0 with asserted, uncounted items). | Additive. |

The version table in the book shows the plan as of v0.1.0. The actual history is in the
[README roadmap](../README.md#roadmap), `CHANGELOG.md` (v0.20.0 onward) and `PRESIDIO-REQ.md`
(v0.1.0–v0.19.2).

## The worked example

The example in Anhang B is reproduced by:

```bash
iga assess --use-case fraud-scoring --risk-class medium --lang en \
  --affirm S1,S2,S3,S4,S5,D1,D2,D4,D5,T1,T2,T3,T4,O1,O2,O3,I1 --skip D3
```

M1 100, M2 100, M3 100, M4 50, M5 20, M6 60, overall 71.7 %; G0 and G1 OPEN, G2 PARTIAL with
D3 skipped, G3 BLOCKED by T5 alone, G4 and G5 BLOCKED. This is the only answer set consistent
with all six gate lines: G1 OPEN requires S1–S5, D1 and D5; G2 PARTIAL with only D3 skipped
requires D2, D4 and T1–T3; G3 blocked by T5 alone requires T4, O1 and O3. At `--risk-class high`
the same answers turn G2 into `BLOCKED — blocking (skips not permitted): D3`.

The printed block keeps the v0.1.0 layout (ASCII bars, no blocking items listed for G4 and G5);
the current renderer uses block bars, lists every blocking item, and shortens item texts at a
word boundary.

## Scoring

The formula is as printed: affirmed weight over non-skipped weight per dimension, skips excluded
from both, overall score the mean of M1–M6. The risk-class factor (1.0 / 1.5 / 2.0) applies to
every item of a class alike, so it cancels within each dimension and **does not change any score**.
The risk class acts through the gate policy above, not through the numbers.

## Gates

Numbering G0–G5 is the same throughout. The tool labels gates by lifecycle transition, as in the
framework chapter and the Anhang B gate table; Teil IV names them by purpose:

| Gate | Tool label (transition) | Teil IV name |
|---|---|---|
| G0 | Kontext → Konzeption | Projektstart |
| G1 | Konzeption → Entwicklung | Daten- und Konzeptfreigabe |
| G2 | Entwicklung → Freigabe | Modellfreigabe |
| G3 | Freigabe → Betrieb | Produktionsfreigabe |
| G4 | Betrieb → Anpassung | Betriebsreview |
| G5 | Anpassung → Außerbetriebnahme | Außerbetriebnahme |

The Anhang B item table gives *primary* gates per block. The tool maps each item individually,
which differs from the block view in three places: T4 and T5 map to G3 only (the table lists
G2, G3), and O5 maps to G4 and G5 (the table lists G3, G4 for O1–O5). The per-item mapping is
authoritative; see `src/presidio_ikigov_assess/checklist.py`.
