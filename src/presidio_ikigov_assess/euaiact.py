"""EU AI Act gate-to-article coverage engine for high-risk systems (v0.8.0).

For high-risk AI systems under Annex III, IKI-Gov gates G0–G5 generate the
evidence required by EU AI Act Articles 9–18 and 72. The book's orientation matrix
(``tab:framework-euaiact-gates``) maps each *gate* to its primary articles; this
module inverts that to article→gates and derives each article's coverage from the
current gate readiness:

  - OPEN     — every gate associated with the article is OPEN.
  - BLOCKED  — every associated gate is BLOCKED.
  - PARTIAL  — a mix (some evidence in place, some outstanding).

The article→gate mapping below is transcribed verbatim (inverted) from the book
table as corrected in the October 2026 proofs (G4 cites Art. 9 in conjunction with
Art. 72; G5 cites Art. 18 and 17, no longer Art. 11); it is the authoritative
source — do not derive.
"""

from __future__ import annotations

from dataclasses import dataclass

from presidio_ikigov_assess.gates import GateResult

# Articles in display order: Chapter III Section 2–3 high-risk obligations, then
# post-market monitoring (Chapter IX).
ARTICLE_ORDER: tuple[str, ...] = ("9", "10", "11", "12", "13", "14", "15", "17", "18", "72")

# Article → gates, inverted from the book gate→article table:
#   G0: Art 9, 17     G1: Art 10, 9      G2: Art 9, 11, 15
#   G3: Art 11, 13, 14, 17               G4: Art 9 + 72, 12, 15 G5: Art 18, 17
EU_AI_ACT_ARTICLE_GATES: dict[str, tuple[str, ...]] = {
    "9": ("G0", "G1", "G2", "G4"),
    "10": ("G1",),
    "11": ("G2", "G3"),
    "12": ("G4",),
    "13": ("G3",),
    "14": ("G3",),
    "15": ("G2", "G4"),
    "17": ("G0", "G3", "G5"),
    "18": ("G5",),
    "72": ("G4",),
}


@dataclass(frozen=True)
class ArticleCoverage:
    article: str
    status: str  # OPEN | PARTIAL | BLOCKED
    gate_statuses: tuple[tuple[str, str], ...]  # ordered (gate, status) for this article
    blocking: tuple[tuple[str, str], ...]  # non-OPEN (gate, status) pairs


def evaluate_euaiact(gate_results: dict[str, GateResult]) -> dict[str, ArticleCoverage]:
    """Derive per-article EU AI Act coverage from gate readiness results."""
    coverage: dict[str, ArticleCoverage] = {}
    for article in ARTICLE_ORDER:
        gates = EU_AI_ACT_ARTICLE_GATES[article]
        gate_statuses = tuple((g, gate_results[g].status.value) for g in gates)
        blocking = tuple((g, s) for g, s in gate_statuses if s != "OPEN")

        if not blocking:
            status = "OPEN"
        elif all(s == "BLOCKED" for _, s in gate_statuses):
            status = "BLOCKED"
        else:
            status = "PARTIAL"

        coverage[article] = ArticleCoverage(
            article=article,
            status=status,
            gate_statuses=gate_statuses,
            blocking=blocking,
        )
    return coverage
