"""M1–M6 scoring engine for the IKI-Gov Assessment Tool.

Scoring formula (per dimension):
    score_m(dim) = sum(weight_i for affirmed i in dim)
                   / sum(weight_i for non-skipped i in dim)
                   * 100

Skipped items are excluded from both numerator and denominator.
Not-affirmed (denied) items contribute 0 to the numerator but are
included in the denominator.

Overall maturity score = arithmetic mean of M1–M6 individual scores.
"""

from __future__ import annotations

from dataclasses import dataclass

from presidio_ikigov_assess.checklist import (
    CHECKLIST,
    ITEMS_BY_DIMENSION,
    VALID_DIMENSIONS,
)


@dataclass(frozen=True)
class DimensionScore:
    dimension: str
    score: float  # 0.0–100.0
    affirmed_count: int
    denied_count: int
    skipped_count: int
    total_count: int


@dataclass(frozen=True)
class AssessmentScores:
    dimensions: dict[str, DimensionScore]
    overall: float  # arithmetic mean of M1–M6 scores


def compute_scores(
    affirmed: frozenset[str],
    skipped: frozenset[str],
    risk_class: str,
) -> AssessmentScores:
    """Compute M1–M6 dimension scores and overall maturity for the given answers.

    Args:
        affirmed:   set of item IDs answered "yes".
        skipped:    set of item IDs explicitly skipped.
        risk_class: one of "low", "medium", "high".

    Returns:
        AssessmentScores with per-dimension and overall scores.
    """
    dimension_scores: dict[str, DimensionScore] = {}

    for dim in sorted(VALID_DIMENSIONS):
        items = ITEMS_BY_DIMENSION[dim]
        numerator = 0.0
        denominator = 0.0
        affirmed_count = 0
        denied_count = 0
        skipped_count = 0

        for item in items:
            w = item.weight(risk_class)
            if item.id in affirmed:
                numerator += w
                denominator += w
                affirmed_count += 1
            elif item.id in skipped:
                # skipped: excluded from both numerator and denominator
                skipped_count += 1
            else:
                # denied: added to denominator only
                denominator += w
                denied_count += 1

        if denominator > 0:
            score = (numerator / denominator) * 100.0
        else:
            # All items skipped — conservative zero
            score = 0.0

        dimension_scores[dim] = DimensionScore(
            dimension=dim,
            score=round(score, 1),
            affirmed_count=affirmed_count,
            denied_count=denied_count,
            skipped_count=skipped_count,
            total_count=len(items),
        )

    overall = _mean([ds.score for ds in dimension_scores.values()])

    return AssessmentScores(
        dimensions=dimension_scores,
        overall=round(overall, 1),
    )


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def all_item_ids() -> frozenset[str]:
    return frozenset(item.id for item in CHECKLIST)
