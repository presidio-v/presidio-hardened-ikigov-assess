"""Tests for the M1–M6 scoring engine."""

import pytest

from presidio_ikigov_assess.checklist import ITEMS_BY_DIMENSION, VALID_DIMENSIONS
from presidio_ikigov_assess.scoring import AssessmentScores, DimensionScore, compute_scores


def _all_ids() -> frozenset[str]:
    from presidio_ikigov_assess.scoring import all_item_ids

    return all_item_ids()


def _dim_ids(dim: str) -> frozenset[str]:
    return frozenset(item.id for item in ITEMS_BY_DIMENSION[dim])


def test_all_affirmed_gives_100():
    all_ids = _all_ids()
    scores = compute_scores(all_ids, frozenset(), "medium")
    for dim in VALID_DIMENSIONS:
        assert scores.dimensions[dim].score == pytest.approx(100.0)
    assert scores.overall == pytest.approx(100.0)


def test_none_affirmed_gives_0():
    scores = compute_scores(frozenset(), frozenset(), "medium")
    for dim in VALID_DIMENSIONS:
        assert scores.dimensions[dim].score == pytest.approx(0.0)
    assert scores.overall == pytest.approx(0.0)


def test_all_skipped_gives_0():
    all_ids = _all_ids()
    scores = compute_scores(frozenset(), all_ids, "medium")
    for dim in VALID_DIMENSIONS:
        assert scores.dimensions[dim].score == pytest.approx(0.0)
    assert scores.overall == pytest.approx(0.0)


def test_m1_half_affirmed():
    m1_ids = list(_dim_ids("M1"))
    half = frozenset(m1_ids[: len(m1_ids) // 2])
    scores = compute_scores(half, frozenset(), "medium")
    assert 0.0 < scores.dimensions["M1"].score < 100.0


def test_risk_class_does_not_change_relative_score():
    """Risk class scales all weights equally so the percentage is unchanged."""
    m1_ids = _dim_ids("M1")
    half = frozenset(list(m1_ids)[: len(m1_ids) // 2])
    for risk in ("low", "medium", "high"):
        s = compute_scores(half, frozenset(), risk)
        # Score for M1 should be identical regardless of risk class
        # (weights cancel in numerator/denominator)
        assert s.dimensions["M1"].score == pytest.approx(
            compute_scores(half, frozenset(), "low").dimensions["M1"].score
        )


def test_skipped_excluded_from_denominator():
    """Skipping an item should raise the score for the remaining items."""
    m1_ids = list(_dim_ids("M1"))
    # Affirm all but one; skip the last one
    affirmed = frozenset(m1_ids[:-1])
    skipped = frozenset([m1_ids[-1]])
    scores_with_skip = compute_scores(affirmed, skipped, "medium")
    scores_no_skip = compute_scores(affirmed, frozenset(), "medium")
    assert scores_with_skip.dimensions["M1"].score > scores_no_skip.dimensions["M1"].score


def test_overall_is_mean_of_dimensions():
    all_ids = _all_ids()
    scores = compute_scores(all_ids, frozenset(), "high")
    dim_mean = sum(scores.dimensions[d].score for d in VALID_DIMENSIONS) / len(VALID_DIMENSIONS)
    assert scores.overall == pytest.approx(dim_mean, abs=0.1)


def test_dimension_score_counts():
    m1_ids = list(_dim_ids("M1"))
    affirmed = frozenset([m1_ids[0]])
    skipped = frozenset([m1_ids[1]])
    scores = compute_scores(affirmed, skipped, "medium")
    ds = scores.dimensions["M1"]
    assert ds.affirmed_count == 1
    assert ds.skipped_count == 1
    assert ds.denied_count == ds.total_count - 2


def test_return_type():
    scores = compute_scores(frozenset(), frozenset(), "low")
    assert isinstance(scores, AssessmentScores)
    for dim in VALID_DIMENSIONS:
        assert isinstance(scores.dimensions[dim], DimensionScore)
