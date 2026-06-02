"""Tests for the maturity-trend engine."""

from __future__ import annotations

import pytest

from presidio_ikigov_assess.store import SavedAssessment
from presidio_ikigov_assess.trend import (
    TrendError,
    compute_trend,
    select_trend_pair,
)


def _mk(ts: str, overall: float, scores=None, gates=None) -> SavedAssessment:
    return SavedAssessment(
        id=0,
        use_case="uc",
        risk_class="high",
        timestamp=ts,
        lang="en",
        answers={"affirmed": [], "skipped": []},
        scores=scores or {"M1": overall, "overall": overall},
        gates=gates or {"G0": "OPEN"},
    )


# ── select_trend_pair ────────────────────────────────────────────────────────


def test_select_default_latest_vs_previous():
    # newest-first list
    a = [_mk("2026-03-01T00:00:00Z", 90.0), _mk("2026-01-01T00:00:00Z", 40.0)]
    earlier, later = select_trend_pair(a)
    assert earlier.timestamp.startswith("2026-01-01")
    assert later.timestamp.startswith("2026-03-01")


def test_select_requires_two():
    with pytest.raises(TrendError):
        select_trend_pair([_mk("2026-01-01T00:00:00Z", 40.0)])


def test_select_empty_raises():
    with pytest.raises(TrendError):
        select_trend_pair([])


def test_select_date_window_picks_first_and_last_in_range():
    a = [
        _mk("2026-05-01T00:00:00Z", 95.0),
        _mk("2026-03-15T00:00:00Z", 70.0),
        _mk("2026-02-01T00:00:00Z", 50.0),
        _mk("2026-01-01T00:00:00Z", 30.0),
    ]
    earlier, later = select_trend_pair(a, from_date="2026-02-01", to_date="2026-03-31")
    assert earlier.timestamp.startswith("2026-02-01")
    assert later.timestamp.startswith("2026-03-15")


def test_select_window_too_few_raises():
    a = [_mk("2026-05-01T00:00:00Z", 95.0), _mk("2026-01-01T00:00:00Z", 30.0)]
    with pytest.raises(TrendError):
        select_trend_pair(a, from_date="2026-02-01", to_date="2026-03-31")


def test_select_open_ended_from_only():
    a = [_mk("2026-05-01T00:00:00Z", 95.0), _mk("2026-03-01T00:00:00Z", 70.0)]
    earlier, later = select_trend_pair(a, from_date="2026-01-01")
    assert earlier.timestamp.startswith("2026-03-01")
    assert later.timestamp.startswith("2026-05-01")


# ── compute_trend ────────────────────────────────────────────────────────────


def test_compute_trend_dimension_deltas_and_directions():
    earlier = _mk("2026-01-01T00:00:00Z", 0.0, scores={"M1": 20.0, "M2": 80.0, "overall": 50.0})
    later = _mk("2026-03-01T00:00:00Z", 0.0, scores={"M1": 60.0, "M2": 80.0, "overall": 70.0})
    result = compute_trend(earlier, later)

    by_dim = {d.dimension: d for d in result.dimensions}
    assert by_dim["M1"].delta == 40.0 and by_dim["M1"].direction == "up"
    assert by_dim["M2"].delta == 0.0 and by_dim["M2"].direction == "same"
    # dimensions absent from scores default to 0.0 → same
    assert by_dim["M3"].direction == "same"
    assert result.overall_delta == 20.0


def test_compute_trend_negative_direction():
    earlier = _mk("2026-01-01T00:00:00Z", 80.0)
    later = _mk("2026-03-01T00:00:00Z", 50.0)
    result = compute_trend(earlier, later)
    assert result.overall_delta == -30.0
    assert result.dimensions[0].direction == "down"


def test_compute_trend_gate_transitions():
    earlier = _mk("2026-01-01T00:00:00Z", 0.0, gates={"G0": "BLOCKED", "G1": "OPEN"})
    later = _mk("2026-03-01T00:00:00Z", 0.0, gates={"G0": "PARTIAL", "G1": "OPEN"})
    result = compute_trend(earlier, later)
    by_gate = {g.gate: g for g in result.gate_transitions}
    assert by_gate["G0"].earlier_status == "BLOCKED"
    assert by_gate["G0"].later_status == "PARTIAL"
    assert by_gate["G0"].changed is True
    assert by_gate["G1"].changed is False
    # gate missing from both snapshots → "—", unchanged
    assert by_gate["G5"].earlier_status == "—"
    assert by_gate["G5"].changed is False
