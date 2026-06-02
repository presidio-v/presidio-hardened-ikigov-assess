"""Maturity-trend engine: deltas between two saved assessments (v0.7.0).

Compares two ``SavedAssessment`` snapshots of the same use case and reports the
per-dimension score delta (M1–M6), the overall maturity delta, and gate status
transitions. Selection of the pair is either "latest vs previous" or the first
and last assessment within a ``--from``/``--to`` date window.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from presidio_ikigov_assess.store import SavedAssessment

_DIMENSIONS = ("M1", "M2", "M3", "M4", "M5", "M6")
_GATES = ("G0", "G1", "G2", "G3", "G4", "G5")


class TrendError(ValueError):
    """Raised when a trend cannot be computed (e.g. fewer than two assessments)."""


@dataclass(frozen=True)
class DimensionDelta:
    dimension: str
    earlier: float
    later: float
    delta: float  # later - earlier, rounded
    direction: str  # "up" | "down" | "same"


@dataclass(frozen=True)
class GateTransition:
    gate: str
    earlier_status: str
    later_status: str
    changed: bool


@dataclass(frozen=True)
class TrendResult:
    use_case: str
    earlier_timestamp: str
    later_timestamp: str
    dimensions: tuple[DimensionDelta, ...]
    overall_earlier: float
    overall_later: float
    overall_delta: float
    gate_transitions: tuple[GateTransition, ...]


def _direction(delta: float) -> str:
    if delta > 0:
        return "up"
    if delta < 0:
        return "down"
    return "same"


def select_trend_pair(
    assessments: list[SavedAssessment],
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
) -> tuple[SavedAssessment, SavedAssessment]:
    """Pick the (earlier, later) pair to compare from a newest-first list.

    Without a date window, returns (previous, latest). With ``from_date`` and/or
    ``to_date`` (YYYY-MM-DD), returns the earliest and latest assessments whose
    date falls in the inclusive window. Raises ``TrendError`` if fewer than two
    qualifying assessments exist.
    """
    if from_date is None and to_date is None:
        if len(assessments) < 2:
            raise TrendError("at least two saved assessments are required")
        # newest-first: index 0 is latest, index 1 is the previous run
        return assessments[1], assessments[0]

    lo = from_date or "0000-00-00"
    hi = to_date or "9999-99-99"
    in_window = [a for a in assessments if lo <= a.timestamp[:10] <= hi]
    if len(in_window) < 2:
        raise TrendError("at least two saved assessments are required in the date window")
    # in_window is newest-first → last is earliest, first is latest
    return in_window[-1], in_window[0]


def compute_trend(earlier: SavedAssessment, later: SavedAssessment) -> TrendResult:
    """Compute the trend between two assessments of the same use case."""
    dims: list[DimensionDelta] = []
    for dim in _DIMENSIONS:
        e = float(earlier.scores.get(dim, 0.0))
        latr = float(later.scores.get(dim, 0.0))
        delta = round(latr - e, 1)
        dims.append(
            DimensionDelta(
                dimension=dim,
                earlier=e,
                later=latr,
                delta=delta,
                direction=_direction(delta),
            )
        )

    overall_e = float(earlier.scores.get("overall", 0.0))
    overall_l = float(later.scores.get("overall", 0.0))

    transitions: list[GateTransition] = []
    for gate in _GATES:
        e_status = earlier.gates.get(gate, "—")
        l_status = later.gates.get(gate, "—")
        transitions.append(
            GateTransition(
                gate=gate,
                earlier_status=e_status,
                later_status=l_status,
                changed=e_status != l_status,
            )
        )

    return TrendResult(
        use_case=later.use_case,
        earlier_timestamp=earlier.timestamp,
        later_timestamp=later.timestamp,
        dimensions=tuple(dims),
        overall_earlier=overall_e,
        overall_later=overall_l,
        overall_delta=round(overall_l - overall_e, 1),
        gate_transitions=tuple(transitions),
    )
