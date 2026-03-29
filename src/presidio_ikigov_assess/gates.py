"""Gate readiness engine for the IKI-Gov Assessment Tool.

Gate status definitions:
  OPEN     — all items mapped to gate Gn are affirmed.
  PARTIAL  — all items are affirmed or skipped; at least one is skipped
             (no item is explicitly denied).
  BLOCKED  — at least one item mapped to Gn is explicitly not affirmed
             (denied: neither affirmed nor skipped).

In parameter mode unmentioned items are treated as denied.

In CI mode, --assert-gate Gn exits with code 1 if the gate is PARTIAL or BLOCKED
(v0.2.0 will introduce distinct exit codes 2/3 for PARTIAL/BLOCKED).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from presidio_ikigov_assess.checklist import ITEMS_BY_GATE, VALID_GATES, ChecklistItem


class GateStatus(str, Enum):
    OPEN = "OPEN"
    PARTIAL = "PARTIAL"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class GateResult:
    gate: str
    status: GateStatus
    blocking_items: tuple[ChecklistItem, ...]  # items that are denied
    skipped_items: tuple[ChecklistItem, ...]  # items that are skipped


def evaluate_gate(
    gate: str,
    affirmed: frozenset[str],
    skipped: frozenset[str],
) -> GateResult:
    """Evaluate readiness for *gate* given the set of affirmed and skipped item IDs.

    Any item that is neither affirmed nor skipped is considered denied.
    """
    items = ITEMS_BY_GATE.get(gate, [])

    blocking: list[ChecklistItem] = []
    skipped_items: list[ChecklistItem] = []

    for item in items:
        if item.id in affirmed:
            continue
        elif item.id in skipped:
            skipped_items.append(item)
        else:
            blocking.append(item)

    if blocking:
        status = GateStatus.BLOCKED
    elif skipped_items:
        status = GateStatus.PARTIAL
    else:
        status = GateStatus.OPEN

    return GateResult(
        gate=gate,
        status=status,
        blocking_items=tuple(blocking),
        skipped_items=tuple(skipped_items),
    )


def evaluate_all_gates(
    affirmed: frozenset[str],
    skipped: frozenset[str],
) -> dict[str, GateResult]:
    """Return gate readiness results for all gates G0–G5 in order."""
    return {gate: evaluate_gate(gate, affirmed, skipped) for gate in sorted(VALID_GATES)}
