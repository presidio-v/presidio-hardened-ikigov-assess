"""Gate readiness engine for the IKI-Gov Assessment Tool.

A gate's *partition* — which mapped items are affirmed, denied (neither affirmed
nor skipped), or skipped — is policy-free and depends only on the answers. The
*status* (OPEN / PARTIAL / BLOCKED) is then resolved from that partition under a
risk-class-aware policy (v0.3.0):

  - low risk     — skips are forgiven; a gate with no denials is OPEN even if
                   some mapped items are skipped (PARTIAL "suffices" to open).
  - medium risk  — denials block; remaining skips leave the gate PARTIAL.
  - high risk    — strict by default: skips on gate-critical items are not
                   permitted and count as blockers (equivalent to ``--strict``).

``--strict`` forces high-risk behaviour at any risk class. When strict turns
skips into blockers, those items are surfaced separately as ``blocking_skips``
so the report can explain *why* an otherwise-PARTIAL gate is BLOCKED.

In CI mode, ``--assert-gate Gn`` exits with a status-specific code:
0 OPEN, 2 PARTIAL, 3 BLOCKED (1 remains the general error code).
"""

from __future__ import annotations

from dataclasses import dataclass, field
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
    # Skipped items that block the gate under the active policy (strict / high
    # risk). Empty unless skips are disqualifying; subset of skipped_items.
    blocking_skips: tuple[ChecklistItem, ...] = field(default_factory=tuple)


def _resolve_status(
    blocking: list[ChecklistItem],
    skipped: list[ChecklistItem],
    risk_class: str,
    strict_effective: bool,
) -> GateStatus:
    """Map a gate partition to a status under the active risk policy."""
    if blocking or (strict_effective and skipped):
        return GateStatus.BLOCKED
    if skipped:
        # No denials and skips are permitted: forgiven at low risk, else PARTIAL.
        return GateStatus.OPEN if risk_class == "low" else GateStatus.PARTIAL
    return GateStatus.OPEN


def evaluate_gate(
    gate: str,
    affirmed: frozenset[str],
    skipped: frozenset[str],
    risk_class: str = "medium",
    strict: bool = False,
) -> GateResult:
    """Evaluate readiness for *gate* given the affirmed and skipped item IDs.

    Any item that is neither affirmed nor skipped is considered denied. The
    status is resolved under the *risk_class* / *strict* policy described in the
    module docstring; ``--strict`` is implied at ``risk_class == "high"``.
    """
    if gate not in VALID_GATES:
        raise ValueError(f"Unknown gate {gate!r}. Valid gates: {sorted(VALID_GATES)}")
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

    strict_effective = strict or risk_class == "high"
    blocking_skips = tuple(skipped_items) if (strict_effective and skipped_items) else ()
    status = _resolve_status(blocking, skipped_items, risk_class, strict_effective)

    return GateResult(
        gate=gate,
        status=status,
        blocking_items=tuple(blocking),
        skipped_items=tuple(skipped_items),
        blocking_skips=blocking_skips,
    )


def evaluate_all_gates(
    affirmed: frozenset[str],
    skipped: frozenset[str],
    risk_class: str = "medium",
    strict: bool = False,
) -> dict[str, GateResult]:
    """Return gate readiness results for all gates G0–G5 in order."""
    return {
        gate: evaluate_gate(gate, affirmed, skipped, risk_class, strict)
        for gate in sorted(VALID_GATES)
    }
