"""Framework-agnostic coverage engine over a content pack (v0.16.0).

Reproduces the legacy ISO (item-mapped) and EU AI Act (gate-mapped) coverage:

* ``item`` packs — a target is *covered* if every mapped checklist item is affirmed,
  *gap* if none are, else *partial*.
* ``gate`` packs — a target is *covered* if every mapped gate is OPEN, *gap* if all are
  BLOCKED, else *partial* (gate readiness comes from ``gates.evaluate_all_gates``).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from presidio_ikigov_assess.content.pack import ContentError, ContentPack


class Coverage(str, Enum):
    COVERED = "covered"
    PARTIAL = "partial"
    GAP = "gap"


@dataclass(frozen=True)
class TargetCoverage:
    target: str
    status: Coverage
    total: int  # mapped sources
    satisfied: int  # affirmed items / OPEN gates
    outstanding: tuple[str, ...]  # source ids not satisfied


def evaluate_coverage(
    pack: ContentPack,
    affirmed: frozenset[str],
    gate_results: Mapping[str, object] | None = None,
) -> dict[str, TargetCoverage]:
    """Coverage per target, in the pack's ``target_order``."""
    result: dict[str, TargetCoverage] = {}
    for target in pack.target_order:
        sources = pack.mapping.get(target, ())
        if pack.mapping_kind == "item":
            outstanding = tuple(s for s in sources if s not in affirmed)
            status = _status_item(sources, outstanding)
        else:
            if gate_results is None:
                raise ContentError("gate-mapped pack requires gate_results")
            statuses = [
                getattr(gate_results[g].status, "value", gate_results[g].status) for g in sources
            ]
            outstanding = tuple(g for g, st in zip(sources, statuses, strict=True) if st != "OPEN")
            status = _status_gate(sources, statuses, outstanding)
        result[target] = TargetCoverage(
            target=target,
            status=status,
            total=len(sources),
            satisfied=len(sources) - len(outstanding),
            outstanding=outstanding,
        )
    return result


def _status_item(sources: tuple[str, ...], outstanding: tuple[str, ...]) -> Coverage:
    if sources and not outstanding:
        return Coverage.COVERED
    if len(outstanding) == len(sources):
        return Coverage.GAP
    return Coverage.PARTIAL


def _status_gate(sources, statuses, outstanding) -> Coverage:
    if sources and not outstanding:
        return Coverage.COVERED
    if statuses and all(st == "BLOCKED" for st in statuses):
        return Coverage.GAP
    return Coverage.PARTIAL
