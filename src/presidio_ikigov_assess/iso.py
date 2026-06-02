"""ISO/IEC 42001 clause-level coverage engine for the IKI-Gov Assessment Tool.

Given the affirmed checklist items, this computes how well each ISO/IEC 42001
clause group (clauses 4–10 and Annex A controls) is evidenced:

  - covered  — every checklist item mapped to the clause is affirmed.
  - partial  — some, but not all, mapped items are affirmed.
  - gap      — no mapped item is affirmed.

Items that are skipped or denied count as *not affirmed* (outstanding) — a
conservative stance: skipping an item does not earn clause coverage. The
item→clause mapping lives in ``checklist.ISO_CLAUSES_BY_ITEM``; this engine is
generic over whatever that orientation matrix says.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from presidio_ikigov_assess.checklist import (
    ISO_CLAUSE_ORDER,
    ITEMS_BY_ISO_CLAUSE,
    ChecklistItem,
)


class Coverage(str, Enum):
    COVERED = "covered"
    PARTIAL = "partial"
    GAP = "gap"


@dataclass(frozen=True)
class ClauseCoverage:
    clause: str
    status: Coverage
    total: int  # mapped items
    affirmed: int  # affirmed mapped items
    outstanding: tuple[ChecklistItem, ...]  # mapped items not affirmed


def evaluate_clause(clause: str, affirmed: frozenset[str]) -> ClauseCoverage:
    """Evaluate coverage of a single ISO clause group given affirmed item IDs."""
    items = ITEMS_BY_ISO_CLAUSE.get(clause, [])
    outstanding = tuple(item for item in items if item.id not in affirmed)
    affirmed_count = len(items) - len(outstanding)

    if items and affirmed_count == len(items):
        status = Coverage.COVERED
    elif affirmed_count == 0:
        status = Coverage.GAP
    else:
        status = Coverage.PARTIAL

    return ClauseCoverage(
        clause=clause,
        status=status,
        total=len(items),
        affirmed=affirmed_count,
        outstanding=outstanding,
    )


def evaluate_iso_coverage(affirmed: frozenset[str]) -> dict[str, ClauseCoverage]:
    """Return ISO/IEC 42001 coverage for every clause group, in report order."""
    return {clause: evaluate_clause(clause, affirmed) for clause in ISO_CLAUSE_ORDER}
