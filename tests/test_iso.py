"""Tests for the ISO/IEC 42001 clause-coverage engine."""

from __future__ import annotations

import pytest

from presidio_ikigov_assess.checklist import (
    ISO_CLAUSE_ORDER,
    ITEMS_BY_ISO_CLAUSE,
    VALID_ISO_CLAUSES,
)
from presidio_ikigov_assess.iso import (
    ClauseCoverage,
    Coverage,
    evaluate_clause,
    evaluate_iso_coverage,
)
from presidio_ikigov_assess.scoring import all_item_ids


def _clause_ids(clause: str) -> frozenset[str]:
    return frozenset(item.id for item in ITEMS_BY_ISO_CLAUSE[clause])


def test_every_clause_has_at_least_one_item():
    # No clause group should be permanently uncoverable.
    for clause in ISO_CLAUSE_ORDER:
        assert len(ITEMS_BY_ISO_CLAUSE[clause]) >= 1, f"clause {clause} has no items"


def test_coverage_returns_all_clauses_in_order():
    coverage = evaluate_iso_coverage(frozenset())
    assert list(coverage.keys()) == list(ISO_CLAUSE_ORDER)


def test_all_affirmed_is_all_covered():
    coverage = evaluate_iso_coverage(all_item_ids())
    assert all(c.status is Coverage.COVERED for c in coverage.values())
    assert all(c.outstanding == () for c in coverage.values())


def test_none_affirmed_is_all_gap():
    coverage = evaluate_iso_coverage(frozenset())
    assert all(c.status is Coverage.GAP for c in coverage.values())


@pytest.mark.parametrize("clause", sorted(VALID_ISO_CLAUSES))
def test_clause_covered_when_all_its_items_affirmed(clause):
    result = evaluate_clause(clause, _clause_ids(clause))
    assert result.status is Coverage.COVERED
    assert result.affirmed == result.total
    assert result.outstanding == ()


def test_clause_partial_when_some_affirmed():
    clause = "5"
    ids = sorted(_clause_ids(clause))
    assert len(ids) >= 2  # need at least two items for a partial state
    affirmed = frozenset(ids[:1])
    result = evaluate_clause(clause, affirmed)
    assert result.status is Coverage.PARTIAL
    assert result.affirmed == 1
    assert {item.id for item in result.outstanding} == set(ids[1:])


def test_skipped_items_do_not_earn_coverage():
    # The engine only credits affirmed IDs; skipped items are simply absent
    # from the affirmed set and therefore remain outstanding.
    clause = "5"
    ids = _clause_ids(clause)
    result = evaluate_clause(clause, frozenset())  # nothing affirmed (all skipped/denied)
    assert result.status is Coverage.GAP
    assert {item.id for item in result.outstanding} == ids


def test_clause_coverage_type():
    result = evaluate_clause("8", frozenset())
    assert isinstance(result, ClauseCoverage)
    assert isinstance(result.status, Coverage)
