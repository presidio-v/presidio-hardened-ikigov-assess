"""Tests for the EU AI Act gate-to-article coverage engine."""

from __future__ import annotations

import pytest

from presidio_ikigov_assess.checklist import ITEMS_BY_GATE, VALID_GATES
from presidio_ikigov_assess.euaiact import (
    ARTICLE_ORDER,
    EU_AI_ACT_ARTICLE_GATES,
    evaluate_euaiact,
)
from presidio_ikigov_assess.gates import evaluate_all_gates
from presidio_ikigov_assess.scoring import all_item_ids


def test_article_mapping_references_valid_gates():
    for article, gates in EU_AI_ACT_ARTICLE_GATES.items():
        assert gates, f"Art. {article} has no gates"
        for g in gates:
            assert g in VALID_GATES


def test_every_article_present_and_ordered():
    coverage = evaluate_euaiact(evaluate_all_gates(frozenset(), frozenset()))
    assert list(coverage.keys()) == list(ARTICLE_ORDER)


def test_all_affirmed_all_articles_open():
    gates = evaluate_all_gates(all_item_ids(), frozenset())
    coverage = evaluate_euaiact(gates)
    assert all(c.status == "OPEN" for c in coverage.values())
    assert all(c.blocking == () for c in coverage.values())


def test_nothing_affirmed_all_articles_blocked():
    coverage = evaluate_euaiact(evaluate_all_gates(frozenset(), frozenset()))
    assert all(c.status == "BLOCKED" for c in coverage.values())


def test_single_gate_article_open_when_its_gate_open():
    # Art. 10 maps to G1 only; affirm all G1 items → Art. 10 OPEN.
    g1 = frozenset(item.id for item in ITEMS_BY_GATE["G1"])
    coverage = evaluate_euaiact(evaluate_all_gates(g1, frozenset()))
    assert coverage["10"].status == "OPEN"


def test_multi_gate_article_partial_when_some_gates_open():
    # Art. 9 maps to G0,G1,G2,G4. Affirming all G1 items also affirms S1–S3
    # (shared with G0), so G0 and G1 open while G2/G4 stay blocked → PARTIAL.
    g1 = frozenset(item.id for item in ITEMS_BY_GATE["G1"])
    coverage = evaluate_euaiact(evaluate_all_gates(g1, frozenset()))
    art9 = coverage["9"]
    assert art9.status == "PARTIAL"
    blocking_gates = {g for g, _ in art9.blocking}
    assert {"G0", "G1"}.isdisjoint(blocking_gates)
    assert {"G2", "G4"} <= blocking_gates


@pytest.mark.parametrize("article", sorted(EU_AI_ACT_ARTICLE_GATES))
def test_gate_statuses_cover_all_article_gates(article):
    coverage = evaluate_euaiact(evaluate_all_gates(frozenset(), frozenset()))
    cov = coverage[article]
    assert {g for g, _ in cov.gate_statuses} == set(EU_AI_ACT_ARTICLE_GATES[article])
