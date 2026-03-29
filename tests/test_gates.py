"""Tests for the gate readiness engine."""

import pytest

from presidio_ikigov_assess.checklist import ITEMS_BY_GATE, VALID_GATES
from presidio_ikigov_assess.gates import GateResult, GateStatus, evaluate_all_gates, evaluate_gate


def _gate_ids(gate: str) -> frozenset[str]:
    return frozenset(item.id for item in ITEMS_BY_GATE[gate])


# ── G0 tests ─────────────────────────────────────────────────────────────────


def test_g0_open_when_all_affirmed():
    result = evaluate_gate("G0", _gate_ids("G0"), frozenset())
    assert result.status == GateStatus.OPEN
    assert len(result.blocking_items) == 0
    assert len(result.skipped_items) == 0


def test_g0_blocked_when_one_denied():
    g0_ids = list(_gate_ids("G0"))
    affirmed = frozenset(g0_ids[1:])  # skip first → denied
    result = evaluate_gate("G0", affirmed, frozenset())
    assert result.status == GateStatus.BLOCKED
    assert len(result.blocking_items) >= 1


def test_g0_partial_when_one_skipped():
    g0_ids = list(_gate_ids("G0"))
    affirmed = frozenset(g0_ids[1:])
    skipped = frozenset([g0_ids[0]])
    result = evaluate_gate("G0", affirmed, skipped)
    assert result.status == GateStatus.PARTIAL
    assert g0_ids[0] in [item.id for item in result.skipped_items]


# ── All gates: open when all affirmed ────────────────────────────────────────


@pytest.mark.parametrize("gate", sorted(VALID_GATES))
def test_gate_open_when_all_gate_items_affirmed(gate):
    affirmed = _gate_ids(gate)
    result = evaluate_gate(gate, affirmed, frozenset())
    assert result.status == GateStatus.OPEN


@pytest.mark.parametrize("gate", sorted(VALID_GATES))
def test_gate_blocked_when_none_affirmed(gate):
    result = evaluate_gate(gate, frozenset(), frozenset())
    assert result.status == GateStatus.BLOCKED
    assert len(result.blocking_items) == len(ITEMS_BY_GATE[gate])


@pytest.mark.parametrize("gate", sorted(VALID_GATES))
def test_gate_partial_when_all_skipped(gate):
    skipped = _gate_ids(gate)
    result = evaluate_gate(gate, frozenset(), skipped)
    assert result.status == GateStatus.PARTIAL


# ── evaluate_all_gates ────────────────────────────────────────────────────────


def test_evaluate_all_gates_returns_all_six():
    results = evaluate_all_gates(frozenset(), frozenset())
    assert set(results.keys()) == VALID_GATES


def test_evaluate_all_gates_all_open():
    from presidio_ikigov_assess.scoring import all_item_ids

    all_ids = all_item_ids()
    results = evaluate_all_gates(all_ids, frozenset())
    for gate, result in results.items():
        assert result.status == GateStatus.OPEN, f"Gate {gate} expected OPEN"


def test_evaluate_all_gates_all_blocked():
    results = evaluate_all_gates(frozenset(), frozenset())
    for gate, result in results.items():
        assert result.status == GateStatus.BLOCKED, f"Gate {gate} expected BLOCKED"


# ── Blocking / skipped item reporting ────────────────────────────────────────


def test_blocking_items_not_in_affirmed():
    result = evaluate_gate("G0", frozenset(), frozenset())
    for item in result.blocking_items:
        assert item.id not in frozenset()


def test_skipped_items_are_those_in_skip_set():
    g0_ids = list(_gate_ids("G0"))
    skipped = frozenset([g0_ids[0]])
    affirmed = frozenset(g0_ids[1:])
    result = evaluate_gate("G0", affirmed, skipped)
    assert {item.id for item in result.skipped_items} == skipped


def test_gate_result_type():
    result = evaluate_gate("G1", frozenset(), frozenset())
    assert isinstance(result, GateResult)
    assert isinstance(result.status, GateStatus)
