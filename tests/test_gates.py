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


# ── v0.3.0: risk-class-aware thresholds & strict policy ──────────────────────


def _partition_one_skip(gate: str):
    """Return (affirmed, skipped) where one G0 item is skipped, rest affirmed."""
    ids = list(_gate_ids(gate))
    return frozenset(ids[1:]), frozenset([ids[0]])


def test_low_risk_forgives_skips_to_open():
    affirmed, skipped = _partition_one_skip("G0")
    result = evaluate_gate("G0", affirmed, skipped, risk_class="low")
    assert result.status == GateStatus.OPEN
    assert result.blocking_skips == ()


def test_medium_risk_skips_stay_partial():
    affirmed, skipped = _partition_one_skip("G0")
    result = evaluate_gate("G0", affirmed, skipped, risk_class="medium")
    assert result.status == GateStatus.PARTIAL
    assert result.blocking_skips == ()


def test_high_risk_skips_block():
    affirmed, skipped = _partition_one_skip("G0")
    result = evaluate_gate("G0", affirmed, skipped, risk_class="high")
    assert result.status == GateStatus.BLOCKED
    assert {i.id for i in result.blocking_skips} == skipped


def test_strict_blocks_skips_at_any_risk():
    affirmed, skipped = _partition_one_skip("G0")
    result = evaluate_gate("G0", affirmed, skipped, risk_class="low", strict=True)
    # strict overrides low-risk forgiveness
    assert result.status == GateStatus.BLOCKED
    assert {i.id for i in result.blocking_skips} == skipped


def test_strict_all_affirmed_is_open():
    result = evaluate_gate("G0", _gate_ids("G0"), frozenset(), risk_class="high", strict=True)
    assert result.status == GateStatus.OPEN
    assert result.blocking_skips == ()


@pytest.mark.parametrize("risk", ["low", "medium", "high"])
def test_denied_always_blocks_regardless_of_risk(risk):
    # One denied item (not affirmed, not skipped) blocks at every risk class.
    ids = list(_gate_ids("G0"))
    affirmed = frozenset(ids[1:])  # first denied
    result = evaluate_gate("G0", affirmed, frozenset(), risk_class=risk)
    assert result.status == GateStatus.BLOCKED
    assert len(result.blocking_items) == 1


def test_evaluate_all_gates_threads_policy():
    from presidio_ikigov_assess.scoring import all_item_ids

    # Skip everything; at low risk all gates should be OPEN (skips forgiven).
    results = evaluate_all_gates(frozenset(), all_item_ids(), risk_class="low")
    assert all(r.status == GateStatus.OPEN for r in results.values())
