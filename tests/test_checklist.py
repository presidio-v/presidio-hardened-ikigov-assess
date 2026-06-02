"""Tests for the IKI-Gov checklist data model."""

from presidio_ikigov_assess.checklist import (
    CHECKLIST,
    ISO_CLAUSES_BY_ITEM,
    ITEM_BY_ID,
    ITEMS_BY_DIMENSION,
    ITEMS_BY_GATE,
    RISK_WEIGHTS,
    VALID_DIMENSIONS,
    VALID_GATES,
    VALID_ISO_CLAUSES,
    VALID_ITEM_IDS,
)


def test_every_item_has_valid_iso_clauses():
    for item in CHECKLIST:
        clauses = item.iso_clauses
        assert clauses, f"{item.id} has no ISO clauses"
        for clause in clauses:
            assert clause in VALID_ISO_CLAUSES, f"{item.id} maps to invalid clause {clause}"


def test_iso_matrix_covers_every_item():
    assert set(ISO_CLAUSES_BY_ITEM) == VALID_ITEM_IDS


def test_checklist_has_25_items():
    assert len(CHECKLIST) == 25


def test_all_item_ids_unique():
    ids = [item.id for item in CHECKLIST]
    assert len(ids) == len(set(ids))


def test_valid_item_ids_set_matches_checklist():
    assert {item.id for item in CHECKLIST} == VALID_ITEM_IDS


def test_each_item_has_required_fields():
    for item in CHECKLIST:
        assert item.id
        assert item.text_de
        assert item.text_en
        assert item.m_dimension in VALID_DIMENSIONS
        assert len(item.gates) >= 1
        for g in item.gates:
            assert g in VALID_GATES


def test_item_ids_follow_naming_convention():
    for item in CHECKLIST:
        assert item.id[0] in {"S", "D", "T", "O", "I"}
        assert item.id[1:].isdigit()
        assert 1 <= int(item.id[1:]) <= 5


def test_s_items_map_to_m1():
    for item in CHECKLIST:
        if item.id.startswith("S"):
            assert item.m_dimension == "M1"


def test_d_items_map_to_m2():
    for item in CHECKLIST:
        if item.id.startswith("D"):
            assert item.m_dimension == "M2"


def test_t1_t3_map_to_m3():
    for item_id in ["T1", "T2", "T3"]:
        assert ITEM_BY_ID[item_id].m_dimension == "M3"


def test_t4_t5_map_to_m4():
    for item_id in ["T4", "T5"]:
        assert ITEM_BY_ID[item_id].m_dimension == "M4"


def test_o_items_map_to_m6():
    for item in CHECKLIST:
        if item.id.startswith("O"):
            assert item.m_dimension == "M6"


def test_i_items_map_to_m5():
    for item in CHECKLIST:
        if item.id.startswith("I"):
            assert item.m_dimension == "M5"


def test_risk_weights_correct():
    assert RISK_WEIGHTS["low"] == 1.0
    assert RISK_WEIGHTS["medium"] == 1.5
    assert RISK_WEIGHTS["high"] == 2.0


def test_item_weight():
    item = ITEM_BY_ID["S1"]
    assert item.weight("low") == 1.0
    assert item.weight("medium") == 1.5
    assert item.weight("high") == 2.0


def test_item_text_en():
    item = ITEM_BY_ID["S1"]
    assert item.text("en") == item.text_en


def test_item_text_de():
    item = ITEM_BY_ID["S1"]
    assert item.text("de") == item.text_de


def test_items_by_dimension_covers_all_dims():
    for dim in VALID_DIMENSIONS:
        assert dim in ITEMS_BY_DIMENSION
        assert len(ITEMS_BY_DIMENSION[dim]) > 0


def test_items_by_dimension_total_equals_25():
    total = sum(len(v) for v in ITEMS_BY_DIMENSION.values())
    assert total == 25


def test_items_by_gate_covers_all_gates():
    for gate in VALID_GATES:
        assert gate in ITEMS_BY_GATE
        assert len(ITEMS_BY_GATE[gate]) > 0


def test_g0_contains_s1_s2_s3():
    g0_ids = {item.id for item in ITEMS_BY_GATE["G0"]}
    assert {"S1", "S2", "S3"}.issubset(g0_ids)


def test_g5_contains_i3_i4_i5():
    g5_ids = {item.id for item in ITEMS_BY_GATE["G5"]}
    assert {"I3", "I4", "I5"}.issubset(g5_ids)


def test_item_by_id_lookup():
    for item_id in VALID_ITEM_IDS:
        assert item_id in ITEM_BY_ID
        assert ITEM_BY_ID[item_id].id == item_id
