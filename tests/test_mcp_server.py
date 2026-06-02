"""Tests for the MCP server's pure tool logic.

These exercise ``mcp_server``'s helper functions directly — they carry no
dependency on the optional ``mcp`` package, so they run on every Python.
A guarded smoke test builds the FastMCP server only when ``mcp`` is installed.
"""

from __future__ import annotations

import pytest

from presidio_ikigov_assess import security
from presidio_ikigov_assess.checklist import CHECKLIST, VALID_GATES
from presidio_ikigov_assess.mcp_server import (
    ToolInputError,
    assess,
    framework_info,
    gate_status,
    list_items,
)


@pytest.fixture(autouse=True)
def _reset_session_counter(monkeypatch):
    """Isolate each test from the global per-session assessment counter."""
    monkeypatch.setattr(security, "_session_count", 0)


# ── framework_info ───────────────────────────────────────────────────────────


def test_framework_info_default_lang_en():
    info = framework_info()
    assert info["lang"] == "en"
    assert set(info["dimensions"]) == {"M1", "M2", "M3", "M4", "M5", "M6"}
    assert set(info["gates"]) == VALID_GATES
    assert info["dimensions"]["M2"] == "Data Quality & Lineage"
    assert info["gates"]["G0"] == "Context → Conception"
    assert len(info["lifecycle_phases"]) == 7


def test_framework_info_german():
    info = framework_info("de")
    assert info["lang"] == "de"
    assert info["gates"]["G0"] == "Kontext → Konzeption"
    assert info["lifecycle_phases"][0] == "Kontext"
    assert set(info["risk_classes"]) == {"low", "medium", "high"}


def test_framework_info_rejects_bad_lang():
    with pytest.raises(ToolInputError):
        framework_info("fr")


# ── list_items ───────────────────────────────────────────────────────────────


def test_list_items_returns_all_25():
    result = list_items()
    assert result["count"] == 25
    assert len(result["items"]) == len(CHECKLIST)
    ids = {item["id"] for item in result["items"]}
    assert ids == {item.id for item in CHECKLIST}


def test_list_item_shape():
    first = list_items("de")["items"][0]
    assert set(first) == {"id", "text", "dimension", "dimension_name", "gates", "section"}
    assert first["id"] == "S1"
    assert isinstance(first["gates"], list)


# ── assess ───────────────────────────────────────────────────────────────────


def test_assess_empty_is_all_blocked():
    payload = assess()
    assert payload["overall"] == 0.0
    assert all(g["status"] == "BLOCKED" for g in payload["gates"].values())


def test_assess_all_affirmed_is_all_open():
    all_ids = [item.id for item in CHECKLIST]
    payload = assess(affirmed=all_ids, risk_class="high")
    assert payload["overall"] == 100.0
    assert all(g["status"] == "OPEN" for g in payload["gates"].values())


def test_assess_lowercase_ids_are_normalised():
    payload = assess(affirmed=["s1", "s2"])
    assert payload["answers"]["affirmed"] == ["S1", "S2"]


def test_assess_skipped_excluded_from_scoring():
    # Affirm S1; skip the rest of M1 (S2–S5) → M1 should be 100% on the one item.
    payload = assess(affirmed=["S1"], skipped=["S2", "S3", "S4", "S5"])
    assert payload["scores"]["M1"]["score"] == 100.0
    assert payload["scores"]["M1"]["skipped"] == 4


def test_assess_rejects_unknown_id():
    with pytest.raises(ToolInputError):
        assess(affirmed=["S1", "ZZ9"])


def test_assess_rejects_overlap():
    with pytest.raises(ToolInputError) as exc:
        assess(affirmed=["S1"], skipped=["S1"])
    assert "both" in str(exc.value).lower()


def test_assess_rejects_bad_risk_class():
    with pytest.raises(ToolInputError):
        assess(affirmed=["S1"], risk_class="extreme")


def test_assess_rejects_bad_use_case():
    with pytest.raises(ToolInputError):
        assess(use_case="bad name!")


def test_assess_session_limit(monkeypatch):
    monkeypatch.setattr(security, "_MAX_ASSESSMENTS", 1)
    monkeypatch.setattr(security, "_session_count", 0)
    assess(affirmed=["S1"])  # first one OK
    with pytest.raises(ToolInputError):
        assess(affirmed=["S1"])  # second exceeds the limit


# ── gate_status ──────────────────────────────────────────────────────────────


def test_gate_status_open():
    from presidio_ikigov_assess.checklist import ITEMS_BY_GATE

    g0_ids = [item.id for item in ITEMS_BY_GATE["G0"]]
    result = gate_status("G0", affirmed=g0_ids)
    assert result["status"] == "OPEN"
    assert result["gate"] == "G0"
    assert result["transition"] == "Context → Conception"
    assert result["blocking"] == []


def test_gate_status_blocked_lists_items():
    result = gate_status("G0")
    assert result["status"] == "BLOCKED"
    assert len(result["blocking"]) >= 1
    assert all({"id", "text"} == set(b) for b in result["blocking"])


def test_gate_status_lowercase_gate_normalised():
    result = gate_status("g1")
    assert result["gate"] == "G1"


def test_gate_status_rejects_bad_gate():
    with pytest.raises(ToolInputError):
        gate_status("G9")


def test_gate_status_low_risk_forgives_skips():
    from presidio_ikigov_assess.checklist import ITEMS_BY_GATE

    ids = [item.id for item in ITEMS_BY_GATE["G0"]]
    result = gate_status("G0", affirmed=ids[1:], skipped=[ids[0]], risk_class="low")
    assert result["status"] == "OPEN"
    assert result["blocking_skips"] == []


def test_gate_status_strict_blocks_skips():
    from presidio_ikigov_assess.checklist import ITEMS_BY_GATE

    ids = [item.id for item in ITEMS_BY_GATE["G0"]]
    result = gate_status("G0", affirmed=ids[1:], skipped=[ids[0]], strict=True)
    assert result["status"] == "BLOCKED"
    assert [b["id"] for b in result["blocking_skips"]] == [ids[0]]
    assert result["strict"] is True


def test_assess_strict_reflected_in_gates():
    payload = assess(affirmed=["S1", "S2"], skipped=["S3"], strict=True)
    assert payload["gates"]["G0"]["status"] == "BLOCKED"
    assert payload["gates"]["G0"]["blocking_skips"] == ["S3"]


# ── iso_gap ──────────────────────────────────────────────────────────────────


def test_iso_gap_payload_shape():
    from presidio_ikigov_assess.mcp_server import iso_gap

    payload = iso_gap(affirmed=["S2", "S3", "I1", "I2"], use_case="demo")
    assert payload["iso_coverage"]["5"]["status"] == "covered"
    assert "disclaimer" in payload
    assert set(payload["iso_coverage"]) == {"4", "5", "6", "7", "8", "9", "10", "A"}


def test_iso_gap_rejects_bad_lang():
    from presidio_ikigov_assess.mcp_server import iso_gap

    with pytest.raises(ToolInputError):
        iso_gap(affirmed=["S1"], lang="fr")


# ── FastMCP wiring (only when the optional mcp package is installed) ──────────


def test_build_server_registers_tools():
    pytest.importorskip("mcp")
    from presidio_ikigov_assess.mcp_server import build_server

    server = build_server()
    tools = server._tool_manager.list_tools()
    names = {tool.name for tool in tools}
    assert names == {
        "iga_framework_info",
        "iga_list_checklist",
        "iga_assess",
        "iga_check_gate",
        "iga_iso_gap",
        "iga_euaiact_gap",
    }


def test_euaiact_gap_payload_shape():
    # All gate-G1 items affirmed → Art. 10 (G1 only) should be OPEN.
    from presidio_ikigov_assess.checklist import ITEMS_BY_GATE
    from presidio_ikigov_assess.mcp_server import euaiact_gap

    g1 = [item.id for item in ITEMS_BY_GATE["G1"]]
    payload = euaiact_gap(affirmed=g1)
    assert payload["articles"]["10"]["status"] == "OPEN"
    assert set(payload["articles"]) == {"9", "10", "11", "12", "13", "14", "15", "17"}


def test_euaiact_gap_all_blocked_when_nothing_affirmed():
    from presidio_ikigov_assess.mcp_server import euaiact_gap

    payload = euaiact_gap()
    assert all(a["status"] == "BLOCKED" for a in payload["articles"].values())
