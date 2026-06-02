"""Tests for the SQLite persistence layer."""

from __future__ import annotations

import stat

import pytest

from presidio_ikigov_assess import store


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("IGA_DB_PATH", str(tmp_path / "assessments.db"))


def _save(use_case, overall=50.0, gates=None, scores=None):
    return store.save_assessment(
        use_case=use_case,
        risk_class="high",
        lang="en",
        answers={"affirmed": ["S1"], "skipped": []},
        scores=scores or {"M1": overall, "overall": overall},
        gates=gates or {"G0": "OPEN"},
    )


def test_save_returns_row_id():
    rid = _save("uc1")
    assert isinstance(rid, int) and rid >= 1


def test_save_and_list_roundtrip():
    _save("uc1", overall=80.0)
    rows = store.list_assessments()
    assert len(rows) == 1
    assert rows[0].use_case == "uc1"
    assert rows[0].scores["overall"] == 80.0
    assert rows[0].answers["affirmed"] == ["S1"]


def test_list_newest_first():
    _save("old")
    _save("new")
    rows = store.list_assessments()
    # ordered by timestamp desc, id desc → most recently inserted first
    assert rows[0].use_case == "new"


def test_list_empty():
    assert store.list_assessments() == []


def test_delete_use_case():
    _save("keep")
    _save("drop")
    _save("drop")
    removed = store.delete_use_case("drop")
    assert removed == 2
    remaining = {a.use_case for a in store.list_assessments()}
    assert remaining == {"keep"}


def test_delete_missing_returns_zero():
    assert store.delete_use_case("absent") == 0


def test_latest_per_use_case():
    _save("uc", overall=10.0)
    _save("uc", overall=90.0)
    latest = store.latest_per_use_case()
    assert len(latest) == 1
    assert latest[0].scores["overall"] == 90.0


def test_portfolio_summary_aggregates_means():
    _save("a", scores={"M1": 100.0, "M2": 0.0, "overall": 50.0})
    _save("b", scores={"M1": 0.0, "M2": 100.0, "overall": 50.0})
    summary = store.portfolio_summary()
    assert summary["use_case_count"] == 2
    assert summary["dimensions"]["M1"] == 50.0
    assert summary["dimensions"]["M2"] == 50.0


def test_portfolio_summary_counts_blocked_gates():
    _save("a", gates={"G0": "BLOCKED", "G1": "OPEN"})
    _save("b", gates={"G0": "BLOCKED", "G1": "BLOCKED"})
    summary = store.portfolio_summary()
    assert summary["gates_blocked"]["G0"] == 2
    assert summary["gates_blocked"]["G1"] == 1


def test_portfolio_summary_empty():
    summary = store.portfolio_summary()
    assert summary["use_case_count"] == 0
    assert summary["overall"] == 0.0
    assert summary["gates_blocked"] == {}


def test_db_file_permissions_are_600():
    _save("uc1")
    mode = stat.S_IMODE(store.db_path().stat().st_mode)
    assert mode == 0o600, f"expected 0o600, got {oct(mode)}"
