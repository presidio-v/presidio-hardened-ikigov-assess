"""CLI integration tests using Typer's test runner."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from presidio_ikigov_assess.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    """Point persistence at a per-test temp DB so the real ~/.iga is untouched."""
    monkeypatch.setenv("IGA_DB_PATH", str(tmp_path / "assessments.db"))


def invoke(*args: str) -> object:
    """Invoke the CLI with --no-dep-check to skip the audit check in tests."""
    return runner.invoke(app, ["--no-dep-check"] + list(args))


# ── assess command ────────────────────────────────────────────────────────────


def test_assess_no_affirm_exits_0():
    result = invoke("assess", "--use-case", "test-case", "--risk-class", "low")
    assert result.exit_code == 0


def test_assess_with_affirmed_items():
    result = invoke(
        "assess",
        "--use-case",
        "fraud-scoring",
        "--risk-class",
        "high",
        "--affirm",
        "S1,S2,S3",
        "--lang",
        "en",
    )
    assert result.exit_code == 0
    assert "fraud-scoring" in result.output


def test_assess_all_items_affirmed():
    all_ids = ",".join(
        [
            "S1",
            "S2",
            "S3",
            "S4",
            "S5",
            "D1",
            "D2",
            "D3",
            "D4",
            "D5",
            "T1",
            "T2",
            "T3",
            "T4",
            "T5",
            "O1",
            "O2",
            "O3",
            "O4",
            "O5",
            "I1",
            "I2",
            "I3",
            "I4",
            "I5",
        ]
    )
    result = invoke("assess", "--affirm", all_ids, "--risk-class", "medium")
    assert result.exit_code == 0
    assert "100" in result.output


def test_assess_german_output():
    result = invoke("assess", "--use-case", "kredit-scoring", "--lang", "de")
    assert result.exit_code == 0
    assert "Messdimensionen" in result.output or "IKI-Gov" in result.output


def test_assess_invalid_use_case():
    result = invoke("assess", "--use-case", "fraud scoring with spaces")
    assert result.exit_code == 1


def test_assess_invalid_risk_class():
    result = invoke("assess", "--use-case", "test", "--risk-class", "extreme")
    assert result.exit_code == 1


def test_assess_invalid_affirm_id():
    result = invoke("assess", "--affirm", "XX")
    assert result.exit_code == 1


def test_assess_overlap_affirm_skip():
    result = invoke("assess", "--affirm", "S1,S2", "--skip", "S2")
    assert result.exit_code == 1


def test_assess_with_skip():
    result = invoke("assess", "--affirm", "S1,S2,S3", "--skip", "I4,I5")
    assert result.exit_code == 0


def test_assess_shows_gate_status():
    result = invoke("assess", "--affirm", "S1,S2,S3")
    assert result.exit_code == 0
    assert "G0" in result.output


# ── gate command ──────────────────────────────────────────────────────────────


def test_gate_open():
    result = invoke("gate", "--gate", "G0", "--affirm", "S1,S2,S3")
    assert result.exit_code == 0
    assert "OPEN" in result.output


def test_gate_blocked():
    result = invoke("gate", "--gate", "G0", "--affirm", "S1")
    assert result.exit_code == 0
    assert "BLOCKED" in result.output


def test_gate_partial_with_skip():
    result = invoke("gate", "--gate", "G0", "--affirm", "S1,S2", "--skip", "S3")
    assert result.exit_code == 0
    assert "PARTIAL" in result.output


def test_gate_invalid_gate_id():
    result = invoke("gate", "--gate", "G9")
    assert result.exit_code == 1


def test_gate_assert_open_exits_0():
    result = invoke(
        "gate",
        "--gate",
        "G0",
        "--affirm",
        "S1,S2,S3",
        "--assert-gate",
        "G0",
    )
    assert result.exit_code == 0


def test_gate_assert_blocked_exits_3():
    # v0.3.0 CI exit codes: BLOCKED -> 3 (distinct from general error 1).
    result = invoke("gate", "--gate", "G0", "--affirm", "S1", "--assert-gate", "G0")
    assert result.exit_code == 3


def test_gate_assert_partial_exits_2():
    # PARTIAL (only gaps are skips, at default medium risk) -> exit 2.
    result = invoke(
        "gate", "--gate", "G0", "--affirm", "S1,S2", "--skip", "S3", "--assert-gate", "G0"
    )
    assert result.exit_code == 2


def test_gate_assert_mismatch_exits_1():
    # --assert-gate must match --gate; mismatch is a usage error -> 1.
    result = invoke("gate", "--gate", "G0", "--affirm", "S1,S2,S3", "--assert-gate", "G1")
    assert result.exit_code == 1


# ── v0.3.0: risk-class-aware thresholds & --strict ──────────────────────────────


def test_gate_low_risk_forgives_skips():
    # At low risk a gate with only skips (no denials) is OPEN, not PARTIAL.
    result = invoke(
        "gate", "--gate", "G0", "--affirm", "S1,S2", "--skip", "S3", "--risk-class", "low"
    )
    assert result.exit_code == 0
    assert "OPEN" in result.output


def test_gate_strict_blocks_skips():
    # --strict turns an otherwise-PARTIAL (skipped) gate into BLOCKED.
    result = invoke("gate", "--gate", "G0", "--affirm", "S1,S2", "--skip", "S3", "--strict")
    assert "BLOCKED" in result.output


def test_gate_high_risk_implies_strict():
    # high risk implies strict: a skipped gate item blocks the gate.
    result = invoke(
        "gate", "--gate", "G0", "--affirm", "S1,S2", "--skip", "S3", "--risk-class", "high"
    )
    assert "BLOCKED" in result.output


def test_gate_strict_assert_exits_3():
    result = invoke(
        "gate",
        "--gate",
        "G0",
        "--affirm",
        "S1,S2",
        "--skip",
        "S3",
        "--strict",
        "--assert-gate",
        "G0",
    )
    assert result.exit_code == 3


# ── v0.3.0: --quiet machine-readable output ─────────────────────────────────────


def test_gate_quiet_emits_json():
    result = invoke("gate", "--gate", "G0", "--affirm", "S1,S2", "--skip", "S3", "--quiet")
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["gate"] == "G0"
    assert data["status"] == "PARTIAL"
    assert data["skipped"] == ["S3"]


def test_gate_quiet_strict_reports_blocking_skips():
    result = invoke(
        "gate", "--gate", "G0", "--affirm", "S1,S2", "--skip", "S3", "--strict", "--quiet"
    )
    data = json.loads(result.output)
    assert data["status"] == "BLOCKED"
    assert data["blocking_skips"] == ["S3"]
    assert data["strict"] is True


def test_assess_quiet_emits_json():
    result = invoke("assess", "--affirm", "S1,S2,S3", "--quiet")
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "scores" in data and "gates" in data and "overall" in data


def test_assess_strict_reflected_in_gate_json():
    result = invoke("assess", "--affirm", "S1,S2", "--skip", "S3", "--strict", "--quiet")
    data = json.loads(result.output)
    assert data["gates"]["G0"]["status"] == "BLOCKED"
    assert data["gates"]["G0"]["blocking_skips"] == ["S3"]


def test_gate_german_output():
    result = invoke("gate", "--gate", "G0", "--affirm", "S1,S2,S3", "--lang", "de")
    assert result.exit_code == 0
    assert "OFFEN" in result.output


# ── report command ────────────────────────────────────────────────────────────


def test_report_markdown_default():
    result = invoke(
        "report",
        "--use-case",
        "fraud-scoring",
        "--affirm",
        "S1,S2,S3",
        "--risk-class",
        "high",
    )
    assert result.exit_code == 0
    assert "# IKI-Gov Assessment" in result.output
    assert "fraud-scoring" in result.output


def test_report_json():
    result = invoke(
        "report",
        "--use-case",
        "fraud-scoring",
        "--affirm",
        "S1,S2",
        "--format",
        "json",
    )
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["use_case"] == "fraud-scoring"
    assert "scores" in data
    assert "gates" in data
    assert "overall" in data


def test_report_json_contains_answers():
    result = invoke(
        "report",
        "--use-case",
        "test",
        "--affirm",
        "S1,S2",
        "--skip",
        "I5",
        "--format",
        "json",
    )
    data = json.loads(result.output)
    assert "S1" in data["answers"]["affirmed"]
    assert "I5" in data["answers"]["skipped"]


def test_report_invalid_format():
    result = invoke("report", "--format", "pdf")
    assert result.exit_code == 1


# ── v0.4.0: per-item answers & file export ──────────────────────────────────────


def test_report_markdown_per_item_section():
    result = invoke("report", "--affirm", "S1,S2", "--skip", "I5", "--format", "markdown")
    assert result.exit_code == 0
    assert "Per-Item Answers" in result.output
    # All 25 item IDs should appear in the answers table.
    for item_id in ("S1", "S3", "D1", "T4", "O5", "I5"):
        assert item_id in result.output
    assert "affirmed" in result.output and "not affirmed" in result.output


def test_report_json_per_item_detail():
    result = invoke("report", "--affirm", "S1", "--skip", "S2", "--format", "json")
    data = json.loads(result.output)
    items = data["answers"]["items"]
    assert len(items) == 25
    by_id = {row["id"]: row for row in items}
    assert by_id["S1"]["status"] == "affirmed"
    assert by_id["S2"]["status"] == "skipped"
    assert by_id["S3"]["status"] == "denied"
    assert "text" in by_id["S1"] and by_id["S1"]["dimension"] == "M1"


def test_report_writes_markdown_file(tmp_path):
    out = tmp_path / "report.md"
    result = invoke(
        "report", "--use-case", "fraud-scoring", "--affirm", "S1,S2", "--output", str(out)
    )
    assert result.exit_code == 0
    assert out.is_file()
    content = out.read_text(encoding="utf-8")
    assert "# IKI-Gov Assessment" in content
    assert "fraud-scoring" in content
    assert "Per-Item Answers" in content
    # Report goes to the file, not stdout.
    assert "# IKI-Gov Assessment" not in result.output


def test_report_writes_json_file(tmp_path):
    out = tmp_path / "report.json"
    result = invoke("report", "--affirm", "S1,S2", "--format", "json", "-o", str(out))
    assert result.exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["overall"] >= 0
    assert len(data["answers"]["items"]) == 25


def test_report_output_confirmation_message(tmp_path):
    out = tmp_path / "r.md"
    result = invoke("report", "--affirm", "S1", "--output", str(out))
    assert result.exit_code == 0
    assert str(out) in result.output  # confirmation names the path


def test_report_output_unwritable_path_exits_1(tmp_path):
    # Parent directory does not exist → OSError → exit 1.
    bad = tmp_path / "missing-dir" / "report.md"
    result = invoke("report", "--affirm", "S1", "--output", str(bad))
    assert result.exit_code == 1
    assert not bad.exists()


def test_report_empty_output_path_exits_1():
    result = invoke("report", "--affirm", "S1", "--output", "   ")
    assert result.exit_code == 1


def test_report_output_symlink_rejected(tmp_path):
    # L-4: writing through a symlink is refused so the write cannot be redirected.
    victim = tmp_path / "victim.md"
    link = tmp_path / "link.md"
    link.symlink_to(victim)
    result = invoke("report", "--affirm", "S1", "--output", str(link))
    assert result.exit_code == 1
    assert not victim.exists()


def test_assess_persistent_rate_limit_blocks(monkeypatch):
    # M-1: the persistent CLI guard blocks once the limit is exceeded, and the
    # state survives across invocations (separate runner calls = the same store).
    import presidio_ikigov_assess.security as sec

    monkeypatch.setattr(sec, "_MAX_ASSESSMENTS", 2)
    assert invoke("assess", "-u", "a", "-r", "low", "--affirm", "S1", "-q").exit_code == 0
    assert invoke("assess", "-u", "b", "-r", "low", "--affirm", "S1", "-q").exit_code == 0
    blocked = invoke("assess", "-u", "c", "-r", "low", "--affirm", "S1", "-q")
    assert blocked.exit_code == 1


def test_report_html_escaped_use_case():
    result = invoke(
        "report",
        "--use-case",
        "fraud-scoring",
        "--format",
        "markdown",
    )
    assert result.exit_code == 0
    # Ensure no raw HTML injection possible
    assert "<" not in result.output.split("# ")[1].split("\n")[0]


def test_report_german():
    result = invoke(
        "report",
        "--use-case",
        "test",
        "--lang",
        "de",
        "--format",
        "markdown",
    )
    assert result.exit_code == 0
    assert "IKI-Gov" in result.output


# ── iso-gap command (v0.5.0) ────────────────────────────────────────────────────


def test_iso_gap_console():
    result = invoke("iso-gap", "--use-case", "demo", "--affirm", "S1,S2")
    assert result.exit_code == 0
    assert "ISO/IEC 42001" in result.output


def test_iso_gap_quiet_json_clause_covered():
    # Clause 5 (Leadership) maps to exactly S2, S3, I1, I2.
    result = invoke("iso-gap", "--affirm", "S2,S3,I1,I2", "--quiet")
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert "iso_coverage" in data
    assert data["iso_coverage"]["5"]["status"] == "covered"
    assert data["iso_coverage"]["5"]["outstanding"] == []


def test_iso_gap_all_gap_when_none_affirmed():
    result = invoke("iso-gap", "--quiet")
    data = json.loads(result.output)
    assert all(c["status"] == "gap" for c in data["iso_coverage"].values())


def test_iso_gap_partial_lists_outstanding():
    result = invoke("iso-gap", "--affirm", "S2", "--quiet")
    data = json.loads(result.output)
    assert data["iso_coverage"]["5"]["status"] == "partial"
    assert set(data["iso_coverage"]["5"]["outstanding"]) == {"S3", "I1", "I2"}


def test_iso_gap_invalid_risk_class():
    result = invoke("iso-gap", "--risk-class", "extreme")
    assert result.exit_code == 1


def test_iso_gap_german():
    result = invoke("iso-gap", "--affirm", "S1", "--lang", "de")
    assert result.exit_code == 0
    assert "ISO/IEC 42001" in result.output


# ── euaiact-gap command (v0.8.0) ────────────────────────────────────────────────


def test_euaiact_gap_console():
    result = invoke("euaiact-gap", "--use-case", "fraud-scoring", "--affirm", "S1,S2")
    assert result.exit_code == 0
    assert "EU AI Act" in result.output
    assert "Art. 9" in result.output


def test_euaiact_gap_requires_high_risk():
    result = invoke("euaiact-gap", "--risk-class", "medium", "--affirm", "S1")
    assert result.exit_code == 1
    assert "high-risk" in result.output


def test_euaiact_gap_quiet_json():
    result = invoke("euaiact-gap", "--affirm", "S1", "--quiet")
    assert result.exit_code == 0
    data = json.loads(result.output)
    assert set(data["articles"]) == {"9", "10", "11", "12", "13", "14", "15", "17"}
    # nothing meaningful affirmed at high/strict → articles blocked
    assert data["articles"]["13"]["status"] == "BLOCKED"


def test_euaiact_gap_german():
    result = invoke("euaiact-gap", "--affirm", "S1", "--lang", "de")
    assert result.exit_code == 0
    assert "EU-KI-VO" in result.output


# ── persistence: list / portfolio / delete / --save (v0.6.0) ────────────────────


def test_list_empty_shows_hint():
    result = invoke("list")
    assert result.exit_code == 0
    assert "No saved assessments" in result.output


def test_list_german_empty():
    result = invoke("list", "--lang", "de")
    assert result.exit_code == 0


def test_assess_save_then_list():
    save = invoke("assess", "--use-case", "fraud-scoring", "--affirm", "S1,S2,S3", "--save")
    assert save.exit_code == 0
    assert "saved" in save.output.lower()
    listed = invoke("list", "--quiet")
    data = json.loads(listed.output)
    assert len(data) == 1
    assert data[0]["use_case"] == "fraud-scoring"
    assert "overall" in data[0]


def test_save_quiet_emits_only_json():
    # --save with --quiet must keep stdout pure JSON (confirmation goes to stderr).
    result = invoke("assess", "--use-case", "uc1", "--affirm", "S1", "--quiet", "--save")
    assert result.exit_code == 0
    data = json.loads(result.output)  # would raise if stdout were polluted
    assert "scores" in data


def test_portfolio_aggregates_saved():
    invoke("assess", "--use-case", "uc-a", "--affirm", "S1,S2,S3,S4,S5", "--save")
    invoke("assess", "--use-case", "uc-b", "--save")  # nothing affirmed → low scores
    result = invoke("portfolio", "--quiet")
    data = json.loads(result.output)
    assert data["use_case_count"] == 2
    assert "M1" in data["dimensions"]
    # uc-b has no affirmations → some gates BLOCKED across the portfolio
    assert data["gates_blocked"]


def test_portfolio_latest_per_use_case():
    # Two saves for the same use case → counts once (latest only).
    invoke("assess", "--use-case", "uc-x", "--affirm", "S1", "--save")
    invoke("assess", "--use-case", "uc-x", "--affirm", "S1,S2,S3", "--save")
    result = invoke("portfolio", "--quiet")
    assert json.loads(result.output)["use_case_count"] == 1


def test_portfolio_empty():
    result = invoke("portfolio")
    assert result.exit_code == 0
    assert "nothing to aggregate" in result.output.lower()


def test_delete_removes_use_case():
    invoke("assess", "--use-case", "to-del", "--affirm", "S1", "--save")
    deleted = invoke("delete", "--use-case", "to-del")
    assert deleted.exit_code == 0
    assert "Deleted 1" in deleted.output
    assert json.loads(invoke("list", "--quiet").output) == []


def test_delete_missing_use_case():
    result = invoke("delete", "--use-case", "never-saved")
    assert result.exit_code == 0
    assert "No assessments found" in result.output


def test_list_console_table_shows_saved():
    invoke("assess", "--use-case", "fraud-scoring", "--affirm", "S1,S2", "--save")
    result = invoke("list")
    assert result.exit_code == 0
    assert "Saved Assessments" in result.output
    assert "fraud-scoring" in result.output


def test_portfolio_console_shows_dimensions():
    invoke("assess", "--use-case", "uc-a", "--affirm", "S1,S2,S3", "--save")
    result = invoke("portfolio")
    assert result.exit_code == 0
    assert "Portfolio Overview" in result.output
    assert "M1" in result.output


# ── trend command (v0.7.0) ──────────────────────────────────────────────────────


def test_trend_needs_two_assessments():
    invoke("assess", "--use-case", "solo", "--affirm", "S1", "--save")
    result = invoke("trend", "--use-case", "solo")
    assert result.exit_code == 1
    assert "two saved assessments" in result.output


def test_trend_latest_vs_previous_quiet():
    invoke("assess", "--use-case", "growth", "--affirm", "S1", "--save")
    invoke("assess", "--use-case", "growth", "--affirm", "S1,S2,S3,S4,S5", "--save")
    result = invoke("trend", "--use-case", "growth", "--quiet")
    assert result.exit_code == 0
    data = json.loads(result.output)
    # later run affirmed more → overall went up
    assert data["overall"]["delta"] > 0
    assert len(data["dimensions"]) == 6
    assert len(data["gate_transitions"]) == 6


def test_trend_console_output():
    invoke("assess", "--use-case", "g2", "--affirm", "S1", "--save")
    invoke("assess", "--use-case", "g2", "--affirm", "S1,S2,S3", "--save")
    result = invoke("trend", "--use-case", "g2")
    assert result.exit_code == 0
    assert "Maturity Trend" in result.output
    assert "Gate Transitions" in result.output


def test_trend_invalid_date():
    result = invoke("trend", "--use-case", "x", "--from", "2026/01/01")
    assert result.exit_code == 1


# ── global flags ──────────────────────────────────────────────────────────────


def test_no_dep_check_flag_accepted():
    result = runner.invoke(app, ["--no-dep-check", "list"])
    assert result.exit_code == 0


def test_invalid_lang_on_assess():
    result = invoke("assess", "--lang", "fr")
    assert result.exit_code == 1
