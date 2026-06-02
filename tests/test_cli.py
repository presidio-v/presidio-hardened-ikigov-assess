"""CLI integration tests using Typer's test runner."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from presidio_ikigov_assess.cli import app

runner = CliRunner()


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


# ── list command ──────────────────────────────────────────────────────────────


def test_list_shows_stub_message():
    result = invoke("list")
    assert result.exit_code == 0
    assert (
        "0.5.0" in result.output or "Persistence" in result.output or "persistence" in result.output
    )


def test_list_german():
    result = invoke("list", "--lang", "de")
    assert result.exit_code == 0


# ── global flags ──────────────────────────────────────────────────────────────


def test_no_dep_check_flag_accepted():
    result = runner.invoke(app, ["--no-dep-check", "list"])
    assert result.exit_code == 0


def test_invalid_lang_on_assess():
    result = invoke("assess", "--lang", "fr")
    assert result.exit_code == 1
