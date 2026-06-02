"""Tests for input validation and output sanitisation."""

import pytest

from presidio_ikigov_assess.sanitize import (
    ValidationError,
    escape_for_report,
    validate_date,
    validate_format,
    validate_gate,
    validate_item_ids,
    validate_lang,
    validate_output_path,
    validate_risk_class,
    validate_use_case,
)

# ── validate_output_path (v0.4.0) ───────────────────────────────────────────


def test_output_path_valid():
    assert validate_output_path("/tmp/report.md") == "/tmp/report.md"


def test_output_path_strips_whitespace():
    assert validate_output_path("  report.json  ") == "report.json"


def test_output_path_rejects_empty():
    with pytest.raises(ValidationError):
        validate_output_path("   ")


def test_output_path_rejects_null_byte():
    with pytest.raises(ValidationError):
        validate_output_path("report\x00.md")


def test_output_path_rejects_too_long():
    with pytest.raises(ValidationError):
        validate_output_path("a" * 5000)


# ── validate_date (v0.7.0) ──────────────────────────────────────────────────


def test_date_valid():
    assert validate_date("2026-03-15") == "2026-03-15"


def test_date_rejects_wrong_format():
    with pytest.raises(ValidationError):
        validate_date("2026/03/15")


def test_date_rejects_impossible_day():
    with pytest.raises(ValidationError):
        validate_date("2026-02-30")


# ── validate_use_case ─────────────────────────────────────────────────────────


def test_valid_use_case_alphanumeric():
    assert validate_use_case("fraud-scoring") == "fraud-scoring"


def test_valid_use_case_with_underscores():
    assert validate_use_case("kredit_scoring_v2") == "kredit_scoring_v2"


def test_use_case_rejects_empty():
    with pytest.raises(ValidationError):
        validate_use_case("")


def test_use_case_rejects_spaces():
    with pytest.raises(ValidationError):
        validate_use_case("fraud scoring")


def test_use_case_rejects_special_chars():
    with pytest.raises(ValidationError):
        validate_use_case("fraud<script>")


def test_use_case_rejects_overlong():
    with pytest.raises(ValidationError):
        validate_use_case("a" * 129)


def test_use_case_accepts_max_length():
    assert validate_use_case("a" * 128)


# ── validate_risk_class ───────────────────────────────────────────────────────


def test_valid_risk_classes():
    for rc in ("low", "medium", "high"):
        assert validate_risk_class(rc) == rc


def test_risk_class_case_insensitive():
    assert validate_risk_class("HIGH") == "high"
    assert validate_risk_class("Medium") == "medium"


def test_risk_class_rejects_invalid():
    with pytest.raises(ValidationError):
        validate_risk_class("critical")


def test_risk_class_rejects_empty():
    with pytest.raises(ValidationError):
        validate_risk_class("")


# ── validate_gate ─────────────────────────────────────────────────────────────


def test_valid_gates():
    for g in ("G0", "G1", "G2", "G3", "G4", "G5"):
        assert validate_gate(g) == g


def test_gate_case_insensitive():
    assert validate_gate("g2") == "G2"


def test_gate_rejects_invalid():
    with pytest.raises(ValidationError):
        validate_gate("G6")


def test_gate_rejects_garbage():
    with pytest.raises(ValidationError):
        validate_gate("GATE_0")


# ── validate_lang ─────────────────────────────────────────────────────────────


def test_valid_langs():
    assert validate_lang("en") == "en"
    assert validate_lang("de") == "de"


def test_lang_case_insensitive():
    assert validate_lang("EN") == "en"


def test_lang_rejects_unknown():
    with pytest.raises(ValidationError):
        validate_lang("fr")


# ── validate_format ───────────────────────────────────────────────────────────


def test_valid_formats():
    assert validate_format("markdown") == "markdown"
    assert validate_format("json") == "json"


def test_format_rejects_unknown():
    with pytest.raises(ValidationError):
        validate_format("pdf")


# ── validate_item_ids ─────────────────────────────────────────────────────────


def test_valid_item_ids_single():
    assert validate_item_ids("S1") == ["S1"]


def test_valid_item_ids_multiple():
    result = validate_item_ids("S1,D2,T3")
    assert set(result) == {"S1", "D2", "T3"}


def test_item_ids_case_insensitive():
    result = validate_item_ids("s1,d2")
    assert set(result) == {"S1", "D2"}


def test_item_ids_empty_string():
    assert validate_item_ids("") == []


def test_item_ids_rejects_unknown():
    with pytest.raises(ValidationError):
        validate_item_ids("X9")


def test_item_ids_rejects_too_many():
    with pytest.raises(ValidationError):
        validate_item_ids(",".join(["S1"] * 30))


# ── escape_for_report ─────────────────────────────────────────────────────────


def test_escape_html_tags():
    assert escape_for_report("<script>alert(1)</script>") == "&lt;script&gt;alert(1)&lt;/script&gt;"


def test_escape_quotes():
    assert "&quot;" in escape_for_report('"quoted"')


def test_escape_ampersand():
    result = escape_for_report("A & B")
    assert "&amp;" in result


def test_escape_plain_string_unchanged():
    assert escape_for_report("fraud-scoring") == "fraud-scoring"


def test_escape_converts_non_string():
    result = escape_for_report(42)
    assert result == "42"
