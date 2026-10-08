"""Regression tests pinning the tool to the printed book.

Stantchev, *KI und IT-Governance* (Springer, ISBN 978-3-662-74093-4), Anhang B
documents ``iga`` as of v0.1.0, with the 2026-10 proof corrections applied (risk
class ``medium`` in the worked example). These tests run the book's commands
verbatim and assert the lines a reader will compare against the page, so a
future release cannot silently drift from the printed text. See
``docs/book-compatibility.md`` for the claim-by-claim mapping.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from presidio_ikigov_assess import wizard
from presidio_ikigov_assess.cli import app
from presidio_ikigov_assess.renderer import shorten_text

runner = CliRunner()

# The worked example of Anhang B §"Ausgabebeispiel" (corrected proof). This is the
# only answer set consistent with every gate line printed there: G1 OPEN forces
# S1–S5, D1, D5; G2 PARTIAL with only D3 skipped forces D2, D4, T1–T3; G3 blocked
# by T5 alone forces T4, O1, O3.
BOOK_EXAMPLE = [
    "assess",
    "--use-case",
    "fraud-scoring",
    "--risk-class",
    "medium",
    "--affirm",
    "S1,S2,S3,S4,S5,D1,D2,D4,D5,T1,T2,T3,T4,O1,O2,O3,I1",
    "--skip",
    "D3",
    "--lang",
    "en",
]


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("IGA_DB_PATH", str(tmp_path / "assessments.db"))


def invoke(*args: str):
    return runner.invoke(app, ["--no-dep-check", *args])


def flat(output: str) -> str:
    """Collapse whitespace so assertions survive terminal-width line wrapping."""
    return " ".join(output.split())


def with_risk(args: list[str], risk_class: str) -> list[str]:
    out = list(args)
    out[out.index("--risk-class") + 1] = risk_class
    return out


# ── Worked example (Anhang B, Ausgabebeispiel) ───────────────────────────────


def test_book_example_header_shows_risk_class():
    """The ``[risk: MEDIUM]`` header must not be swallowed as Rich markup."""
    result = invoke(*BOOK_EXAMPLE)
    assert result.exit_code == 0
    assert "IKI-Gov Assessment — fraud-scoring [risk: MEDIUM]" in flat(result.output)


def test_book_example_scores():
    result = invoke(*BOOK_EXAMPLE, "--quiet")
    assert result.exit_code == 0
    data = json.loads(result.output)
    scores = {dim: entry["score"] for dim, entry in data["scores"].items()}
    assert scores == {"M1": 100.0, "M2": 100.0, "M3": 100.0, "M4": 50.0, "M5": 20.0, "M6": 60.0}
    assert data["overall"] == 71.7


def test_book_example_gate_lines():
    out = flat(invoke(*BOOK_EXAMPLE).output)
    assert "G0 OPEN" in out
    assert "G1 OPEN" in out
    assert "G2 PARTIAL — skipped: D3" in out
    assert "G3 BLOCKED — blocking: T5 (A security review of the model…) G4" in out
    assert "G4 BLOCKED" in out
    assert "G5 BLOCKED" in out


def test_book_example_at_high_risk_forbids_the_skip():
    """Anhang B: at ``high`` gate-critical items may not be skipped (strict mode)."""
    out = flat(invoke(*with_risk(BOOK_EXAMPLE, "high")).output)
    assert "[risk: HIGH]" in out
    assert "G2 BLOCKED — blocking (skips not permitted): D3" in out


def test_book_example_header_in_german():
    out = flat(invoke(*BOOK_EXAMPLE[:-1], "de").output)
    assert "IKI-Gov Bewertung — fraud-scoring [Risiko: MITTEL]" in out


# ── Commands printed in Anhang B, run verbatim ───────────────────────────────


def test_book_interactive_wizard(monkeypatch):
    """The book's answer keys Y / N / S are accepted, also under ``--lang de``."""
    answers = iter(["Y"] * 20 + ["N"] * 3 + ["S"] * 2)
    monkeypatch.setattr(wizard, "pt_prompt", lambda *a, **k: next(answers))
    result = invoke(
        "assess",
        "--interactive",
        "--lang",
        "de",
        "--risk-class",
        "high",
        "--use-case",
        "kredit-scoring",
    )
    assert result.exit_code == 0
    out = flat(result.output)
    assert "20 bestätigt · 3 abgelehnt · 2 übersprungen" in out
    assert "IKI-Gov Bewertung — kredit-scoring [Risiko: HOCH]" in out


def test_book_parameter_mode():
    result = invoke(
        "assess",
        "--use-case",
        "fraud-scoring",
        "--risk-class",
        "high",
        "--affirm",
        "S1,S2,S3,D1,D2,T1,T4,O1,I1",
        "--skip",
        "I4,I5",
        "--lang",
        "en",
    )
    assert result.exit_code == 0
    assert "[risk: HIGH]" in flat(result.output)


def test_book_single_gate():
    result = invoke(
        "gate",
        "--gate",
        "G2",
        "--risk-class",
        "high",
        "--affirm",
        "S1,S2,S3,D1,D2,T1,T4,O1,I1",
        "--lang",
        "en",
    )
    assert result.exit_code == 0
    assert "G2 BLOCKED" in flat(result.output)


def test_book_report_markdown_to_console():
    result = invoke(
        "report",
        "--use-case",
        "fraud-scoring",
        "--risk-class",
        "high",
        "--affirm",
        "S1,S2,S3,D1,D2,T1",
        "--format",
        "markdown",
    )
    assert result.exit_code == 0
    assert result.output.startswith("# IKI-Gov Assessment — fraud-scoring")
    assert "| Risk Class | HIGH |" in result.output


# ── CI exit codes (Anhang B, Integration in Entwicklungsprozesse) ────────────


def test_book_ci_example_fails_the_build():
    """The printed ``--assert-gate G1`` example leaves G1 BLOCKED → exit 3."""
    result = invoke(
        "gate",
        "--gate",
        "G1",
        "--risk-class",
        "high",
        "--affirm",
        "S1,S2,D1,D2",
        "--assert-gate",
        "G1",
    )
    assert result.exit_code == 3


@pytest.mark.parametrize(
    ("affirm", "skip", "code"),
    [
        ("S1,S2,S3,S4,S5,D1,D5", "", 0),  # OPEN
        ("S1,S2,S3,S4,D1,D5", "S5", 2),  # PARTIAL
        ("S1,S2,D1,D2", "", 3),  # BLOCKED
    ],
)
def test_book_exit_codes(affirm, skip, code):
    args = ["gate", "--gate", "G1", "--risk-class", "medium", "--affirm", affirm]
    if skip:
        args += ["--skip", skip]
    result = invoke(*args, "--assert-gate", "G1", "--quiet")
    assert result.exit_code == code


# ── Blocking-item text is shortened at a word boundary ───────────────────────


def test_shorten_text_keeps_short_text():
    assert shorten_text("Security review", 40) == "Security review"


def test_shorten_text_cuts_at_word_boundary_without_dangling_comma():
    text = "A security review of the model pipeline, infrastructure, and APIs"
    assert shorten_text(text, 40) == "A security review of the model…"


def test_shorten_text_hard_cuts_a_single_long_word():
    assert shorten_text("x" * 50, 10) == "x" * 9 + "…"
