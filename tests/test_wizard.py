"""Tests for the interactive wizard.

The wizard reads each answer through ``prompt_toolkit.prompt`` (imported as
``pt_prompt``). We replace it with a scripted feeder so the 25-item walkthrough
runs non-interactively.
"""

from __future__ import annotations

import pytest

from presidio_ikigov_assess import wizard
from presidio_ikigov_assess.checklist import CHECKLIST


def _feed(monkeypatch, answers):
    """Patch the wizard's prompt to return *answers* in sequence."""
    it = iter(answers)
    monkeypatch.setattr(wizard, "pt_prompt", lambda *a, **k: next(it))


N = len(CHECKLIST)


def test_all_yes_affirms_everything(monkeypatch, capsys):
    _feed(monkeypatch, ["y"] * N)
    affirmed, skipped = wizard.run_wizard(lang="en", risk_class="high", use_case="uc")
    assert affirmed == frozenset(item.id for item in CHECKLIST)
    assert skipped == frozenset()


def test_no_denies_everything(monkeypatch):
    _feed(monkeypatch, ["n"] * N)
    affirmed, skipped = wizard.run_wizard(lang="en", risk_class="low", use_case="uc")
    assert affirmed == frozenset()
    assert skipped == frozenset()


def test_skip_recorded(monkeypatch):
    # First item skipped, the rest affirmed.
    _feed(monkeypatch, ["s"] + ["y"] * (N - 1))
    affirmed, skipped = wizard.run_wizard(lang="en", risk_class="medium", use_case="uc")
    assert skipped == frozenset([CHECKLIST[0].id])
    assert CHECKLIST[0].id not in affirmed


def test_german_tokens(monkeypatch):
    # First "ja", second "überspringen", rest "nein".
    _feed(monkeypatch, ["ja", "überspringen"] + ["nein"] * (N - 2))
    affirmed, skipped = wizard.run_wizard(lang="de", risk_class="high", use_case="uc")
    assert affirmed == frozenset([CHECKLIST[0].id])
    assert skipped == frozenset([CHECKLIST[1].id])


def test_help_then_answer_does_not_advance(monkeypatch, capsys):
    # "?" on the first item prints help and re-prompts, then "y"; rest "y".
    _feed(monkeypatch, ["?", "y"] + ["y"] * (N - 1))
    affirmed, _ = wizard.run_wizard(lang="en", risk_class="high", use_case="uc")
    out = capsys.readouterr().out
    assert "Dimension:" in out  # help line was shown
    assert len(affirmed) == N


def test_invalid_then_answer(monkeypatch, capsys):
    _feed(monkeypatch, ["x", "y"] + ["n"] * (N - 1))
    affirmed, _ = wizard.run_wizard(lang="en", risk_class="high", use_case="uc")
    out = capsys.readouterr().out
    assert "Invalid input" in out
    assert affirmed == frozenset([CHECKLIST[0].id])


def test_summary_counts_printed(monkeypatch, capsys):
    _feed(monkeypatch, ["y", "n", "s"] + ["y"] * (N - 3))
    wizard.run_wizard(lang="en", risk_class="medium", use_case="uc")
    out = capsys.readouterr().out
    assert "affirmed" in out and "skipped" in out


def test_eof_propagates(monkeypatch):
    def _raise(*a, **k):
        raise EOFError

    monkeypatch.setattr(wizard, "pt_prompt", _raise)
    with pytest.raises(EOFError):
        wizard.run_wizard(lang="en", risk_class="high", use_case="uc")
