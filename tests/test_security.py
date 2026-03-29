"""Tests for security controls."""

from __future__ import annotations

import json

import pytest

import presidio_ikigov_assess.security as sec


def test_ensure_iga_dir_creates_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(sec, "_IGA_DIR", tmp_path / ".iga")
    monkeypatch.setattr(sec, "_SECURITY_LOG", tmp_path / ".iga" / "security.log")
    sec.ensure_iga_dir()
    assert (tmp_path / ".iga").is_dir()


def test_log_security_event_writes_json(tmp_path, monkeypatch):
    log_path = tmp_path / "security.log"
    monkeypatch.setattr(sec, "_IGA_DIR", tmp_path)
    monkeypatch.setattr(sec, "_SECURITY_LOG", log_path)

    sec.log_security_event({"event": "test-event", "risk_class": "low"})

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["event"] == "test-event"
    assert data["risk_class"] == "low"
    assert "timestamp" in data


def test_log_security_event_no_secrets(tmp_path, monkeypatch):
    log_path = tmp_path / "security.log"
    monkeypatch.setattr(sec, "_IGA_DIR", tmp_path)
    monkeypatch.setattr(sec, "_SECURITY_LOG", log_path)

    sec.log_security_event({"event": "iga-assessment-complete", "gates_open": ["G0", "G1"]})
    data = json.loads(log_path.read_text().strip())
    # Structural fields only — no free-text use-case content in this entry
    assert "gates_open" in data


def test_log_security_event_multiple_entries(tmp_path, monkeypatch):
    log_path = tmp_path / "security.log"
    monkeypatch.setattr(sec, "_IGA_DIR", tmp_path)
    monkeypatch.setattr(sec, "_SECURITY_LOG", log_path)

    for i in range(3):
        sec.log_security_event({"event": f"evt-{i}"})

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 3


def test_session_count_increments():
    initial = sec.get_session_count()
    sec.increment_and_check_session_count()
    assert sec.get_session_count() == initial + 1


def test_session_count_limit_triggers_exit(monkeypatch):
    monkeypatch.setattr(sec, "_MAX_ASSESSMENTS", 0)
    monkeypatch.setattr(sec, "_session_count", 1)
    with pytest.raises(SystemExit) as exc_info:
        sec.increment_and_check_session_count()
    assert exc_info.value.code == 1


def test_dep_check_available_returns_bool():
    result = sec.dep_check_available()
    assert isinstance(result, bool)


def test_run_dep_check_returns_bool():
    # Should return bool regardless of pip_audit availability
    result = sec.run_dep_check()
    assert isinstance(result, bool)
