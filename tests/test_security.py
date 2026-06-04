"""Tests for security controls."""

from __future__ import annotations

import json
import subprocess

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


# ── L-1: safe environment-variable parsing ──────────────────────────────────


def test_read_int_env_valid(monkeypatch):
    monkeypatch.setenv("IGA_TEST_INT", "42")
    assert sec._read_int_env("IGA_TEST_INT", 100) == 42


def test_read_int_env_malformed_falls_back(monkeypatch, capsys):
    monkeypatch.setenv("IGA_TEST_INT", "not-a-number")
    assert sec._read_int_env("IGA_TEST_INT", 100) == 100
    assert "not an integer" in capsys.readouterr().err


def test_read_int_env_below_minimum_is_clamped(monkeypatch, capsys):
    monkeypatch.setenv("IGA_TEST_INT", "0")
    assert sec._read_int_env("IGA_TEST_INT", 100, minimum=1) == 1
    assert "below the minimum" in capsys.readouterr().err


def test_read_int_env_unset_uses_default(monkeypatch):
    monkeypatch.delenv("IGA_TEST_INT", raising=False)
    assert sec._read_int_env("IGA_TEST_INT", 7) == 7


# ── L-2: dependency check distinguishes clean from inconclusive ──────────────


def _fake_run(returncode, stdout=""):
    def _run(*args, **kwargs):
        return subprocess.CompletedProcess(args, returncode, stdout=stdout, stderr="")

    return _run


def test_dep_check_status_clean(monkeypatch):
    monkeypatch.setattr(sec, "dep_check_available", lambda: True)
    monkeypatch.setattr(sec.subprocess, "run", _fake_run(0))
    assert sec.dep_check_status() is sec.DepCheckResult.CLEAN


def test_dep_check_status_vulnerable(monkeypatch):
    monkeypatch.setattr(sec, "dep_check_available", lambda: True)
    monkeypatch.setattr(sec.subprocess, "run", _fake_run(1, stdout="{}"))
    assert sec.dep_check_status() is sec.DepCheckResult.VULNERABLE


def test_dep_check_status_inconclusive_on_error_code(monkeypatch):
    monkeypatch.setattr(sec, "dep_check_available", lambda: True)
    monkeypatch.setattr(sec.subprocess, "run", _fake_run(2))
    assert sec.dep_check_status() is sec.DepCheckResult.INCONCLUSIVE


def test_dep_check_status_inconclusive_on_timeout(monkeypatch):
    monkeypatch.setattr(sec, "dep_check_available", lambda: True)

    def _raise(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="pip_audit", timeout=45)

    monkeypatch.setattr(sec.subprocess, "run", _raise)
    assert sec.dep_check_status() is sec.DepCheckResult.INCONCLUSIVE


def test_dep_check_status_unavailable(monkeypatch):
    monkeypatch.setattr(sec, "dep_check_available", lambda: False)
    assert sec.dep_check_status() is sec.DepCheckResult.UNAVAILABLE


def test_run_dep_check_false_only_when_vulnerable(monkeypatch):
    monkeypatch.setattr(sec, "dep_check_available", lambda: True)
    monkeypatch.setattr(sec.subprocess, "run", _fake_run(1, stdout="{}"))
    assert sec.run_dep_check() is False
    monkeypatch.setattr(sec.subprocess, "run", _fake_run(2))  # inconclusive
    assert sec.run_dep_check() is True  # fails open


# ── M-1: persistent cross-process session limit ─────────────────────────────


def test_persistent_session_limit_counts_and_blocks(monkeypatch):
    monkeypatch.setattr(sec, "_MAX_ASSESSMENTS", 2)
    assert sec.enforce_persistent_session_limit() == 1
    assert sec.enforce_persistent_session_limit() == 2
    with pytest.raises(sec.SessionLimitError) as exc:
        sec.enforce_persistent_session_limit()
    assert exc.value.limit == 2


def test_persistent_session_limit_resets_after_idle(monkeypatch):
    monkeypatch.setattr(sec, "_MAX_ASSESSMENTS", 2)
    monkeypatch.setenv("IGA_SESSION_IDLE_SECONDS", "3600")
    sec.enforce_persistent_session_limit()
    sec.enforce_persistent_session_limit()
    # Force the stored last_seen far into the past → next call starts a new session.
    state = sec._load_session_state()
    state["last_seen"] = 0.0
    sec._write_session_state(state)
    assert sec.enforce_persistent_session_limit() == 1  # reset, not blocked


def test_persistent_session_limit_survives_corrupt_state(monkeypatch):
    monkeypatch.setattr(sec, "_MAX_ASSESSMENTS", 5)
    sec.ensure_iga_dir()
    sec._session_state_path().write_text("{not valid json", encoding="utf-8")
    # Corrupt state must not crash — it starts a fresh session.
    assert sec.enforce_persistent_session_limit() == 1


def test_persistent_session_state_file_is_0600(monkeypatch):
    import stat

    sec.enforce_persistent_session_limit()
    mode = stat.S_IMODE(sec._session_state_path().stat().st_mode)
    assert mode == 0o600
