"""Shared test fixtures.

Isolates the per-user ``~/.iga`` state (security log, persistent session
counter) to a per-test temp directory so the real home is never touched and
tests do not leak state into one another. Persistence (``IGA_DB_PATH``) is
additionally isolated by the per-file ``_isolated_db`` fixtures.
"""

from __future__ import annotations

import pytest

import presidio_ikigov_assess.security as sec


@pytest.fixture(autouse=True)
def _isolated_iga_home(tmp_path, monkeypatch):
    home = tmp_path / "iga-home"
    monkeypatch.setattr(sec, "_IGA_DIR", home)
    monkeypatch.setattr(sec, "_SECURITY_LOG", home / "security.log")
    # Fresh in-memory MCP counter per test for determinism.
    monkeypatch.setattr(sec, "_session_count", 0)
    yield
