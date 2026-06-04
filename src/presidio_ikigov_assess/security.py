"""Security controls for the IKI-Gov Assessment Tool.

Implements:
  - On-startup CVE/dependency check via pip-audit (suppressible with --no-dep-check)
  - Structured security event logging to ~/.iga/security.log
  - Session-level rate limiting:
      * a *persistent*, cross-process guard for the one-shot CLI
        (``enforce_persistent_session_limit``), and
      * an in-memory guard for the long-lived MCP server process
        (``increment_session_count`` / ``session_limit``).
    Both honour ``IGA_MAX_ASSESSMENTS`` (default 100).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

_IGA_DIR = Path.home() / ".iga"
_SECURITY_LOG = _IGA_DIR / "security.log"
_SESSION_STATE = "session.json"


def _read_int_env(name: str, default: int, minimum: int = 1) -> int:
    """Parse a positive-int environment variable, failing safe on bad input.

    A malformed (non-integer) value must never crash the tool, and an
    out-of-range value is clamped to *minimum* rather than silently disabling a
    guard. Both cases emit a one-line warning to stderr.
    """
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        print(
            f"Warning: {name}={raw!r} is not an integer; using default {default}.",
            file=sys.stderr,
        )
        return default
    if value < minimum:
        print(
            f"Warning: {name}={value} is below the minimum {minimum}; using {minimum}.",
            file=sys.stderr,
        )
        return minimum
    return value


# Parsed defensively at import (see _read_int_env) so a malformed env value
# degrades to the default with a warning instead of aborting the whole tool.
_MAX_ASSESSMENTS: int = _read_int_env("IGA_MAX_ASSESSMENTS", 100, minimum=1)

# In-memory counter for long-lived processes (the MCP server). A one-shot CLI
# invocation is a fresh OS process, so for the CLI this resets every run and is
# *not* a useful guard — the CLI uses the persistent limiter below instead.
_session_count: int = 0
_session_lock = threading.Lock()


def ensure_iga_dir() -> None:
    """Create ~/.iga with restricted permissions if it does not exist."""
    _IGA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)


class DepCheckResult(str, Enum):
    """Outcome of the dependency/CVE check, distinguishing clean from inconclusive."""

    CLEAN = "clean"  # pip-audit ran and found nothing
    VULNERABLE = "vulnerable"  # pip-audit positively reported vulnerabilities
    UNAVAILABLE = "unavailable"  # pip-audit not installed / not runnable
    INCONCLUSIVE = "inconclusive"  # ran but errored or timed out — result unknown


def dep_check_status(verbose: bool = False) -> DepCheckResult:
    """Run pip-audit and classify the outcome.

    Unlike a plain boolean, this distinguishes a *clean* scan from an
    *inconclusive* one (timeout, tool/usage error), so callers can avoid telling
    the user "no vulnerabilities" when in fact no scan completed.

    pip-audit exit codes: 0 = no vulnerabilities, 1 = vulnerabilities found; any
    other code is a usage/internal error and is reported as INCONCLUSIVE.
    """
    if not dep_check_available():
        return DepCheckResult.UNAVAILABLE
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip_audit", "--format", "json", "--progress-spinner", "off"],
            capture_output=True,
            text=True,
            timeout=45,
        )
    except subprocess.TimeoutExpired:
        return DepCheckResult.INCONCLUSIVE
    except (FileNotFoundError, OSError):
        return DepCheckResult.UNAVAILABLE

    if result.returncode == 0:
        return DepCheckResult.CLEAN
    if result.returncode == 1:
        if verbose and result.stdout:
            print(result.stdout, file=sys.stderr, end="")
        return DepCheckResult.VULNERABLE
    # Any other exit code is a tool/usage error — result is unknown, not clean.
    return DepCheckResult.INCONCLUSIVE


def run_dep_check(verbose: bool = False) -> bool:
    """Boolean wrapper over :func:`dep_check_status` (advisory, fails open).

    Returns ``False`` only when pip-audit positively reports vulnerabilities;
    every other outcome (clean, unavailable, inconclusive) returns ``True`` so
    the advisory check never blocks. Use :func:`dep_check_status` when the
    distinction between *clean* and *inconclusive* matters.
    """
    return dep_check_status(verbose=verbose) is not DepCheckResult.VULNERABLE


def dep_check_available() -> bool:
    """Return True if pip_audit is importable."""
    try:
        import importlib.util

        return importlib.util.find_spec("pip_audit") is not None
    except Exception:
        return False


def log_security_event(event: dict[str, object]) -> None:
    """Append a structured JSON security event to ~/.iga/security.log.

    Only structural metadata is logged — no use-case content, no org data,
    no secrets. The log file is created with mode 0o600 atomically (no
    world-readable window between creation and chmod).
    """
    try:
        ensure_iga_dir()
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **event,
        }
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        # Create with 0o600 from the outset (O_CREAT honours the mode only on
        # creation); avoids the TOCTOU window of open-then-chmod.
        fd = os.open(_SECURITY_LOG, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as fh:
            fh.write(line)
        try:
            _SECURITY_LOG.chmod(0o600)  # belt-and-suspenders for pre-existing files
        except OSError:
            pass
    except OSError:
        pass  # logging must never crash the main flow


# ── Persistent (cross-process) session limit for the CLI ─────────────────────


class SessionLimitError(RuntimeError):
    """Raised when the persistent per-session assessment limit is exceeded."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        super().__init__(f"Session limit reached ({limit} assessments).")


def _session_state_path() -> Path:
    return _IGA_DIR / _SESSION_STATE


def _session_idle_seconds() -> int:
    """Idle gap (seconds) after which a new CLI session starts. Default 1 hour."""
    return _read_int_env("IGA_SESSION_IDLE_SECONDS", 3600, minimum=1)


def _load_session_state() -> dict:
    try:
        with _session_state_path().open(encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}  # missing or corrupt → start a fresh session, never crash


def _write_session_state(state: dict) -> None:
    try:
        ensure_iga_dir()
        fd = os.open(_session_state_path(), os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
    except OSError:
        pass


def enforce_persistent_session_limit() -> int:
    """Persistent per-session assessment guard for the one-shot CLI.

    Unlike the in-memory counter (which resets every CLI process and so only
    guards the long-lived MCP server), this persists to ``~/.iga/session.json``
    so the limit holds across CLI invocations. A "session" is a run of activity
    with no idle gap longer than ``IGA_SESSION_IDLE_SECONDS`` (default 3600s);
    after that gap the counter resets.

    Returns the new in-session count; raises :class:`SessionLimitError` when the
    configured maximum is exceeded.
    """
    now = time.time()
    state = _load_session_state()
    last_seen = state.get("last_seen", 0.0)
    count = state.get("count", 0)
    if (
        not isinstance(last_seen, (int, float))
        or not isinstance(count, int)
        or now - last_seen > _session_idle_seconds()
    ):
        count = 0
    count += 1
    _write_session_state({"last_seen": now, "count": count})
    if count > _MAX_ASSESSMENTS:
        raise SessionLimitError(_MAX_ASSESSMENTS)
    return count


# ── In-memory session counter (long-lived processes: the MCP server) ─────────


def increment_session_count() -> int:
    """Increment the per-session assessment counter and return the new count.

    Non-fatal: the caller decides how to react when the limit is exceeded.
    Used by long-running front-ends (e.g. the MCP server) that must not abort
    the whole process on a single over-limit request.
    """
    global _session_count
    with _session_lock:
        _session_count += 1
        return _session_count


def session_limit() -> int:
    """Return the configured maximum assessments per session."""
    return _MAX_ASSESSMENTS


def increment_and_check_session_count() -> None:
    """Increment the in-memory counter and abort if the limit is exceeded.

    Fatal in-process variant. Retained for completeness and unit testing; the
    CLI uses :func:`enforce_persistent_session_limit` so the guard survives
    across one-shot invocations.
    """
    count = increment_session_count()
    if count > _MAX_ASSESSMENTS:
        print(
            f"Session limit reached. Maximum {_MAX_ASSESSMENTS} assessments per session.",
            file=sys.stderr,
        )
        sys.exit(1)


def get_session_count() -> int:
    return _session_count
