"""Security controls for the IKI-Gov Assessment Tool.

Implements:
  - On-startup CVE/dependency check via pip-audit (suppressible with --no-dep-check)
  - Structured security event logging to ~/.iga/security.log
  - Session-level rate limiting (configurable via IGA_MAX_ASSESSMENTS env var)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

_IGA_DIR = Path.home() / ".iga"
_SECURITY_LOG = _IGA_DIR / "security.log"

_MAX_ASSESSMENTS: int = int(os.environ.get("IGA_MAX_ASSESSMENTS", "100"))
_session_count: int = 0
_session_lock = threading.Lock()


def ensure_iga_dir() -> None:
    """Create ~/.iga with restricted permissions if it does not exist."""
    _IGA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)


def run_dep_check(verbose: bool = False) -> bool:
    """Run pip-audit to check for known vulnerabilities in installed packages.

    Returns True if the check passed (no vulnerabilities or tool unavailable).
    Returns False if vulnerabilities were found.
    Prints a brief status line to stderr.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip_audit", "--format", "json", "-q", "--disable-pip"],
            capture_output=True,
            text=True,
            timeout=45,
        )
        if result.returncode == 0:
            return True
        # pip-audit exits non-zero when vulnerabilities are found
        if verbose and result.stdout:
            print(result.stdout, file=sys.stderr, end="")
        return False
    except subprocess.TimeoutExpired:
        return True  # timed out — non-blocking, assume OK
    except FileNotFoundError:
        # pip_audit module not available
        return True


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
    no secrets.
    """
    try:
        ensure_iga_dir()
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **event,
        }
        with _SECURITY_LOG.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        # Restrict log file permissions
        _SECURITY_LOG.chmod(0o600)
    except OSError:
        pass  # logging must never crash the main flow


def increment_and_check_session_count() -> None:
    """Increment the per-session assessment counter and abort if limit exceeded."""
    global _session_count
    with _session_lock:
        _session_count += 1
        count = _session_count
    if count > _MAX_ASSESSMENTS:
        print(
            f"Session limit reached. Maximum {_MAX_ASSESSMENTS} assessments per session.",
            file=sys.stderr,
        )
        sys.exit(1)


def get_session_count() -> int:
    return _session_count
