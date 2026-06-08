"""SQLite persistence for IKI-Gov assessments (v0.6.0).

Assessments are stored in a local SQLite database at ``~/.iga/assessments.db``
(override with the ``IGA_DB_PATH`` env var, primarily for tests). Only what the
user explicitly provides is stored — use-case name, risk class, language, and the
computed answers/scores/gates as JSON. No organisational metadata beyond that.

Security:
  - the ``~/.iga`` directory is created mode 0o700 and the DB file 0o600.
  - ``delete_use_case`` is a hard delete; no soft-delete log is retained.
"""

from __future__ import annotations

import contextvars
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_DEFAULT_DB_PATH = Path.home() / ".iga" / "assessments.db"

# Request-local database override. The remote endpoint sets this per request to
# scope one org to its own database; being a context var (not an env var) it is
# isolated per task, so concurrent requests cannot read each other's store.
_db_path_override: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "iga_db_path_override", default=None
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    use_case     TEXT NOT NULL,
    risk_class   TEXT NOT NULL,
    timestamp    TEXT NOT NULL,
    lang         TEXT NOT NULL,
    answers_json TEXT NOT NULL,
    scores_json  TEXT NOT NULL,
    gates_json   TEXT NOT NULL
)
"""


@dataclass(frozen=True)
class SavedAssessment:
    id: int
    use_case: str
    risk_class: str
    timestamp: str
    lang: str
    answers: dict
    scores: dict
    gates: dict


def db_path() -> Path:
    """Resolve the active database path.

    Precedence: a request-local override (set via :func:`use_db_path`, used by the
    remote endpoint to scope a request to one org), then the ``IGA_DB_PATH`` env var,
    then the default. The context-var override is per-task, so concurrent requests
    stay isolated.
    """
    override = _db_path_override.get() or os.environ.get("IGA_DB_PATH")
    return Path(override) if override else _DEFAULT_DB_PATH


def use_db_path(path: str | Path) -> contextvars.Token:
    """Bind the active DB path for the current context; returns a reset token."""
    return _db_path_override.set(str(path))


def reset_db_path(token: contextvars.Token) -> None:
    """Undo a :func:`use_db_path` binding using its token."""
    _db_path_override.reset(token)


def _connect() -> sqlite3.Connection:
    """Open the database, creating the directory, file (0o600), and schema."""
    path = db_path()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Pre-create the DB file with 0o600 before sqlite opens it, so there is no
    # world-readable window between sqlite's create-under-umask and the chmod.
    if not path.exists():
        try:
            os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
        except OSError:
            pass  # fall back to sqlite creating it + the chmod below
    conn = sqlite3.connect(path)
    conn.execute(_SCHEMA)
    conn.commit()
    try:
        path.chmod(0o600)
    except OSError:
        pass  # best effort; never block persistence on a chmod failure
    return conn


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def save_assessment(
    use_case: str,
    risk_class: str,
    lang: str,
    answers: dict,
    scores: dict,
    gates: dict,
) -> int:
    """Persist one assessment; returns its new row id."""
    conn = _connect()
    try:
        cur = conn.execute(
            "INSERT INTO assessments "
            "(use_case, risk_class, timestamp, lang, answers_json, scores_json, gates_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                use_case,
                risk_class,
                _now_iso(),
                lang,
                json.dumps(answers, ensure_ascii=False),
                json.dumps(scores, ensure_ascii=False),
                json.dumps(gates, ensure_ascii=False),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def _row_to_assessment(row: sqlite3.Row) -> SavedAssessment:
    return SavedAssessment(
        id=row["id"],
        use_case=row["use_case"],
        risk_class=row["risk_class"],
        timestamp=row["timestamp"],
        lang=row["lang"],
        answers=json.loads(row["answers_json"]),
        scores=json.loads(row["scores_json"]),
        gates=json.loads(row["gates_json"]),
    )


def list_assessments() -> list[SavedAssessment]:
    """Return all saved assessments, newest first."""
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM assessments ORDER BY timestamp DESC, id DESC").fetchall()
        return [_row_to_assessment(row) for row in rows]
    finally:
        conn.close()


def assessments_for_use_case(use_case: str) -> list[SavedAssessment]:
    """Return all saved assessments for *use_case*, newest first."""
    conn = _connect()
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT * FROM assessments WHERE use_case = ? ORDER BY timestamp DESC, id DESC",
            (use_case,),
        ).fetchall()
        return [_row_to_assessment(row) for row in rows]
    finally:
        conn.close()


def delete_use_case(use_case: str) -> int:
    """Hard-delete all assessments for *use_case*; returns rows removed."""
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM assessments WHERE use_case = ?", (use_case,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def latest_per_use_case() -> list[SavedAssessment]:
    """Return the most recent saved assessment for each distinct use case."""
    seen: dict[str, SavedAssessment] = {}
    for assessment in list_assessments():  # already newest-first
        seen.setdefault(assessment.use_case, assessment)
    return list(seen.values())


def portfolio_summary() -> dict:
    """Aggregate the latest assessment per use case into a portfolio view.

    Returns per-dimension mean scores (M1–M6) and overall maturity across use
    cases, plus, for each gate, how many use cases currently have it BLOCKED.
    """
    latest = latest_per_use_case()
    dims = ["M1", "M2", "M3", "M4", "M5", "M6"]

    dimension_means: dict[str, float] = {}
    if latest:
        for dim in dims:
            values = [a.scores.get(dim, 0.0) for a in latest]
            dimension_means[dim] = round(sum(values) / len(values), 1)
    else:
        dimension_means = {dim: 0.0 for dim in dims}

    overall = round(sum(dimension_means.values()) / len(dims), 1) if latest else 0.0

    gates_blocked: dict[str, int] = {}
    for assessment in latest:
        for gate, status in assessment.gates.items():
            if status == "BLOCKED":
                gates_blocked[gate] = gates_blocked.get(gate, 0) + 1

    return {
        "use_case_count": len(latest),
        "dimensions": dimension_means,
        "overall": overall,
        "gates_blocked": gates_blocked,
    }
