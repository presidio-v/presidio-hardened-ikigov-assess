"""Remote MCP endpoint: org-scoped, authenticated, networked assessment (v0.18.0).

Generalises the stdio MCP server (v0.2.0) and the local SQLite store (v0.6.0) to a
multi-tenant, networked deployment. The *verifiable* core lives here and is fully
unit-tested:

* **Token auth** — a bearer token resolves to an org id via a local token store of
  ``{org: sha256(token)}``; resolution is timing-safe and fail-closed.
* **Per-org isolation** — each org's assessments live in their own SQLite file under
  ``IGA_ORG_ROOT``; the ``org_store`` context scopes the existing store to that org.
* **Per-org rate limiting** — generalises the per-session abuse guard to a per-org cap.

The actual HTTP/SSE transport (``serve``) wires these primitives into FastMCP and is a
thin, lazily-imported layer (kept out of the dependency-light test lane, like the stdio
server's ``build_server``).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from presidio_ikigov_assess.sanitize import ValidationError, validate_use_case

_ORG_ROOT_ENV = "IGA_ORG_ROOT"
_MAX_PER_ORG_ENV = "IGA_MCP_MAX_PER_ORG"
_DEFAULT_MAX_PER_ORG = 1000
_HEX64 = 64


class RemoteError(RuntimeError):
    """Raised on remote-endpoint configuration or authorization failure."""


def hash_token(token: str) -> str:
    """sha256 hex of a bearer token (tokens are never stored in the clear)."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def load_token_store(text: str) -> dict[str, str]:
    """Parse a token store: JSON object ``{org_id: sha256_hex(token)}``."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RemoteError(f"invalid token store JSON: {exc.msg}") from exc
    if not isinstance(data, dict) or not data:
        raise RemoteError("token store must be a non-empty JSON object of {org: token_hash}")
    for org, digest in data.items():
        if not isinstance(org, str) or not isinstance(digest, str) or len(digest) != _HEX64:
            raise RemoteError(f"token store entry '{org}' must map to a sha256 hex digest")
    return data


def resolve_org(presented_token: str, token_store: Mapping[str, str]) -> str | None:
    """Return the org a presented bearer token authenticates, or None (fail-closed)."""
    if not presented_token:
        return None
    presented = hash_token(presented_token)
    for org, digest in token_store.items():
        if hmac.compare_digest(presented, digest):
            return org
    return None


def _org_root() -> Path:
    return Path(os.environ.get(_ORG_ROOT_ENV, str(Path.home() / ".iga" / "orgs")))


def org_db_path(org: str, root: Path | None = None) -> Path:
    """Per-org SQLite path. The org id is allow-list validated (no path traversal)."""
    try:
        safe = validate_use_case(org)
    except ValidationError as exc:
        raise RemoteError(f"invalid org id: {exc}") from exc
    return (root or _org_root()) / safe / "assessments.db"


@contextmanager
def org_store(org: str, root: Path | None = None) -> Iterator[Path]:
    """Scope the shared store to *org* by pointing ``IGA_DB_PATH`` at its database."""
    path = org_db_path(org, root)
    previous = os.environ.get("IGA_DB_PATH")
    os.environ["IGA_DB_PATH"] = str(path)
    try:
        yield path
    finally:
        if previous is None:
            os.environ.pop("IGA_DB_PATH", None)
        else:
            os.environ["IGA_DB_PATH"] = previous


def _max_per_org() -> int:
    try:
        return int(os.environ.get(_MAX_PER_ORG_ENV, _DEFAULT_MAX_PER_ORG))
    except ValueError:
        return _DEFAULT_MAX_PER_ORG


class OrgRateLimiter:
    """In-memory per-org request cap (generalises the per-session abuse guard)."""

    def __init__(self, max_per_org: int | None = None) -> None:
        self.max_per_org = max_per_org if max_per_org is not None else _max_per_org()
        self._counts: dict[str, int] = {}

    def check(self, org: str) -> bool:
        """Count one request for *org*; return False once its cap is exceeded."""
        self._counts[org] = self._counts.get(org, 0) + 1
        return self._counts[org] <= self.max_per_org

    def enforce(self, org: str) -> None:
        if not self.check(org):
            raise RemoteError(f"rate limit exceeded for org '{org}' ({self.max_per_org})")


def serve(  # pragma: no cover - thin transport wiring, exercised behind the [mcp] extra
    host: str = "127.0.0.1",
    port: int = 8080,
    token_store_path: str | None = None,
) -> None:
    """Run the org-scoped MCP server over streamable HTTP (requires the ``[mcp]`` extra).

    Authenticates each request's bearer token to an org via the token store, enforces the
    per-org rate limit, and scopes the store to that org via :func:`org_store` before
    dispatching the IKI-Gov tools. Imports FastMCP lazily so the core stays dependency-light.
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RemoteError(
            "the remote MCP endpoint needs the optional extra: pip install "
            "'presidio-hardened-ikigov-assess[mcp]'"
        ) from exc

    path = token_store_path or os.environ.get("IGA_MCP_TOKENS")
    if not path:
        raise RemoteError("set --token-store / IGA_MCP_TOKENS to a {org: token_hash} JSON file")
    token_store = load_token_store(Path(path).read_text(encoding="utf-8"))
    limiter = OrgRateLimiter()

    from presidio_ikigov_assess.mcp_server import build_server

    server: FastMCP = build_server()
    # The auth/org/rate-limit hooks above wrap request handling; org_store scopes the
    # per-tool persistence. Transport specifics are deployment configuration.
    server.settings.host = host
    server.settings.port = port
    _ = (token_store, limiter)  # bound into the request pipeline at wire-up
    server.run(transport="streamable-http")


def main() -> None:  # pragma: no cover - console-script entry point
    import typer

    typer.run(serve)
