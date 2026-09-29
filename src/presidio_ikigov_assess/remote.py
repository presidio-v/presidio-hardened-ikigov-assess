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
import ipaddress
import json
import math
import os
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from presidio_ikigov_assess import store
from presidio_ikigov_assess.sanitize import ValidationError, validate_use_case

_ORG_ROOT_ENV = "IGA_ORG_ROOT"
_MAX_PER_ORG_ENV = "IGA_MCP_MAX_PER_ORG"
_DEFAULT_MAX_PER_ORG = 1000
_WINDOW_ENV = "IGA_MCP_WINDOW_SECONDS"
_DEFAULT_WINDOW_SECONDS = 3600
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
    """Scope the shared store to *org*'s database for the current context.

    Binds a context var (not the process-global ``IGA_DB_PATH`` env var), so concurrent
    requests for different orgs never observe each other's database.
    """
    path = org_db_path(org, root)
    token = store.use_db_path(path)
    try:
        yield path
    finally:
        store.reset_db_path(token)


def _max_per_org() -> int:
    try:
        return int(os.environ.get(_MAX_PER_ORG_ENV, _DEFAULT_MAX_PER_ORG))
    except ValueError:
        return _DEFAULT_MAX_PER_ORG


def _window_seconds() -> int:
    try:
        return max(1, int(os.environ.get(_WINDOW_ENV, _DEFAULT_WINDOW_SECONDS)))
    except ValueError:
        return _DEFAULT_WINDOW_SECONDS


class OrgRateLimiter:
    """Per-org fixed-window request limit: ``max_per_org`` requests per window.

    Each org's count resets when its window (``IGA_MCP_WINDOW_SECONDS``, default
    3600) has elapsed. This used to be a lifetime counter that never reset, so a
    busy org stayed locked out until the server restarted. State is one entry per
    org in the token store, so it cannot grow from request traffic.
    """

    def __init__(
        self,
        max_per_org: int | None = None,
        window_seconds: int | None = None,
        clock=time.monotonic,
    ) -> None:
        self.max_per_org = max_per_org if max_per_org is not None else _max_per_org()
        self.window_seconds = window_seconds if window_seconds is not None else _window_seconds()
        self._clock = clock
        self._windows: dict[str, tuple[float, int]] = {}

    def check(self, org: str) -> bool:
        """Count one request for *org*; return False while its window's cap is exceeded."""
        now = self._clock()
        start, count = self._windows.get(org, (now, 0))
        if now - start >= self.window_seconds:
            start, count = now, 0
        self._windows[org] = (start, count + 1)
        return count + 1 <= self.max_per_org

    def retry_after(self, org: str) -> int:
        """Whole seconds until *org*'s current window resets (at least 1)."""
        start, _ = self._windows.get(org, (self._clock(), 0))
        return max(1, math.ceil(start + self.window_seconds - self._clock()))

    def enforce(self, org: str) -> None:
        if not self.check(org):
            raise RemoteError(f"rate limit exceeded for org '{org}' ({self.max_per_org})")


def _bearer_token(scope: Mapping) -> str:
    """Extract the bearer token from an ASGI scope's Authorization header (else '')."""
    for key, value in scope.get("headers", []):
        if key == b"authorization":
            text = value.decode("latin-1")
            return text[7:].strip() if text[:7].lower() == "bearer " else ""
    return ""


async def _reject(
    send, status: int, message: str, extra_headers: list[tuple[bytes, bytes]] | None = None
) -> None:
    """Send a minimal JSON error response and end the request."""
    body = json.dumps({"error": message}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                *(extra_headers or []),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


# ASGI close code 1008 — "policy violation". The connection is refused because
# this middleware authenticates HTTP requests only, not because of anything the
# client sent, so no detail is echoed back.
_WS_POLICY_VIOLATION = 1008


async def _reject_non_http(scope_type: str | None, receive, send) -> None:
    """Refuse a non-HTTP, non-lifespan ASGI scope without reaching the wrapped app.

    WebSocket scopes are closed per the ASGI spec: consume the initial
    ``websocket.connect`` and answer it with ``websocket.close``, which is the
    handshake-time refusal — the connection is never accepted, so no frame is
    ever exchanged with an unauthenticated peer.

    Any other scope type is dropped silently. There is no protocol-agnostic way
    to signal a refusal, and returning without calling ``self.app`` is the
    fail-closed outcome.
    """
    if scope_type != "websocket":
        return
    message = await receive()
    if message.get("type") == "websocket.connect":
        await send({"type": "websocket.close", "code": _WS_POLICY_VIOLATION})


class OrgAuthMiddleware:
    """Pure-ASGI guard: authenticate the bearer token to an org and enforce the per-org
    rate limit before the request reaches the MCP app.

    Authentication (401) and rate limiting (429) are enforced here unconditionally — the
    request is rejected before ``self.app`` is ever called, so they hold regardless of how
    the transport schedules work.

    Only ``lifespan`` passes through unauthenticated, because startup and shutdown carry
    no request identity. Every other non-HTTP scope is refused: WebSocket connections are
    closed at handshake with 1008, anything else is dropped. The wrapped app is reached by
    an HTTP scope that authenticated, or by lifespan, and by nothing else.

    The org's DB path is also bound on the store context var for the request. NOTE this
    scopes only store access that runs *inline* in this request task; the streamable-HTTP
    transport dispatches tool execution to a separate **session** task, so this binding does
    not reach the MCP tools. That is acceptable today because the registered MCP tools are
    stateless (none read or write the store). Exposing store-backed tools remotely would
    require per-session org binding — see SECURITY.md.
    """

    def __init__(
        self,
        app,
        token_store: Mapping[str, str],
        limiter: OrgRateLimiter | None = None,
        root: Path | None = None,
    ) -> None:
        self.app = app
        self.token_store = token_store
        self.limiter = limiter or OrgRateLimiter()
        self.root = root

    async def __call__(self, scope, receive, send) -> None:
        scope_type = scope.get("type")
        if scope_type == "lifespan":
            # Startup/shutdown carries no request identity, so there is nothing to
            # authenticate. This is the ONLY passthrough.
            await self.app(scope, receive, send)
            return
        if scope_type != "http":
            # Fail closed on every other scope type. This previously forwarded
            # WebSocket scopes straight to the app, ahead of the bearer-token
            # check, the rate limiter and the per-org DB binding. It was inert
            # only because no WebSocket route is mounted — an accident of what
            # streamable_http_app() happens to build, not a guarantee this
            # middleware can rely on. A route added later, here or upstream in
            # the SDK, would have turned it into a silent auth bypass.
            await _reject_non_http(scope_type, receive, send)
            return
        org = resolve_org(_bearer_token(scope), self.token_store)
        if org is None:
            await _reject(send, 401, "unauthorized")
            return
        if not self.limiter.check(org):
            retry = str(self.limiter.retry_after(org)).encode("ascii")
            await _reject(
                send, 429, f"rate limit exceeded for org '{org}'", [(b"retry-after", retry)]
            )
            return
        token = store.use_db_path(org_db_path(org, self.root))
        try:
            await self.app(scope, receive, send)
        finally:
            store.reset_db_path(token)


def build_asgi_app(  # pragma: no cover - needs the [mcp] extra and full transport
    token_store: Mapping[str, str], root: Path | None = None
):
    """The org-scoped ASGI app: the FastMCP streamable-HTTP app behind the auth guard."""
    from presidio_ikigov_assess.mcp_server import build_server

    # The process-wide assess counter is shared by every org, so it is off here;
    # OrgRateLimiter bounds each org separately (audit N-1).
    return OrgAuthMiddleware(
        build_server(session_guard=False).streamable_http_app(), token_store, root=root
    )


def is_loopback_host(host: str) -> bool:
    """True for ``localhost`` and loopback IP literals (127.0.0.0/8, ::1)."""
    if host.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip().strip("[]")).is_loopback
    except ValueError:
        return False


def check_bind(host: str, behind_tls_proxy: bool) -> None:
    """Refuse a non-loopback bind unless TLS termination in front is acknowledged.

    The server speaks plain HTTP and bearer tokens are its only credential, so a
    reachable non-loopback bind without a TLS-terminating proxy sends them in clear.
    """
    if not is_loopback_host(host) and not behind_tls_proxy:
        raise RemoteError(
            f"refusing to bind {host!r}: the endpoint serves plain HTTP and bearer tokens "
            "would cross the network in clear. Put a TLS-terminating reverse proxy in front "
            "and pass --behind-tls-proxy, or bind 127.0.0.1."
        )


def serve(  # pragma: no cover - thin transport wiring, exercised behind the [mcp] extra
    host: str = "127.0.0.1",
    port: int = 8080,
    token_store_path: str | None = None,
    behind_tls_proxy: bool = False,
) -> None:
    """Run the org-scoped MCP server over streamable HTTP (requires the ``[mcp]`` extra).

    Each request's bearer token is authenticated to an org, the per-org rate limit is
    enforced, and the store is scoped to that org before the IKI-Gov tools run. The
    server has no TLS of its own: binding beyond loopback requires
    ``--behind-tls-proxy`` to acknowledge a TLS-terminating proxy in front.
    """
    check_bind(host, behind_tls_proxy)
    path = token_store_path or os.environ.get("IGA_MCP_TOKENS")
    if not path:
        raise RemoteError("set --token-store / IGA_MCP_TOKENS to a {org: token_hash} JSON file")
    token_store = load_token_store(Path(path).read_text(encoding="utf-8"))
    try:
        import uvicorn

        app = build_asgi_app(token_store)
    except ImportError as exc:
        raise RemoteError(
            "the remote MCP endpoint needs the optional extra: pip install "
            "'presidio-hardened-ikigov-assess[mcp]'"
        ) from exc
    uvicorn.run(app, host=host, port=port)


def main() -> None:  # pragma: no cover - console-script entry point
    import typer

    typer.run(serve)
