"""Tests for the remote MCP endpoint (v0.18.0 primitives + v0.19.0 enforcement).

`serve()`/`build_asgi_app()` (uvicorn + FastMCP transport) are behind the [mcp] extra and
not exercised here. These pin the verifiable core — token auth, per-org store isolation,
rate limiting — and the pure-ASGI `OrgAuthMiddleware` that enforces them per request.
"""

from __future__ import annotations

import asyncio
import contextvars
import json

import pytest

from presidio_ikigov_assess import store
from presidio_ikigov_assess.remote import (
    OrgAuthMiddleware,
    OrgRateLimiter,
    RemoteError,
    hash_token,
    load_token_store,
    org_db_path,
    org_store,
    resolve_org,
)


def test_hash_token_deterministic():
    assert hash_token("secret") == hash_token("secret")
    assert len(hash_token("secret")) == 64


def test_load_token_store_ok_and_rejects_bad():
    store_text = json.dumps({"acme": hash_token("t1"), "globex": hash_token("t2")})
    parsed = load_token_store(store_text)
    assert set(parsed) == {"acme", "globex"}
    with pytest.raises(RemoteError):
        load_token_store("[]")  # not an object
    with pytest.raises(RemoteError):
        load_token_store(json.dumps({"acme": "tooshort"}))  # not a sha256 hex


def test_resolve_org_is_fail_closed():
    ts = {"acme": hash_token("t1"), "globex": hash_token("t2")}
    assert resolve_org("t1", ts) == "acme"
    assert resolve_org("t2", ts) == "globex"
    assert resolve_org("wrong", ts) is None
    assert resolve_org("", ts) is None


def test_org_db_path_distinct_and_validated(tmp_path):
    a = org_db_path("acme", root=tmp_path)
    b = org_db_path("globex", root=tmp_path)
    assert a != b
    assert a.parent.name == "acme"
    with pytest.raises(RemoteError):
        org_db_path("../evil", root=tmp_path)  # path traversal rejected by allow-list


def _save(use_case):
    store.save_assessment(
        use_case=use_case,
        risk_class="high",
        lang="en",
        answers={"affirmed": ["S1"], "skipped": []},
        scores={"M1": 100.0, "overall": 16.7},
        gates={"G0": "OPEN"},
    )


def test_org_store_isolation(tmp_path, monkeypatch):
    monkeypatch.setenv("IGA_ORG_ROOT", str(tmp_path))
    monkeypatch.delenv("IGA_DB_PATH", raising=False)
    with org_store("acme"):
        _save("acme-uc")
        assert len(store.list_assessments()) == 1
    with org_store("globex"):
        assert store.list_assessments() == []  # isolated: globex sees nothing
        _save("globex-uc")
        assert len(store.list_assessments()) == 1
    with org_store("acme"):
        assert [a.use_case for a in store.list_assessments()] == ["acme-uc"]
    # The override is context-local and cleared after the context (no env-var mutation).
    assert store._db_path_override.get() is None
    assert "IGA_DB_PATH" not in __import__("os").environ


def test_org_store_override_is_context_local(tmp_path):
    # The DB-path binding lives in a context var, so a copied context sees the override
    # while the outer context does not — the property that makes concurrent requests safe.
    def inside():
        with org_store("acme", root=tmp_path):
            return store.db_path()

    inner = contextvars.copy_context().run(inside)
    assert inner == org_db_path("acme", root=tmp_path)
    assert store._db_path_override.get() is None  # outer context untouched


# ── Pure-ASGI auth/isolation/rate-limit middleware (v0.19.0) ──────────────────


class _ProbeApp:
    """A downstream ASGI app that records the store path it observes, then returns 200."""

    def __init__(self) -> None:
        self.seen: list[str] = []

    async def __call__(self, scope, receive, send) -> None:
        self.seen.append(str(store.db_path()))
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-length", b"2")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok"})


def _call(middleware, token=None):
    """Drive one HTTP request through the middleware; return (status, body_bytes)."""
    headers = [(b"authorization", f"Bearer {token}".encode())] if token is not None else []
    scope = {"type": "http", "method": "POST", "path": "/mcp", "headers": headers}
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        sent.append(msg)

    asyncio.run(middleware(scope, receive, send))
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body


def _middleware(tmp_path, max_per_org=100):
    token_store = {"acme": hash_token("t-acme"), "globex": hash_token("t-globex")}
    probe = _ProbeApp()
    mw = OrgAuthMiddleware(
        probe, token_store, OrgRateLimiter(max_per_org=max_per_org), root=tmp_path
    )
    return mw, probe


def test_middleware_rejects_missing_and_bad_token(tmp_path):
    mw, probe = _middleware(tmp_path)
    assert _call(mw, token=None)[0] == 401
    assert _call(mw, token="not-a-real-token")[0] == 401
    assert probe.seen == []  # downstream tool never reached
    assert store._db_path_override.get() is None  # nothing bound on the reject path


def test_middleware_authorizes_and_scopes_db_to_org(tmp_path):
    mw, probe = _middleware(tmp_path)
    status, body = _call(mw, token="t-acme")
    assert status == 200 and body == b"ok"
    # The tool ran with the store scoped to acme's database (binding propagated in-task).
    assert probe.seen == [str(org_db_path("acme", root=tmp_path))]
    assert store._db_path_override.get() is None  # cleared after the request


def test_middleware_isolates_orgs_across_requests(tmp_path):
    mw, probe = _middleware(tmp_path)
    _call(mw, token="t-acme")
    _call(mw, token="t-globex")
    assert probe.seen == [
        str(org_db_path("acme", root=tmp_path)),
        str(org_db_path("globex", root=tmp_path)),
    ]


def test_middleware_enforces_per_org_rate_limit(tmp_path):
    mw, _ = _middleware(tmp_path, max_per_org=2)
    assert _call(mw, token="t-acme")[0] == 200
    assert _call(mw, token="t-acme")[0] == 200
    assert _call(mw, token="t-acme")[0] == 429  # over cap
    assert _call(mw, token="t-globex")[0] == 200  # independent per org


def test_rate_limiter_per_org():
    limiter = OrgRateLimiter(max_per_org=2)
    assert limiter.check("acme") and limiter.check("acme")  # 1, 2 OK
    assert limiter.check("acme") is False  # 3rd over cap
    assert limiter.check("globex") is True  # independent per org
    with pytest.raises(RemoteError):
        for _ in range(5):
            limiter.enforce("acme")


# ── Non-HTTP ASGI scopes ─────────────────────────────────────────────────────
# Regression tests for the WebSocket auth bypass: the middleware used to forward
# every non-HTTP scope straight to the wrapped app, ahead of the bearer-token
# check, the rate limiter and the per-org DB binding. It was inert only because
# no WebSocket route is mounted; these lock the guard in independently of that.


class _ScopeProbe:
    """A downstream ASGI app that only records the scope types it is reached with."""

    def __init__(self) -> None:
        self.types: list[str] = []

    async def __call__(self, scope, receive, send) -> None:
        self.types.append(scope.get("type"))


def _drive(middleware, scope, incoming=None):
    """Drive one non-HTTP scope through the middleware; return the messages sent."""
    sent: list[dict] = []
    queue = list(incoming or [])

    async def receive():
        return queue.pop(0) if queue else {"type": "noop"}

    async def send(msg):
        sent.append(msg)

    asyncio.run(middleware(scope, receive, send))
    return sent


def _scope_middleware(tmp_path):
    probe = _ScopeProbe()
    return OrgAuthMiddleware(probe, {"acme": hash_token("t-acme")}, root=tmp_path), probe


def test_middleware_closes_websocket_at_handshake(tmp_path):
    mw, probe = _scope_middleware(tmp_path)
    sent = _drive(mw, {"type": "websocket", "path": "/mcp"}, [{"type": "websocket.connect"}])
    # Closed at handshake with 1008 (policy violation) — never accepted.
    assert sent == [{"type": "websocket.close", "code": 1008}]
    assert probe.types == []  # wrapped app never reached


def test_middleware_closes_websocket_even_with_a_valid_bearer_token(tmp_path):
    """A good token does not buy a WebSocket: this middleware authenticates HTTP only."""
    mw, probe = _scope_middleware(tmp_path)
    scope = {
        "type": "websocket",
        "path": "/mcp",
        "headers": [(b"authorization", b"Bearer t-acme")],
    }
    sent = _drive(mw, scope, [{"type": "websocket.connect"}])
    assert sent == [{"type": "websocket.close", "code": 1008}]
    assert probe.types == []


def test_middleware_passes_lifespan_through(tmp_path):
    """Lifespan is the only unauthenticated passthrough — it carries no request identity."""
    mw, probe = _scope_middleware(tmp_path)
    _drive(mw, {"type": "lifespan"})
    assert probe.types == ["lifespan"]


def test_middleware_drops_unknown_scope_type(tmp_path):
    mw, probe = _scope_middleware(tmp_path)
    assert _drive(mw, {"type": "some-future-protocol"}) == []
    assert probe.types == []


# ── Audit N-1/N-2/N-3: per-org windowed limit, no shared counter, bind guard ──


def test_rate_limiter_window_resets():
    now = [1000.0]
    limiter = OrgRateLimiter(max_per_org=2, window_seconds=60, clock=lambda: now[0])
    assert limiter.check("acme") and limiter.check("acme")
    assert limiter.check("acme") is False
    assert limiter.retry_after("acme") == 60
    now[0] += 59
    assert limiter.check("acme") is False and limiter.retry_after("acme") == 1
    now[0] += 1  # window elapsed: the org is not locked out for the server's lifetime
    assert limiter.check("acme") is True


def test_429_carries_retry_after(tmp_path):
    from presidio_ikigov_assess.remote import OrgAuthMiddleware

    sent: list[dict] = []

    async def app(scope, receive, send):  # pragma: no cover - never reached over cap
        raise AssertionError("over-cap request reached the app")

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "http.request"}

    token_store = {"acme": hash_token("t-acme")}
    mw = OrgAuthMiddleware(app, token_store, OrgRateLimiter(max_per_org=0), root=tmp_path)
    scope = {"type": "http", "headers": [(b"authorization", b"Bearer t-acme")]}
    asyncio.run(mw(scope, receive, send))
    start = sent[0]
    assert start["status"] == 429
    assert dict(start["headers"])[b"retry-after"].isdigit()


def test_remote_server_disables_the_process_wide_session_guard(monkeypatch):
    # One counter shared by every org let one tenant exhaust assess for all (N-1).
    from presidio_ikigov_assess import mcp_server, security

    monkeypatch.setattr(security, "_session_count", 10**6)
    payload = mcp_server.assess(["S1"], None, "low", "en", "uc", False, session_guard=False)
    assert "scores" in payload and "gates" in payload
    with pytest.raises(mcp_server.ToolInputError):
        mcp_server.assess(["S1"], None, "low", "en", "uc", False)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "[::1]", "127.0.0.2"])
def test_loopback_bind_allowed(host):
    from presidio_ikigov_assess.remote import check_bind

    check_bind(host, behind_tls_proxy=False)


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "mcp.example.com", "::"])
def test_non_loopback_bind_needs_tls_acknowledgement(host):
    from presidio_ikigov_assess.remote import RemoteError, check_bind

    with pytest.raises(RemoteError, match="behind-tls-proxy"):
        check_bind(host, behind_tls_proxy=False)
    check_bind(host, behind_tls_proxy=True)
