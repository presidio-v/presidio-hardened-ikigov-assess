"""Tests for the remote MCP endpoint primitives (v0.18.0).

The HTTP transport (`serve`) is thin wiring behind the [mcp] extra and is not exercised
here; these pin the verifiable core: token auth, per-org store isolation, rate limiting.
"""

from __future__ import annotations

import json

import pytest

from presidio_ikigov_assess import store
from presidio_ikigov_assess.remote import (
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
    # IGA_DB_PATH restored (unset) after the context.
    assert "IGA_DB_PATH" not in __import__("os").environ


def test_rate_limiter_per_org():
    limiter = OrgRateLimiter(max_per_org=2)
    assert limiter.check("acme") and limiter.check("acme")  # 1, 2 OK
    assert limiter.check("acme") is False  # 3rd over cap
    assert limiter.check("globex") is True  # independent per org
    with pytest.raises(RemoteError):
        for _ in range(5):
            limiter.enforce("acme")
