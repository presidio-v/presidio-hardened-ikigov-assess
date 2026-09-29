"""evidence-ref@2 acceptance and assurance tiers on the consumer side (ADR-0003)."""

from __future__ import annotations

import pytest

from presidio_ikigov_assess.evidence import (
    ASSURANCE_TIERS,
    DEFAULT_ASSURANCE_TIER,
    SCHEMA_ID,
    SCHEMA_ID_V2,
    TIER_RANK,
    EvidenceError,
    expected_signature,
    parse_assurance_tier,
    parse_document,
    verify_ref,
)

GOLDEN_CH = "abc123def456"
GOLDEN_SIGNER = "presidio-hardened-ai"
GOLDEN_KEY = "shared-key"
GOLDEN_SIG = expected_signature(GOLDEN_CH, GOLDEN_SIGNER, GOLDEN_KEY)


def _raw(item_id="D1", **extra):
    base = {
        "item_id": item_id,
        "source": "presidio-hardened-ai",
        "source_version": "0.30.0",
        "ledger_ref": "pai-ledger:seq/1",
        "content_hash": GOLDEN_CH,
        "signer": GOLDEN_SIGNER,
        "signature": GOLDEN_SIG,
        "claimed_at": "2026-06-12T00:00:00+00:00",
    }
    base.update(extra)
    return base


def test_tier_order_is_weakest_to_strongest():
    assert ASSURANCE_TIERS == ("attested", "optimistic", "zk")
    assert TIER_RANK["attested"] < TIER_RANK["optimistic"] < TIER_RANK["zk"]
    assert DEFAULT_ASSURANCE_TIER == "attested"


def test_v2_document_honours_declared_tiers():
    refs = parse_document(
        {
            "schema": SCHEMA_ID_V2,
            "evidence": [
                _raw("D1", assurance_tier="attested"),
                _raw("D2", assurance_tier="optimistic"),
                _raw("D3", assurance_tier="zk"),
                _raw("D4"),  # absent ⇒ default
            ],
        }
    )
    assert [r.assurance_tier for r in refs] == ["attested", "optimistic", "zk", "attested"]


def test_v2_signature_is_tier_independent():
    trust = {GOLDEN_SIGNER: GOLDEN_KEY}
    for tier in ASSURANCE_TIERS:
        (ref,) = parse_document({"schema": SCHEMA_ID_V2, "evidence": [_raw(assurance_tier=tier)]})
        assert verify_ref(ref, trust)


def test_v2_unknown_tier_fails_closed():
    with pytest.raises(EvidenceError, match="assurance_tier"):
        parse_document({"schema": SCHEMA_ID_V2, "evidence": [_raw(assurance_tier="platinum")]})
    with pytest.raises(EvidenceError):
        parse_document({"schema": SCHEMA_ID_V2, "evidence": [_raw(assurance_tier=3)]})


def test_v1_with_extra_tier_is_inert():
    # Family golden vector evidence-ref-v2/valid-v1-with-extra-tier: valid under
    # @1, the tier is tolerated and ignored (resolves to attested).
    for schema in (SCHEMA_ID, None):
        doc = {"evidence": [_raw(assurance_tier="zk")]}
        if schema is not None:
            doc["schema"] = schema
        (ref,) = parse_document(doc)
        assert ref.assurance_tier == "attested"
    # Even an *invalid* tier value is inert under @1 (never read).
    (ref,) = parse_document({"schema": SCHEMA_ID, "evidence": [_raw(assurance_tier="platinum")]})
    assert ref.assurance_tier == "attested"


def test_unknown_schema_still_rejected():
    with pytest.raises(EvidenceError, match="unsupported evidence schema"):
        parse_document({"schema": "presidio-hardened/evidence-ref@3", "evidence": []})


def test_parse_assurance_tier():
    for tier in ASSURANCE_TIERS:
        assert parse_assurance_tier(tier) == tier
    for bad in ("", "ZK", None, 1):
        with pytest.raises(EvidenceError):
            parse_assurance_tier(bad)
