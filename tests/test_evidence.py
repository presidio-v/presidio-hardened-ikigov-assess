"""Tests for v0.13.0 external evidence-backed affirmation (consumer side)."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from presidio_ikigov_assess.cli import app
from presidio_ikigov_assess.evidence import (
    EVIDENCE,
    EVIDENCE_VERIFIED,
    SELF,
    EvidenceError,
    EvidenceRef,
    classify,
    evidence_coverage,
    expected_signature,
    load_evidence,
    load_trust_store,
    merge_provenance,
    parse_document,
    verify_ref,
)

# Golden wire-format vector — cross-validated against presidio-hardened-ai's
# producer signer (sign_evidence). If this changes, the cross-repo contract broke.
GOLDEN_CH = "abc123def456"
GOLDEN_SIGNER = "presidio-hardened-ai"
GOLDEN_KEY = "shared-key"
GOLDEN_SIG = "2e7af6d2882dd53847dcf3032e1fe36e58c5a879c224ea97b505b3e3b626b87a"


def _ref(item_id="D1", *, content_hash=GOLDEN_CH, signer=GOLDEN_SIGNER, signature=GOLDEN_SIG):
    return EvidenceRef(
        item_id=item_id,
        source="presidio-hardened-ai",
        source_version="0.2.0",
        ledger_ref="pai-ledger:seq/0",
        content_hash=content_hash,
        signer=signer,
        signature=signature,
        claimed_at="2026-06-08T00:00:00+00:00",
    )


def _doc(refs):
    return {
        "schema": "presidio-hardened/evidence-ref@1",
        "use_case": "fraud-scoring",
        "evidence": [r.__dict__ for r in refs],
    }


def test_golden_signature_matches_producer():
    assert expected_signature(GOLDEN_CH, GOLDEN_SIGNER, GOLDEN_KEY) == GOLDEN_SIG


def test_verify_ref_roundtrip_and_failures():
    ref = _ref()
    assert verify_ref(ref, {GOLDEN_SIGNER: GOLDEN_KEY}) is True
    assert verify_ref(ref, {GOLDEN_SIGNER: "wrong"}) is False
    assert verify_ref(ref, {}) is False  # unknown signer -> fail-closed


def test_parse_document_and_load():
    refs = load_evidence(json.dumps(_doc([_ref("D1"), _ref("O5")])))
    assert [r.item_id for r in refs] == ["D1", "O5"]


@pytest.mark.parametrize(
    "doc",
    [
        {"evidence": [{"item_id": "D1"}]},  # missing fields
        {"schema": "wrong", "evidence": []},  # bad schema
        {"evidence": [dict(_ref("ZZ").__dict__)]},  # unknown item id
        {"nope": 1},  # no evidence array
    ],
)
def test_parse_document_rejects_malformed(doc):
    with pytest.raises(EvidenceError):
        parse_document(doc)


def test_bad_hex_signature_rejected():
    bad = dict(_ref().__dict__)
    bad["signature"] = "NOT-HEX!!"
    with pytest.raises(EvidenceError):
        parse_document({"evidence": [bad]})


def test_load_trust_store():
    # String entries normalise to HMAC; verify_ref still accepts bare strings too.
    assert load_trust_store('{"a": "k"}') == {"a": {"alg": "hmac-sha256", "material": "k"}}
    with pytest.raises(EvidenceError):
        load_trust_store('{"a": 1}')


def test_classify_present_vs_verified():
    refs = [_ref("D1"), _ref("O5")]
    # No trust -> present but unverified.
    res = classify(refs, None)
    assert res.provenance == {"D1": EVIDENCE, "O5": EVIDENCE}
    assert res.affirmed == frozenset({"D1", "O5"})
    assert res.n_verified == 0
    # With trust -> verified.
    res2 = classify(refs, {GOLDEN_SIGNER: GOLDEN_KEY})
    assert res2.provenance == {"D1": EVIDENCE_VERIFIED, "O5": EVIDENCE_VERIFIED}
    assert res2.n_verified == 2


def test_classify_require_verified_is_fail_closed():
    refs = [_ref("D1")]
    # require_verified with no trust -> nothing affirmed.
    res = classify(refs, None, require_verified=True)
    assert res.affirmed == frozenset()
    # with correct trust -> affirmed and verified.
    res2 = classify(refs, {GOLDEN_SIGNER: GOLDEN_KEY}, require_verified=True)
    assert res2.affirmed == frozenset({"D1"})


def test_merge_provenance_and_coverage():
    affirmed = frozenset({"S1", "D1", "O5"})
    prov = merge_provenance(affirmed, {"D1": EVIDENCE_VERIFIED, "O5": EVIDENCE})
    assert prov == {"D1": EVIDENCE_VERIFIED, "O5": EVIDENCE, "S1": SELF}
    cov = evidence_coverage(prov)
    assert cov["affirmed_total"] == 3
    assert cov["evidence_backed"] == 2
    assert cov["verified"] == 1


# ── CLI ──────────────────────────────────────────────────────────────────────
runner = CliRunner()


def _write(tmp_path, refs, trust=None):
    ev = tmp_path / "evidence.json"
    ev.write_text(json.dumps(_doc(refs)))
    files = [str(ev)]
    if trust is not None:
        tr = tmp_path / "trust.json"
        tr.write_text(json.dumps(trust))
        files.append(str(tr))
    return files


def test_cli_assess_with_evidence_affirms_and_reports_provenance(tmp_path):
    ev, tr = _write(tmp_path, [_ref("D1"), _ref("O5")], {GOLDEN_SIGNER: GOLDEN_KEY})
    r = runner.invoke(
        app,
        ["--no-dep-check", "assess", "--affirm", "S1", "--evidence", ev, "--trust", tr, "--quiet"],
    )
    assert r.exit_code == 0, r.stdout
    payload = json.loads(r.stdout)
    assert set(payload["answers"]["affirmed"]) == {"S1", "D1", "O5"}
    cov = payload["evidence_coverage"]
    assert cov["evidence_backed"] == 2 and cov["verified"] == 2
    by_id = {row["id"]: row for row in payload["answers"]["items"]}
    assert by_id["D1"]["provenance"] == EVIDENCE_VERIFIED
    assert by_id["S1"]["provenance"] == SELF


def test_cli_require_evidence_without_trust_affirms_nothing(tmp_path):
    (ev,) = _write(tmp_path, [_ref("D1")])
    r = runner.invoke(
        app,
        ["--no-dep-check", "assess", "--evidence", ev, "--require-evidence", "--quiet"],
    )
    assert r.exit_code == 0, r.stdout
    assert json.loads(r.stdout)["answers"]["affirmed"] == []


def test_cli_evidence_cannot_affirm_skipped_item(tmp_path):
    ev, tr = _write(tmp_path, [_ref("D1")], {GOLDEN_SIGNER: GOLDEN_KEY})
    r = runner.invoke(
        app,
        ["--no-dep-check", "assess", "--skip", "D1", "--evidence", ev, "--trust", tr, "--quiet"],
    )
    assert r.exit_code == 0, r.stdout
    payload = json.loads(r.stdout)
    assert "D1" not in payload["answers"]["affirmed"]
    assert "D1" in payload["answers"]["skipped"]


def test_cli_verify_evidence_ok_and_fail(tmp_path):
    ev, tr = _write(tmp_path, [_ref("D1")], {GOLDEN_SIGNER: GOLDEN_KEY})
    ok = runner.invoke(
        app, ["--no-dep-check", "verify-evidence", "--evidence", ev, "--trust", tr, "--quiet"]
    )
    assert ok.exit_code == 0
    assert json.loads(ok.stdout)["all_verified"] is True

    bad_ev, bad_tr = _write(tmp_path, [_ref("D1")], {GOLDEN_SIGNER: "wrong-key"})
    bad = runner.invoke(
        app,
        ["--no-dep-check", "verify-evidence", "--evidence", bad_ev, "--trust", bad_tr, "--quiet"],
    )
    assert bad.exit_code == 1
    assert json.loads(bad.stdout)["all_verified"] is False


def test_mcp_assess_with_evidence():
    from presidio_ikigov_assess.mcp_server import assess_with_evidence

    payload = assess_with_evidence(
        affirmed=["S1"],
        evidence=[_ref("D1").__dict__],
        trust={GOLDEN_SIGNER: GOLDEN_KEY},
        risk_class="high",
    )
    assert set(payload["answers"]["affirmed"]) == {"S1", "D1"}
    assert payload["evidence_coverage"]["verified"] == 1


# ── Ed25519 public-key verification (v0.14.0) ────────────────────────────────
# Golden vector produced by presidio-hardened-ai's Ed25519 signer over the same
# canonical {content_hash, signer} (content_hash=GOLDEN_CH, signer=GOLDEN_SIGNER).
# Cross-validates the consumer against the producer's wire format.
pytest.importorskip("cryptography")

ED_PUB = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
ED_SIG = (
    "a0dc8599958734457f194ebce15c60ec097754b59897ab5dc758f73abadafe36"
    "97874049d9f7736de4e3a9cc28b2fb4d76b15d8bce7fa0b26c8434bebbba590a"
)


def _ed_ref(item_id="D1"):
    return _ref(item_id, signature=ED_SIG)  # content_hash/signer default to the golden pair


def test_load_trust_store_accepts_string_and_object_entries():
    store = load_trust_store(
        json.dumps(
            {
                "hmac-signer": "secret",
                GOLDEN_SIGNER: {"alg": "ed25519", "public_key": ED_PUB},
            }
        )
    )
    assert store["hmac-signer"] == {"alg": "hmac-sha256", "material": "secret"}
    assert store[GOLDEN_SIGNER] == {"alg": "ed25519", "material": ED_PUB}


def test_load_trust_store_rejects_unknown_alg():
    with pytest.raises(EvidenceError):
        load_trust_store(json.dumps({"s": {"alg": "rsa", "public_key": ED_PUB}}))


def test_verify_ref_ed25519_cross_validates_producer_golden():
    ref = _ed_ref()
    trust = {GOLDEN_SIGNER: {"alg": "ed25519", "public_key": ED_PUB}}
    assert verify_ref(ref, trust) is True
    # Fail-closed: wrong public key, tampered content.
    assert verify_ref(ref, {GOLDEN_SIGNER: {"alg": "ed25519", "public_key": "00" * 32}}) is False
    assert verify_ref(_ref(signature=ED_SIG, content_hash="ffff"), trust) is False


def test_string_trust_entry_is_still_hmac():
    # Back-compat: a bare string entry verifies the HMAC golden vector.
    assert verify_ref(_ref(), {GOLDEN_SIGNER: GOLDEN_KEY}) is True


def test_classify_marks_ed25519_verified():
    res = classify([_ed_ref("D1")], {GOLDEN_SIGNER: {"alg": "ed25519", "public_key": ED_PUB}})
    assert res.provenance == {"D1": EVIDENCE_VERIFIED}
    assert res.n_verified == 1


def test_cli_assess_with_ed25519_trust(tmp_path):
    ev = tmp_path / "evidence.json"
    ev.write_text(json.dumps(_doc([_ed_ref("D1")])))
    tr = tmp_path / "trust.json"
    tr.write_text(json.dumps({GOLDEN_SIGNER: {"alg": "ed25519", "public_key": ED_PUB}}))
    r = runner.invoke(
        app,
        ["--no-dep-check", "assess", "--evidence", str(ev), "--trust", str(tr), "--quiet"],
    )
    assert r.exit_code == 0, r.stdout
    payload = json.loads(r.stdout)
    assert "D1" in payload["answers"]["affirmed"]
    by_id = {row["id"]: row for row in payload["answers"]["items"]}
    assert by_id["D1"]["provenance"] == EVIDENCE_VERIFIED
