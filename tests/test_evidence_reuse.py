"""One signed evidence-ref must not count for more than one item (audit C-1).

The evidence-ref signature covers ``{content_hash, signer}`` only, not the
``item_id`` (frozen family wire format), so a single genuine ref can be copied
under every checklist item and each copy still verifies. Before the fix, that one
ref reported 25/25 items evidence-verified and every gate OPEN under
``--require-evidence``. A ref claimed for several items now verifies for none.
"""

from __future__ import annotations

import json

from typer.testing import CliRunner

from presidio_ikigov_assess import certificate as cert_mod
from presidio_ikigov_assess.checklist import ITEMS_BY_GATE, VALID_ITEM_IDS
from presidio_ikigov_assess.cli import app
from presidio_ikigov_assess.evidence import (
    EVIDENCE,
    EVIDENCE_VERIFIED,
    EvidenceRef,
    classify,
    expected_signature,
    resolve_affirmations,
    reused_refs,
)

SIGNER = "presidio-hardened-ai"
KEY = "shared-key"
CH = "abc123def456"
TRUST = {SIGNER: KEY}
runner = CliRunner()


def _ref(item_id: str, content_hash: str = CH) -> EvidenceRef:
    return EvidenceRef(
        item_id=item_id,
        source="presidio-hardened-ai",
        source_version="0.30.0",
        ledger_ref="pai-ledger:seq/1",
        content_hash=content_hash,
        signer=SIGNER,
        signature=expected_signature(content_hash, SIGNER, KEY),
        claimed_at="2026-06-12T00:00:00+00:00",
    )


def _relabelled() -> list[EvidenceRef]:
    """The attack: one genuine signed ref cloned under all 25 item ids."""
    return [_ref(item) for item in sorted(VALID_ITEM_IDS)]


def test_relabelled_ref_verifies_for_no_item():
    refs = _relabelled()
    assert reused_refs(refs) == frozenset({(SIGNER, CH)})
    res = classify(refs, TRUST)
    assert res.n_verified == 0
    assert set(res.provenance.values()) == {EVIDENCE}
    assert res.reused == frozenset(VALID_ITEM_IDS)
    assert classify(refs, TRUST, require_verified=True).affirmed == frozenset()


def test_require_evidence_counts_nothing_from_a_relabelled_ref():
    aff = resolve_affirmations(
        frozenset(VALID_ITEM_IDS), frozenset(), _relabelled(), TRUST, require_evidence=True
    )
    assert aff.affirmed == frozenset()
    assert aff.asserted == frozenset(VALID_ITEM_IDS)
    assert aff.coverage["reused_refs_not_verified"] == len(VALID_ITEM_IDS)


def test_distinct_refs_and_duplicates_for_one_item_still_verify():
    refs = [_ref("D1", "aa11" * 4), _ref("D1", "aa11" * 4), _ref("O5", "bb22" * 4)]
    res = classify(refs, TRUST, require_verified=True)
    assert res.affirmed == frozenset({"D1", "O5"})
    assert res.provenance == {"D1": EVIDENCE_VERIFIED, "O5": EVIDENCE_VERIFIED}
    assert res.reused == frozenset()


def test_verify_evidence_cli_rejects_relabelled_refs(tmp_path):
    ev = tmp_path / "ev.json"
    ev.write_text(
        json.dumps(
            {
                "schema": "presidio-hardened/evidence-ref@1",
                "use_case": "fraud-scoring",
                "evidence": [r.__dict__ for r in _relabelled()[:3]],
            }
        )
    )
    tr = tmp_path / "trust.json"
    tr.write_text(json.dumps(TRUST))
    r = runner.invoke(
        app,
        ["--no-dep-check", "verify-evidence", "--evidence", str(ev), "--trust", str(tr), "-q"],
    )
    assert r.exit_code == 1
    payload = json.loads(r.stdout)
    assert payload["all_verified"] is False
    assert all(ref["reused"] and not ref["verified"] for ref in payload["refs"])


def test_certificate_with_ref_embedded_under_two_items_fails():
    issuer, secret = "presidio-assessor", "issuer-hmac-secret"
    ids = sorted(item.id for item in ITEMS_BY_GATE["G0"])
    doc = cert_mod.build_certificate(
        use_case="fraud-scoring",
        gate="G0",
        risk_class="medium",
        affirmed=frozenset(ids),
        skipped=frozenset(),
        issuer=issuer,
        assessed_at="2026-06-12T00:00:00Z",
        evidence_refs={ids[0]: _ref(ids[0]), ids[1]: _ref(ids[1])},
    )
    cert_mod.sign(doc, alg="hmac-sha256", key_hex_or_secret=secret, signer=issuer)
    trust = {
        issuer: {"alg": "hmac-sha256", "key": secret},
        SIGNER: {"alg": "hmac-sha256", "key": KEY},
    }
    res = cert_mod.verify_certificate(doc, trust)
    assert res.ok is False and res.reason == cert_mod.REASON_EVIDENCE_REF_FAILURE
