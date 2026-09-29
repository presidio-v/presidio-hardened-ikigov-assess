"""Gate certificate lineage, validity, grounding and tier surfacing (v0.26.0).

Coverage:
- ``parents`` (ADR-0002): round-trip inside the signed content; malformed, empty-
  but-present, duplicate and oversized lists fail closed; omitted when empty;
- ``not_after``: round-trip; verification fails closed past the bound (``expired``);
  malformed bound is ``malformed-certificate``; a bound before ``assessed_at`` is
  refused at build time; ``--at`` drives the verifier clock from the CLI;
- ``grounding``: ``self`` vs ``evidence-verified`` recomputed by the verifier;
  a re-signed tampered claim is ``grounding-mismatch``; ``min_grounding`` floor;
- assurance tiers: embedded refs round-trip the declared @2 tier; the verifier
  reports the weakest declared tier and applies ``min_evidence_tier``; an unknown
  embedded tier is ``evidence-ref-failure``; a certificate declaring a non-attested
  tier of its own is ``unsupported-assurance-tier``;
- a pre-v0.26 certificate (none of the new fields) verifies unchanged.
"""

from __future__ import annotations

import copy
import json
from datetime import datetime, timezone

import pytest
from typer.testing import CliRunner

from presidio_ikigov_assess import certificate as cert_mod
from presidio_ikigov_assess.checklist import ITEMS_BY_GATE
from presidio_ikigov_assess.cli import app
from presidio_ikigov_assess.evidence import EvidenceRef, expected_signature

runner = CliRunner()

GOLDEN_CH = "abc123def456"
GOLDEN_SIGNER = "presidio-hardened-ai"
GOLDEN_KEY = "shared-key"
GOLDEN_SIG = expected_signature(GOLDEN_CH, GOLDEN_SIGNER, GOLDEN_KEY)

ISSUER = "presidio-assessor"
ISSUER_SECRET = "issuer-hmac-secret"
ASSESSED = "2026-09-17T00:00:00Z"
PARENT_A = "9173" + "ab" * 30  # 64 hex chars
PARENT_B = "d674a115" + "cd" * 28


def _gate_ids(gate: str) -> frozenset[str]:
    return frozenset(item.id for item in ITEMS_BY_GATE[gate])


def _ref(item_id: str, tier: str = "attested") -> EvidenceRef:
    return EvidenceRef(
        item_id=item_id,
        source="presidio-hardened-ai",
        source_version="0.30.0",
        ledger_ref="pai-ledger:seq/1",
        content_hash=GOLDEN_CH,
        signer=GOLDEN_SIGNER,
        signature=GOLDEN_SIG,
        claimed_at="2026-06-12T00:00:00+00:00",
        assurance_tier=tier,
    )


def _trust(evidence: bool = False) -> dict:
    trust = {ISSUER: {"alg": "hmac-sha256", "key": ISSUER_SECRET}}
    if evidence:
        trust[GOLDEN_SIGNER] = {"alg": "hmac-sha256", "key": GOLDEN_KEY}
    return trust


def _sign(doc: dict) -> dict:
    return cert_mod.sign(doc, alg="hmac-sha256", key_hex_or_secret=ISSUER_SECRET, signer=ISSUER)


def _cert(*, gate="G0", evidence_for=None, tiers=None, **kw) -> dict:
    """Build+sign a G0 OPEN certificate; ``evidence_for`` = item ids backed by refs."""
    ids = _gate_ids(gate)
    tiers = tiers or {}
    refs = {i: _ref(i, tiers.get(i, "attested")) for i in (evidence_for or ())}
    doc = cert_mod.build_certificate(
        use_case="fraud-scoring",
        gate=gate,
        risk_class="medium",
        affirmed=ids,
        skipped=frozenset(),
        issuer=ISSUER,
        assessed_at=ASSESSED,
        evidence_refs=refs,
        **kw,
    )
    return _sign(doc)


def _at(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


# ── parents (ADR-0002) ────────────────────────────────────────────────────────


def test_parents_round_trip_inside_signed_content():
    doc = _cert(parents=[PARENT_A, PARENT_B])
    assert doc["parents"] == [PARENT_A, PARENT_B]  # order-preserving (P3)
    res = cert_mod.verify_certificate(doc, _trust())
    assert res.ok and res.parents == (PARENT_A, PARENT_B)
    # Rewiring lineage after signing breaks the issuer signature (P1).
    tampered = copy.deepcopy(doc)
    tampered["parents"] = [PARENT_B]
    assert cert_mod.verify_certificate(tampered, _trust()).reason == cert_mod.REASON_BAD_SIGNATURE


def test_parents_omitted_when_empty():
    doc = _cert(parents=[])
    assert "parents" not in doc
    assert cert_mod.verify_certificate(doc, _trust()).parents == ()


@pytest.mark.parametrize(
    "bad",
    [
        ["ABCDEF12"],  # uppercase
        ["abc"],  # too short
        [PARENT_A, PARENT_A],  # duplicate
        ["z" * 64],  # non-hex
        [42],  # not a string
        "abcdef12",  # not a list
    ],
)
def test_parents_malformed_refused_at_build(bad):
    with pytest.raises(cert_mod.CertificateError):
        _cert(parents=bad)


def test_parents_too_many_refused():
    with pytest.raises(cert_mod.CertificateError):
        _cert(parents=[f"{i:064x}" for i in range(65)])


def test_parents_malformed_in_resigned_certificate_is_malformed():
    doc = _cert()
    doc["parents"] = []  # present-but-empty violates P3
    _sign(doc)
    assert cert_mod.verify_certificate(doc, _trust()).reason == cert_mod.REASON_MALFORMED
    doc["parents"] = ["not-hex!"]
    _sign(doc)
    assert cert_mod.verify_certificate(doc, _trust()).reason == cert_mod.REASON_MALFORMED


# ── not_after (validity as revocation) ────────────────────────────────────────


def test_not_after_round_trip_and_expiry():
    doc = _cert(not_after="2027-09-17T00:00:00Z")
    assert doc["not_after"] == "2027-09-17T00:00:00Z"
    ok = cert_mod.verify_certificate(doc, _trust(), now=_at("2027-09-16T23:59:59Z"))
    assert ok.ok and ok.not_after == "2027-09-17T00:00:00Z"
    on_bound = cert_mod.verify_certificate(doc, _trust(), now=_at("2027-09-17T00:00:00Z"))
    assert on_bound.ok  # inclusive
    late = cert_mod.verify_certificate(doc, _trust(), now=_at("2027-09-17T00:00:01Z"))
    assert late.ok is False and late.reason == cert_mod.REASON_EXPIRED
    assert late.not_after == "2027-09-17T00:00:00Z" and late.signer == ISSUER


def test_not_after_absent_means_no_expiry():
    doc = _cert()
    assert "not_after" not in doc
    assert cert_mod.verify_certificate(doc, _trust(), now=_at("2099-01-01T00:00:00Z")).ok


@pytest.mark.parametrize("bad", ["2027-09-17", "2027-09-17T00:00:00+00:00", "soon", ""])
def test_not_after_malformed_refused_at_build(bad):
    with pytest.raises(cert_mod.CertificateError):
        _cert(not_after=bad)


def test_not_after_before_assessed_at_refused():
    with pytest.raises(cert_mod.CertificateError):
        _cert(not_after="2026-09-16T23:59:59Z")


def test_not_after_requires_strict_assessed_at():
    with pytest.raises(cert_mod.CertificateError):
        cert_mod.build_certificate(
            use_case="uc",
            gate="G0",
            risk_class="low",
            affirmed=_gate_ids("G0"),
            skipped=frozenset(),
            issuer=ISSUER,
            assessed_at="2026-07-05T00:00:00+00:00",
            not_after="2027-07-05T00:00:00Z",
        )


def test_not_after_malformed_in_resigned_certificate_is_malformed():
    doc = _cert()
    doc["not_after"] = "never"
    _sign(doc)
    assert cert_mod.verify_certificate(doc, _trust()).reason == cert_mod.REASON_MALFORMED


def test_verifier_clock_must_be_timezone_aware():
    doc = _cert(not_after="2027-09-17T00:00:00Z")
    with pytest.raises(cert_mod.CertificateError):
        cert_mod.verify_certificate(doc, _trust(), now=datetime(2027, 1, 1))


def test_add_days_and_parse_timestamp_helpers():
    assert cert_mod.add_days(ASSESSED, 365) == "2027-09-17T00:00:00Z"
    assert cert_mod.parse_timestamp("2026-09-17T00:00:00Z") == _at(ASSESSED)
    assert cert_mod.parse_timestamp("2026-09-17T00:00:00") is None
    assert cert_mod.parse_timestamp(None) is None
    with pytest.raises(cert_mod.CertificateError):
        cert_mod.add_days("2026-09-17", 1)
    with pytest.raises(cert_mod.CertificateError):
        cert_mod.add_days(ASSESSED, -1)


# ── grounding ─────────────────────────────────────────────────────────────────


def test_grounding_self_when_any_affirmed_item_lacks_evidence():
    doc = _cert(evidence_for=[sorted(_gate_ids("G0"))[0]])
    assert doc["grounding"] == cert_mod.GROUNDING_SELF
    res = cert_mod.verify_certificate(doc, _trust(evidence=True))
    assert res.ok and res.grounding == cert_mod.GROUNDING_SELF


def test_grounding_evidence_verified_when_every_affirmed_item_has_a_ref():
    doc = _cert(evidence_for=sorted(_gate_ids("G0")))
    assert doc["grounding"] == cert_mod.GROUNDING_EVIDENCE_VERIFIED
    res = cert_mod.verify_certificate(doc, _trust(evidence=True))
    assert res.ok and res.grounding == cert_mod.GROUNDING_EVIDENCE_VERIFIED


def test_grounding_of_blocked_gate_with_no_affirmations_is_evidence_verified():
    # Vacuous: nothing affirmed ⇒ nothing self-attested. The decision (BLOCKED)
    # is what carries the meaning; grounding only qualifies affirmations.
    doc = cert_mod.build_certificate(
        use_case="uc",
        gate="G0",
        risk_class="medium",
        affirmed=frozenset(),
        skipped=frozenset(),
        issuer=ISSUER,
        assessed_at=ASSESSED,
    )
    assert doc["decision"] == "BLOCKED"
    assert doc["grounding"] == cert_mod.GROUNDING_EVIDENCE_VERIFIED


def test_grounding_tampered_and_resigned_is_mismatch():
    doc = _cert()  # self-grounded
    doc["grounding"] = cert_mod.GROUNDING_EVIDENCE_VERIFIED
    _sign(doc)
    res = cert_mod.verify_certificate(doc, _trust())
    assert res.ok is False and res.reason == cert_mod.REASON_GROUNDING_MISMATCH
    assert res.grounding == cert_mod.GROUNDING_SELF


def test_min_grounding_floor():
    selfg = _cert()
    assert cert_mod.verify_certificate(selfg, _trust(), min_grounding="self").ok
    below = cert_mod.verify_certificate(selfg, _trust(), min_grounding="evidence-verified")
    assert below.ok is False and below.reason == cert_mod.REASON_GROUNDING_BELOW_MINIMUM
    full = _cert(evidence_for=sorted(_gate_ids("G0")))
    assert cert_mod.verify_certificate(
        full, _trust(evidence=True), min_grounding="evidence-verified"
    ).ok
    with pytest.raises(cert_mod.CertificateError):
        cert_mod.verify_certificate(selfg, _trust(), min_grounding="strong")


# ── assurance tiers ───────────────────────────────────────────────────────────


def test_certificate_declares_attested_tier():
    doc = _cert()
    assert doc["assurance_tier"] == "attested"


def test_certificate_with_non_attested_tier_is_unsupported():
    for tier in ("optimistic", "zk", "bogus"):
        doc = _cert()
        doc["assurance_tier"] = tier
        _sign(doc)
        res = cert_mod.verify_certificate(doc, _trust())
        assert res.ok is False and res.reason == cert_mod.REASON_UNSUPPORTED_TIER


def test_embedded_refs_round_trip_declared_tier_and_report_weakest():
    ids = sorted(_gate_ids("G0"))
    tiers = {ids[0]: "zk", ids[1]: "optimistic"}
    for i in ids[2:]:
        tiers[i] = "zk"
    doc = _cert(evidence_for=ids, tiers=tiers)
    embedded = {e["id"]: e["evidence_ref"]["assurance_tier"] for e in doc["affirmation_set"]}
    assert embedded[ids[0]] == "zk" and embedded[ids[1]] == "optimistic"
    res = cert_mod.verify_certificate(doc, _trust(evidence=True))
    assert res.ok and res.evidence_tier_min == "optimistic"
    # The signature of a ref is tier-independent (ADR-0003): still verifies.
    assert res.evidence_ok == len(ids)


def test_min_evidence_tier_floor():
    ids = sorted(_gate_ids("G0"))
    doc = _cert(evidence_for=ids, tiers=dict.fromkeys(ids, "optimistic"))
    assert cert_mod.verify_certificate(doc, _trust(evidence=True), min_evidence_tier="attested").ok
    assert cert_mod.verify_certificate(
        doc, _trust(evidence=True), min_evidence_tier="optimistic"
    ).ok
    res = cert_mod.verify_certificate(doc, _trust(evidence=True), min_evidence_tier="zk")
    assert res.ok is False and res.reason == cert_mod.REASON_EVIDENCE_TIER_BELOW_MINIMUM
    assert res.evidence_tier_min == "optimistic"
    with pytest.raises(cert_mod.CertificateError):
        cert_mod.verify_certificate(doc, _trust(evidence=True), min_evidence_tier="platinum")


def test_min_evidence_tier_is_vacuous_without_embedded_refs():
    doc = _cert()
    res = cert_mod.verify_certificate(doc, _trust(), min_evidence_tier="zk")
    assert res.ok and res.evidence_tier_min == ""


def test_embedded_ref_with_unknown_tier_is_evidence_ref_failure():
    ids = sorted(_gate_ids("G0"))
    doc = _cert(evidence_for=ids[:1])
    entry = next(e for e in doc["affirmation_set"] if e["id"] == ids[0])
    entry["evidence_ref"]["assurance_tier"] = "platinum"
    _sign(doc)
    res = cert_mod.verify_certificate(doc, _trust(evidence=True))
    assert res.ok is False and res.reason == cert_mod.REASON_EVIDENCE_REF_FAILURE


def test_embedded_ref_without_tier_defaults_to_attested():
    ids = sorted(_gate_ids("G0"))
    doc = _cert(evidence_for=ids[:1])
    entry = next(e for e in doc["affirmation_set"] if e["id"] == ids[0])
    del entry["evidence_ref"]["assurance_tier"]
    _sign(doc)
    res = cert_mod.verify_certificate(doc, _trust(evidence=True))
    assert res.ok and res.evidence_tier_min == "attested"


# ── grandfathering ────────────────────────────────────────────────────────────


def test_pre_v026_certificate_shape_verifies_unchanged():
    doc = _cert()
    for key in ("assurance_tier", "grounding"):
        del doc[key]
    assert "parents" not in doc and "not_after" not in doc
    _sign(doc)
    res = cert_mod.verify_certificate(doc, _trust(), now=_at("2099-01-01T00:00:00Z"))
    assert res.ok and res.grounding == cert_mod.GROUNDING_SELF
    assert res.evidence_tier_min == "" and res.not_after == "" and res.parents == ()


# ── CLI ───────────────────────────────────────────────────────────────────────


def _write_trust(tmp_path, evidence=False):
    path = tmp_path / "trust.json"
    path.write_text(json.dumps(_trust(evidence)))
    return path


def test_cli_certify_parents_valid_days_and_verify_at(tmp_path):
    trust = _write_trust(tmp_path)
    out = tmp_path / "cert.json"
    ids = ",".join(sorted(_gate_ids("G0")))
    res = runner.invoke(
        app,
        [
            "certify",
            "--gate",
            "G0",
            "--affirm",
            ids,
            "--issuer",
            ISSUER,
            "--sign-alg",
            "hmac-sha256",
            "--sign-key",
            ISSUER_SECRET,
            "--parent",
            PARENT_A,
            "--parent",
            PARENT_B,
            "--valid-days",
            "30",
            "--output",
            str(out),
            "--quiet",
        ],
    )
    assert res.exit_code == 0, res.output
    doc = json.loads(out.read_text())
    assert doc["parents"] == [PARENT_A, PARENT_B]
    assert doc["grounding"] == "self" and doc["assurance_tier"] == "attested"
    assert cert_mod.add_days(doc["assessed_at"], 30) == doc["not_after"]

    ok = runner.invoke(
        app,
        ["verify-certificate", "--certificate", str(out), "--trust", str(trust), "--quiet"],
    )
    assert ok.exit_code == 0, ok.output
    payload = json.loads(ok.output.strip().splitlines()[-1])
    assert payload["ok"] is True
    assert payload["parents"] == [PARENT_A, PARENT_B]
    assert payload["grounding"] == "self" and payload["evidence_tier_min"] is None
    assert payload["not_after"] == doc["not_after"]

    expired = runner.invoke(
        app,
        [
            "verify-certificate",
            "--certificate",
            str(out),
            "--trust",
            str(trust),
            "--at",
            "2099-01-01T00:00:00Z",
            "--quiet",
        ],
    )
    assert expired.exit_code == 1
    assert json.loads(expired.output.strip().splitlines()[-1])["reason"] == "expired"

    human = runner.invoke(
        app,
        ["verify-certificate", "--certificate", str(out), "--trust", str(trust)],
    )
    assert human.exit_code == 0 and "Grounding: self" in human.output


def test_cli_certify_refuses_malformed_parent(tmp_path):
    res = runner.invoke(
        app,
        [
            "certify",
            "--gate",
            "G0",
            "--issuer",
            ISSUER,
            "--sign-alg",
            "hmac-sha256",
            "--sign-key",
            ISSUER_SECRET,
            "--parent",
            "NOT-HEX",
            "--quiet",
        ],
    )
    assert res.exit_code == 1 and "Cannot build certificate" in res.output


def test_cli_verify_policy_flags_and_bad_inputs(tmp_path):
    trust = _write_trust(tmp_path)
    cert = tmp_path / "cert.json"
    cert.write_text(json.dumps(_cert()))
    base = ["verify-certificate", "--certificate", str(cert), "--trust", str(trust)]

    below = runner.invoke(app, [*base, "--min-grounding", "evidence-verified", "--quiet"])
    assert below.exit_code == 1
    assert json.loads(below.output.strip().splitlines()[-1])["reason"] == "grounding-below-minimum"

    for flag, value in (
        ("--at", "tomorrow"),
        ("--min-grounding", "strong"),
        ("--min-evidence-tier", "platinum"),
    ):
        bad = runner.invoke(app, [*base, flag, value])
        assert bad.exit_code == 1, (flag, bad.output)
        assert "Error:" in bad.output


def test_cli_certify_embeds_declared_v2_tier(tmp_path):
    trust = _write_trust(tmp_path, evidence=True)
    ids = sorted(_gate_ids("G0"))
    ev = tmp_path / "evidence.json"
    ev.write_text(
        json.dumps(
            {
                "schema": "presidio-hardened/evidence-ref@2",
                "evidence": [dict(vars(_ref(ids[0], "optimistic")))],
            }
        )
    )
    out = tmp_path / "cert.json"
    res = runner.invoke(
        app,
        [
            "certify",
            "--gate",
            "G0",
            "--affirm",
            ",".join(ids[1:]),
            "--evidence",
            str(ev),
            "--trust",
            str(trust),
            "--issuer",
            ISSUER,
            "--sign-alg",
            "hmac-sha256",
            "--sign-key",
            ISSUER_SECRET,
            "--output",
            str(out),
            "--quiet",
        ],
    )
    assert res.exit_code == 0, res.output
    doc = json.loads(out.read_text())
    entry = next(e for e in doc["affirmation_set"] if e["id"] == ids[0])
    assert entry["evidence_ref"]["assurance_tier"] == "optimistic"
    ver = runner.invoke(
        app,
        [
            "verify-certificate",
            "--certificate",
            str(out),
            "--trust",
            str(trust),
            "--min-evidence-tier",
            "zk",
            "--quiet",
        ],
    )
    assert ver.exit_code == 1
    payload = json.loads(ver.output.strip().splitlines()[-1])
    assert payload["reason"] == "evidence-tier-below-minimum"
    assert payload["evidence_tier_min"] == "optimistic"


def test_new_i18n_keys_bilingual():
    from presidio_ikigov_assess.i18n import STRINGS

    for key in (
        "cert_verify_reason_expired",
        "cert_verify_reason_unsupported-assurance-tier",
        "cert_verify_reason_grounding-mismatch",
        "cert_verify_reason_grounding-below-minimum",
        "cert_verify_reason_evidence-tier-below-minimum",
        "cert_verify_grounding",
        "cert_err_bad_at",
        "cert_err_bad_grounding",
        "cert_err_bad_tier",
    ):
        entry = STRINGS.get(key)
        assert entry and entry.get("de") and entry.get("en"), key
