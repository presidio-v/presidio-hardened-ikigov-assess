"""Tests for gate certificates (v0.23.0, T-B5) — the certificate is the proof.

Coverage:
- certificate roundtrip (build → sign → verify) for HMAC and Ed25519 issuers;
- third-party verification with NO database present (verify reads cert+trust only);
- tampered certificate, each field class (decision, predicate, affirmation set,
  issuer, signature) fails closed with a distinct reason;
- an embedded evidence-ref failing the trust-store check ⇒ evidence-ref-failure;
- decision-mismatch detection (cert claims OPEN but embedded inputs compute BLOCKED);
- unknown schema; unknown issuer;
- new i18n keys bilingual.
"""

from __future__ import annotations

import copy
import json

import pytest
from typer.testing import CliRunner

from presidio_ikigov_assess import certificate as cert_mod
from presidio_ikigov_assess.checklist import ITEMS_BY_GATE
from presidio_ikigov_assess.cli import app
from presidio_ikigov_assess.evidence import EvidenceRef, expected_signature
from presidio_ikigov_assess.i18n import STRINGS

runner = CliRunner()

# Reuse the evidence golden HMAC wire-format vector for embedded refs.
GOLDEN_CH = "abc123def456"
GOLDEN_SIGNER = "presidio-hardened-ai"
GOLDEN_KEY = "shared-key"
GOLDEN_SIG = expected_signature(GOLDEN_CH, GOLDEN_SIGNER, GOLDEN_KEY)

ISSUER = "presidio-assessor"
ISSUER_SECRET = "issuer-hmac-secret"


def _gate_ids(gate: str) -> frozenset[str]:
    return frozenset(item.id for item in ITEMS_BY_GATE[gate])


def _evidence_ref(item_id: str) -> EvidenceRef:
    return EvidenceRef(
        item_id=item_id,
        source="presidio-hardened-ai",
        source_version="0.2.0",
        ledger_ref="pai-ledger:seq/0",
        content_hash=GOLDEN_CH,
        signer=GOLDEN_SIGNER,
        signature=GOLDEN_SIG,
        claimed_at="2026-06-08T00:00:00+00:00",
    )


def _build_open_cert(*, embed_evidence: bool = False) -> dict:
    gate = "G0"
    all_ids = _gate_ids(gate)
    evidence_refs = {}
    if embed_evidence:
        # Affirm one G0 item via evidence; the rest self-affirmed.
        target = sorted(all_ids)[0]
        evidence_refs = {target: _evidence_ref(target)}
    doc = cert_mod.build_certificate(
        use_case="fraud-scoring",
        gate=gate,
        risk_class="medium",
        affirmed=all_ids,
        skipped=frozenset(),
        issuer=ISSUER,
        assessed_at="2026-07-05T00:00:00Z",
        evidence_refs=evidence_refs,
    )
    cert_mod.sign(doc, alg="hmac-sha256", key_hex_or_secret=ISSUER_SECRET, signer=ISSUER)
    return doc


def _trust(evidence: bool = False) -> dict:
    """A trust store in the *input* (pre-normalisation) shape load_trust_store parses."""
    trust = {ISSUER: {"alg": "hmac-sha256", "key": ISSUER_SECRET}}
    if evidence:
        trust[GOLDEN_SIGNER] = {"alg": "hmac-sha256", "key": GOLDEN_KEY}
    return trust


def _write_evidence_doc(tmp_path, *, ref: EvidenceRef | None = None):
    path = tmp_path / "evidence.json"
    raw_ref = ref or _evidence_ref(sorted(_gate_ids("G0"))[0])
    path.write_text(
        json.dumps({"schema": "presidio-hardened/evidence-ref@1", "evidence": [vars(raw_ref)]})
    )
    return path


# ── Roundtrip ─────────────────────────────────────────────────────────────────


def test_certificate_roundtrip_hmac():
    doc = _build_open_cert()
    assert doc["schema"] == cert_mod.CERTIFICATE_SCHEMA
    assert doc["decision"] == "OPEN"
    res = cert_mod.verify_certificate(doc, _trust())
    assert res.ok is True
    assert res.reason == cert_mod.REASON_OK
    assert res.decision_claimed == "OPEN"
    assert res.decision_recomputed == "OPEN"
    assert res.signer == ISSUER


def test_certificate_roundtrip_ed25519():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes_raw().hex()
    pub_hex = priv.public_key().public_bytes_raw().hex()

    doc = cert_mod.build_certificate(
        use_case="uc",
        gate="G1",
        risk_class="high",
        affirmed=_gate_ids("G1"),
        skipped=frozenset(),
        issuer=ISSUER,
    )
    cert_mod.sign(doc, alg="ed25519", key_hex_or_secret=priv_hex, signer=ISSUER)
    trust = {ISSUER: {"alg": "ed25519", "public_key": pub_hex}}
    res = cert_mod.verify_certificate(doc, trust)
    assert res.ok is True and res.decision_recomputed == "OPEN"


def test_predicate_content_hash_matches_certificate():
    doc = _build_open_cert()
    assert doc["framework_content_hash"] == cert_mod.gate_predicate_content_hash()
    assert doc["predicate"]["predicate_content_hash"] == cert_mod.gate_predicate_content_hash()


def test_tamper_predicate_hash_after_resigning_fails():
    doc = _build_open_cert()
    doc["framework_content_hash"] = "0" * 64
    doc["predicate"]["predicate_content_hash"] = "0" * 64
    cert_mod.sign(doc, alg="hmac-sha256", key_hex_or_secret=ISSUER_SECRET, signer=ISSUER)
    res = cert_mod.verify_certificate(doc, _trust())
    assert res.ok is False
    assert res.reason == cert_mod.REASON_PREDICATE_MISMATCH


def test_tamper_predicate_gate_items_after_resigning_fails():
    doc = _build_open_cert()
    doc["predicate"]["gate_items"] = doc["predicate"]["gate_items"][:-1]
    cert_mod.sign(doc, alg="hmac-sha256", key_hex_or_secret=ISSUER_SECRET, signer=ISSUER)
    res = cert_mod.verify_certificate(doc, _trust())
    assert res.ok is False
    assert res.reason == cert_mod.REASON_PREDICATE_MISMATCH


# ── Third-party verification with NO database present ─────────────────────────


def test_third_party_verifies_without_database(tmp_path, monkeypatch):
    """A verifier with only the cert + trust store — no ~/.iga DB — verifies.

    Point the store at an empty temp dir and confirm verify never touches it.
    """
    monkeypatch.setenv("HOME", str(tmp_path))  # no assessments.db here
    doc = _build_open_cert(embed_evidence=True)
    cert_path = tmp_path / "cert.json"
    trust_path = tmp_path / "trust.json"
    cert_path.write_text(json.dumps(doc))
    trust_path.write_text(json.dumps(_trust(evidence=True)))

    r = runner.invoke(
        app,
        [
            "--no-dep-check",
            "verify-certificate",
            "--certificate",
            str(cert_path),
            "--trust",
            str(trust_path),
            "--quiet",
        ],
    )
    assert r.exit_code == 0, r.stdout
    payload = json.loads(r.stdout)
    assert payload["ok"] is True
    assert payload["evidence_checked"] == 1 and payload["evidence_ok"] == 1
    # No DB file was created by verification.
    assert not (tmp_path / ".iga" / "assessments.db").exists()


# ── Tampering — each field class fails closed with a distinct reason ──────────


def test_tamper_decision_field_mismatch():
    doc = _build_open_cert()
    doc["decision"] = "BLOCKED"  # claim differs from recomputation (signature now stale)
    res = cert_mod.verify_certificate(doc, _trust())
    # The signature covers the decision, so this trips bad-signature first
    # (fail-closed at the earliest gate).
    assert res.ok is False
    assert res.reason == cert_mod.REASON_BAD_SIGNATURE


def test_tamper_decision_after_resigning_is_mismatch():
    """Re-sign a doc whose decision was hand-edited: signature ok, recompute catches it."""
    doc = _build_open_cert()
    doc["decision"] = "BLOCKED"
    cert_mod.sign(doc, alg="hmac-sha256", key_hex_or_secret=ISSUER_SECRET, signer=ISSUER)
    res = cert_mod.verify_certificate(doc, _trust())
    assert res.ok is False
    assert res.reason == cert_mod.REASON_DECISION_MISMATCH
    assert res.decision_claimed == "BLOCKED"
    assert res.decision_recomputed == "OPEN"


def test_tamper_predicate_inputs_flip_decision():
    """Cert claims OPEN but embedded predicate inputs compute BLOCKED after tamper.

    Flip a gate item's status to denied in the affirmation set and re-sign: the
    recomputation now yields BLOCKED, exposing the false OPEN claim.
    """
    doc = _build_open_cert()
    doc["affirmation_set"][0]["status"] = cert_mod.STATUS_DENIED
    cert_mod.sign(doc, alg="hmac-sha256", key_hex_or_secret=ISSUER_SECRET, signer=ISSUER)
    res = cert_mod.verify_certificate(doc, _trust())
    assert res.ok is False
    assert res.reason == cert_mod.REASON_DECISION_MISMATCH
    assert res.decision_recomputed == "BLOCKED"


def test_tamper_signature_block():
    doc = _build_open_cert()
    doc["signature"]["sig"] = "00" * 32
    res = cert_mod.verify_certificate(doc, _trust())
    assert res.ok is False and res.reason == cert_mod.REASON_BAD_SIGNATURE


def test_tamper_issuer_unknown():
    doc = _build_open_cert()
    doc["signature"]["signer"] = "somebody-else"
    res = cert_mod.verify_certificate(doc, _trust())
    assert res.ok is False and res.reason == cert_mod.REASON_UNKNOWN_ISSUER


def test_unknown_schema():
    doc = _build_open_cert()
    doc["schema"] = "presidio-hardened/not-a-certificate@9"
    res = cert_mod.verify_certificate(doc, _trust())
    assert res.ok is False and res.reason == cert_mod.REASON_UNKNOWN_SCHEMA


def test_malformed_certificate():
    res = cert_mod.verify_certificate({"schema": cert_mod.CERTIFICATE_SCHEMA}, _trust())
    assert res.ok is False and res.reason == cert_mod.REASON_MALFORMED


# ── Embedded evidence-ref failing the trust-store check ──────────────────────


def test_embedded_evidence_ref_fails_trust_store():
    doc = _build_open_cert(embed_evidence=True)
    # Trust store knows the issuer but NOT the evidence signer's real key.
    trust = {
        ISSUER: {"alg": "hmac-sha256", "key": ISSUER_SECRET},
        GOLDEN_SIGNER: {"alg": "hmac-sha256", "key": "wrong-key"},
    }
    res = cert_mod.verify_certificate(doc, trust)
    assert res.ok is False
    assert res.reason == cert_mod.REASON_EVIDENCE_REF_FAILURE
    assert res.evidence_checked == 1 and res.evidence_ok == 0


def test_verifier_rejects_cert_whose_embedded_ref_fails_under_verifier_store():
    doc = _build_open_cert(embed_evidence=True)
    verifier_trust = {
        ISSUER: {"alg": "hmac-sha256", "key": ISSUER_SECRET},
        GOLDEN_SIGNER: {"alg": "hmac-sha256", "key": "verifier-does-not-trust-this-key"},
    }
    res = cert_mod.verify_certificate(doc, verifier_trust)
    assert res.ok is False
    assert res.reason == cert_mod.REASON_EVIDENCE_REF_FAILURE


def test_embedded_evidence_ref_tampered_content_hash():
    doc = _build_open_cert(embed_evidence=True)
    for entry in doc["affirmation_set"]:
        if "evidence_ref" in entry:
            entry["evidence_ref"]["content_hash"] = "deadbeef"
    cert_mod.sign(doc, alg="hmac-sha256", key_hex_or_secret=ISSUER_SECRET, signer=ISSUER)
    res = cert_mod.verify_certificate(doc, _trust(evidence=True))
    assert res.ok is False and res.reason == cert_mod.REASON_EVIDENCE_REF_FAILURE


def test_embedded_evidence_ref_verifies_with_correct_trust():
    doc = _build_open_cert(embed_evidence=True)
    res = cert_mod.verify_certificate(doc, _trust(evidence=True))
    assert res.ok is True and res.evidence_ok == 1


# ── signing_bytes excludes the signature field (documented contract) ─────────


def test_signing_bytes_excludes_signature():
    doc = _build_open_cert()
    before = cert_mod.signing_bytes(doc)
    doc2 = copy.deepcopy(doc)
    doc2["signature"]["sig"] = "ffff"
    after = cert_mod.signing_bytes(doc2)
    assert before == after  # signature field is not part of the signed bytes


# ── CLI end-to-end ────────────────────────────────────────────────────────────


def test_cli_certify_and_verify_roundtrip(tmp_path):
    key_file = tmp_path / "issuer.key"
    key_file.write_text(ISSUER_SECRET)
    cert_out = tmp_path / "cert.json"
    r = runner.invoke(
        app,
        [
            "--no-dep-check",
            "certify",
            "--gate",
            "G0",
            "--use-case",
            "uc",
            "--affirm",
            ",".join(sorted(_gate_ids("G0"))),
            "--issuer",
            ISSUER,
            "--sign-alg",
            "hmac-sha256",
            "--sign-key-file",
            str(key_file),
            "--output",
            str(cert_out),
        ],
    )
    assert r.exit_code == 0, r.stdout
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(json.dumps(_trust()))
    v = runner.invoke(
        app,
        [
            "--no-dep-check",
            "verify-certificate",
            "--certificate",
            str(cert_out),
            "--trust",
            str(trust_path),
            "--quiet",
        ],
    )
    assert v.exit_code == 0, v.stdout
    assert json.loads(v.stdout)["ok"] is True


def test_cli_certify_with_evidence_requires_trust(tmp_path):
    key_file = tmp_path / "issuer.key"
    key_file.write_text(ISSUER_SECRET)
    evidence_path = _write_evidence_doc(tmp_path)
    cert_out = tmp_path / "cert.json"
    r = runner.invoke(
        app,
        [
            "--no-dep-check",
            "certify",
            "--gate",
            "G0",
            "--use-case",
            "uc",
            "--evidence",
            str(evidence_path),
            "--issuer",
            ISSUER,
            "--sign-alg",
            "hmac-sha256",
            "--sign-key-file",
            str(key_file),
            "--output",
            str(cert_out),
        ],
    )
    assert r.exit_code == 1
    assert "--trust is required" in (r.stdout + r.stderr)
    assert not cert_out.exists()


def test_cli_certify_refuses_bad_evidence_ref(tmp_path):
    key_file = tmp_path / "issuer.key"
    key_file.write_text(ISSUER_SECRET)
    evidence_path = _write_evidence_doc(tmp_path)
    trust_path = tmp_path / "trust.json"
    trust_path.write_text(
        json.dumps(
            {
                ISSUER: {"alg": "hmac-sha256", "key": ISSUER_SECRET},
                GOLDEN_SIGNER: {"alg": "hmac-sha256", "key": "wrong-key"},
            }
        )
    )
    cert_out = tmp_path / "cert.json"
    r = runner.invoke(
        app,
        [
            "--no-dep-check",
            "certify",
            "--gate",
            "G0",
            "--use-case",
            "uc",
            "--evidence",
            str(evidence_path),
            "--trust",
            str(trust_path),
            "--issuer",
            ISSUER,
            "--sign-alg",
            "hmac-sha256",
            "--sign-key-file",
            str(key_file),
            "--output",
            str(cert_out),
        ],
    )
    assert r.exit_code == 1
    combined = r.stdout + r.stderr
    assert "evidence ref failed verification" in combined
    assert "item_id=" in combined
    assert not cert_out.exists()


def test_cli_certify_requires_key(tmp_path, monkeypatch):
    monkeypatch.delenv("IGA_SIGN_KEY", raising=False)
    r = runner.invoke(
        app,
        ["--no-dep-check", "certify", "--gate", "G0", "--issuer", ISSUER],
    )
    assert r.exit_code == 1


def test_cli_verify_certificate_bad_signature_exits_1(tmp_path):
    doc = _build_open_cert()
    doc["signature"]["sig"] = "00" * 32
    cert_path = tmp_path / "cert.json"
    trust_path = tmp_path / "trust.json"
    cert_path.write_text(json.dumps(doc))
    trust_path.write_text(json.dumps(_trust()))
    v = runner.invoke(
        app,
        [
            "--no-dep-check",
            "verify-certificate",
            "--certificate",
            str(cert_path),
            "--trust",
            str(trust_path),
            "--quiet",
        ],
    )
    assert v.exit_code == 1
    assert json.loads(v.stdout)["reason"] == cert_mod.REASON_BAD_SIGNATURE


# ── Localisation ──────────────────────────────────────────────────────────────


def test_new_cert_i18n_keys_bilingual():
    keys = [
        "cert_written",
        "cert_decision_label",
        "cert_err_no_key",
        "cert_err_build",
        "cert_verify_ok",
        "cert_verify_fail",
        "cert_verify_reason_unknown-schema",
        "cert_verify_reason_bad-signature",
        "cert_verify_reason_unknown-issuer",
        "cert_verify_reason_evidence-ref-failure",
        "cert_verify_reason_decision-mismatch",
        "chain_link_ok",
        "chain_link_fail",
    ]
    for key in keys:
        entry = STRINGS.get(key)
        assert entry, f"missing i18n key: {key}"
        assert entry.get("de") and entry.get("en"), f"key not bilingual: {key}"
