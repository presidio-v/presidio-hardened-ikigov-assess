"""Gate certificate identity, ``certificate_content_hash`` (evidence contract ADR-0006).

Coverage:
- the family evidence contract vector: a certificate issued by this tool hashes to
  the pinned identity, and that identity is sha256 over :func:`signing_bytes`;
- the identity ignores the ``signature`` block (re-signing keeps it) and moves with
  any signed field;
- a freshly built certificate has the same identity before and after signing;
- fail-closed inputs: non-object, foreign schema, non-canonicalisable content.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

import presidio_ikigov_assess.certificate as cert_mod
from presidio_ikigov_assess.certificate import (
    CertificateError,
    certificate_content_hash,
    signing_bytes,
)
from presidio_ikigov_assess.checklist import ITEMS_BY_GATE
from presidio_ikigov_assess.evidence import load_trust_store

VECTOR = json.loads(
    (Path(__file__).parent / "fixtures" / "gate_certificate_identity_vector.json").read_text(
        encoding="utf-8"
    )
)
CERT = VECTOR["certificate"]
IDENTITY = VECTOR["identity"]


def test_vector_identity_pinned() -> None:
    assert IDENTITY == "dbb7c6a36f0aea55bbe5dead3daf8f4f3d59116966e79bd4b78ecfe2a83ebd4a"
    assert certificate_content_hash(CERT) == IDENTITY


def test_identity_is_sha256_of_signing_bytes() -> None:
    assert certificate_content_hash(CERT) == hashlib.sha256(signing_bytes(CERT)).hexdigest()


def test_vector_certificate_verifies() -> None:
    pytest.importorskip("cryptography")
    trust = load_trust_store(json.dumps(VECTOR["trust_store"]))
    at = datetime.strptime(VECTOR["verify_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    result = cert_mod.verify_certificate(CERT, trust, now=at)
    assert result.ok, result.reason


def test_identity_ignores_signature_block() -> None:
    unsigned = {k: v for k, v in CERT.items() if k != "signature"}
    assert certificate_content_hash(unsigned) == IDENTITY
    resigned = copy.deepcopy(CERT)
    resigned["signature"] = {"alg": "hmac-sha256", "signer": "someone-else", "sig": "00"}
    assert certificate_content_hash(resigned) == IDENTITY


def test_identity_moves_with_signed_content() -> None:
    tampered = copy.deepcopy(CERT)
    tampered["decision"] = "BLOCKED"
    assert certificate_content_hash(tampered) != IDENTITY
    reordered = copy.deepcopy(CERT)
    reordered["parents"] = ["a" * 64]
    assert certificate_content_hash(reordered) != IDENTITY


def test_identity_is_lowercase_hex_64() -> None:
    value = certificate_content_hash(CERT)
    assert len(value) == 64
    assert value == value.lower()
    int(value, 16)


def test_identity_stable_across_signing() -> None:
    ids = frozenset(item.id for item in ITEMS_BY_GATE["G0"])
    doc = cert_mod.build_certificate(
        use_case="identity-test",
        gate="G0",
        risk_class="medium",
        affirmed=ids,
        skipped=frozenset(),
        issuer="presidio-assessor",
        assessed_at="2026-07-02T00:00:00Z",
    )
    before = certificate_content_hash(doc)
    signed = cert_mod.sign(
        dict(doc), alg="hmac-sha256", key_hex_or_secret="issuer-secret", signer="presidio-assessor"
    )
    assert "signature" in signed
    assert certificate_content_hash(signed) == before


@pytest.mark.parametrize("bad", [None, [], "certificate", 42])
def test_non_object_fails_closed(bad: object) -> None:
    with pytest.raises(CertificateError):
        certificate_content_hash(bad)  # type: ignore[arg-type]


def test_foreign_schema_fails_closed() -> None:
    other = dict(CERT, schema="presidio-hardened/training-run@1")
    with pytest.raises(CertificateError):
        certificate_content_hash(other)
    missing = {k: v for k, v in CERT.items() if k != "schema"}
    with pytest.raises(CertificateError):
        certificate_content_hash(missing)


def test_non_canonicalisable_fails_closed() -> None:
    odd = dict(CERT, extra={1, 2})
    with pytest.raises(CertificateError):
        certificate_content_hash(odd)


def test_exported() -> None:
    assert "certificate_content_hash" in cert_mod.__all__
