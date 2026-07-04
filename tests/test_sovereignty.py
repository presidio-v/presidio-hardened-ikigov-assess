"""Tests for T-B4 workshop evidence sovereignty (keygen / sign / attest / verify).

Coverage:
- Family golden-vector pin: build_attestation reproduces the frozen
  presidio-evidence vectors/workshop-attestation/ content hash AND the
  deterministic Ed25519 signature, byte-for-byte.
- keygen: 0600 private key + .pub, refuses overwrite, trust-store snippet.
- Customer owner-signing round-trip: run → sign → verify (owner role).
- Owner-pubkey consistency: verifying with a key that does not match the
  embedded owner block fails closed.
- attest: fail-closed without a key; attestation round-trip via
  verify --require-attestation; tampered manifest and wrong assessor key fail.
- Standalone sign.py from the leave-behind: keygen + sign on a "customer
  machine" (subprocess), then iga verify passes.
- Leave-behind completeness (R3/R4): sign.py, SIGNING.md, assessor.pub listed
  in the manifest with correct hashes.
- Localisation: every new i18n key resolves in de and en.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from presidio_ikigov_assess import __version__
from presidio_ikigov_assess.cli import app
from presidio_ikigov_assess.i18n import STRINGS
from presidio_ikigov_assess.sovereignty import (
    ATTESTATION_SCHEMA,
    DEFAULT_SCOPE,
    SovereigntyError,
    build_attestation,
    sha256_hex,
    verify_attestation,
)

runner = CliRunner()

_FIXTURE = Path(__file__).parent / "fixtures" / "medical_classification.json"


def combined_output(result) -> str:
    """Runner stdout+stderr, robust across click versions (see test_cli.py)."""
    text = result.output or ""
    if getattr(result, "stderr_bytes", None) is not None:
        text += result.stderr
    return text


# ── Family golden vector (presidio-evidence vectors/workshop-attestation/) ────
# Appended 2026-07-02; both language suites green. Ed25519 is deterministic,
# so the signature itself is pinnable, not only the content hash.
_FAMILY_TEST_PRIV = "01" * 32
_VECTOR_PARENT_HASH = "91733915b4797d71bfc42422dcfff105b512f613c4d6ad3f1013463d1853b378"
_VECTOR_CONTENT_HASH = "4d078c2e27c41cd31c57c8f929ae699af894e18bcb8075aec8b60d0f8b261b90"
_VECTOR_SIGNATURE = (
    "edc388eda691d02669816a3ea1597727f2ebb7ae8e40b10e52337d11a549664e"
    "b8f5681dc6514265a22859588195ca7d11565ec6f88bec9b611b678d44f7c30d"
)
# The payload whose canonical hash is the vector's `attests` target.
_VECTOR_ATTESTED_PAYLOAD = {
    "run_id": "golden-run",
    "strategy": "pipeline",
    "degree": 4,
    "samples_per_second": 250,
    "duration_s": 7200,
    "device_count": 4,
    "parents": ["a" * 64],
}


@pytest.fixture()
def _no_dep_check(monkeypatch):
    monkeypatch.setenv("IGA_NO_DEP_CHECK", "1")
    yield


def _gen_keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    return priv.private_bytes_raw().hex(), priv.public_key().public_bytes_raw().hex()


def _run_workshop(tmp_path: Path, *extra: str) -> Path:
    """Run the workshop for one use case; return its artifact directory."""
    out_dir = tmp_path / "out"
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--select",
            "infusion-pump-dosing",
            "--out",
            str(out_dir),
            "--quiet",
            *extra,
        ],
    )
    assert result.exit_code == 0, result.output
    return out_dir / "infusion-pump-dosing"


# ── Family golden-vector pin ──────────────────────────────────────────────────


def test_build_attestation_reproduces_family_golden_vector():
    """Byte-identity with presidio-evidence vectors/workshop-attestation/."""
    assert sha256_hex(_VECTOR_ATTESTED_PAYLOAD) == _VECTOR_PARENT_HASH

    reading, envelope = build_attestation(
        _VECTOR_ATTESTED_PAYLOAD,
        engagement="eng-golden-001",
        private_key_hex=_FAMILY_TEST_PRIV,
        workshop_date="2026-07-02",
        source_version="test",
        generated_at="2026-07-02T00:00:00+00:00",
        ledger_ref="iga-ledger:seq/1",
    )
    content = reading["attested_content"]
    assert content["role"] == "assessor"
    assert content["attests"] == _VECTOR_PARENT_HASH
    assert content["parents"] == [_VECTOR_PARENT_HASH]
    assert content["scope"] == DEFAULT_SCOPE
    assert reading["schema"] == ATTESTATION_SCHEMA
    assert reading["content_hash"] == _VECTOR_CONTENT_HASH

    ref = envelope["evidence"][0]
    assert ref["content_hash"] == _VECTOR_CONTENT_HASH
    # Deterministic Ed25519: the family vector's signature, byte-for-byte.
    assert ref["signature"] == _VECTOR_SIGNATURE
    assert ref["item_id"] == "workshop-attestation/eng-golden-001"


def test_build_attestation_rejects_bad_fields():
    for kwargs in (
        {"engagement": ""},
        {"engagement": "bad\nid"},
        {"engagement": "x" * 200},
        {"engagement": "ok", "workshop_date": "02.07.2026"},
        {"engagement": "ok", "scope": "s\x00cope"},
    ):
        with pytest.raises(SovereigntyError):
            build_attestation({"a": "b"}, private_key_hex=_FAMILY_TEST_PRIV, **kwargs)


# ── keygen ────────────────────────────────────────────────────────────────────


def test_keygen_creates_0600_key_and_refuses_overwrite(tmp_path, _no_dep_check):
    key_path = tmp_path / "customer-key.hex"
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "keygen",
            "--out",
            str(key_path),
            "--signer",
            "ACME GmbH",
            "--lang",
            "en",
        ],
    )
    assert result.exit_code == 0, result.output
    assert key_path.exists()
    mode = stat.S_IMODE(os.stat(key_path).st_mode)
    assert mode == 0o600
    pub = Path(str(key_path) + ".pub").read_text().strip()
    assert len(pub) == 64
    assert "ACME GmbH" in result.output  # trust-store snippet

    # Refuses overwrite without --force.
    result2 = runner.invoke(app, ["--no-dep-check", "workshop", "keygen", "--out", str(key_path)])
    assert result2.exit_code == 1


# ── Owner signing round-trip ──────────────────────────────────────────────────


def test_owner_sign_and_verify_roundtrip(tmp_path, _no_dep_check):
    uc_dir = _run_workshop(tmp_path)
    priv_hex, pub_hex = _gen_keypair()
    key_file = tmp_path / "ck.hex"
    key_file.write_text(priv_hex)

    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "sign",
            "--dir",
            str(uc_dir),
            "--key",
            str(key_file),
            "--signer",
            "ACME GmbH",
            "--lang",
            "en",
        ],
    )
    assert result.exit_code == 0, result.output

    manifest = json.loads((uc_dir / "manifest.json").read_text())
    assert manifest["owner"]["signer"] == "ACME GmbH"
    assert manifest["owner"]["public_key"] == pub_hex
    assert manifest["signed"] is True and manifest["UNSIGNED"] is False
    sig = json.loads((uc_dir / "manifest.sig").read_text())
    assert sig["role"] == "owner"

    verify = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "verify",
            "--dir",
            str(uc_dir),
            "--pubkey",
            pub_hex,
            "--quiet",
        ],
    )
    assert verify.exit_code == 0, verify.output
    payload = json.loads(verify.output.strip().splitlines()[-1])
    assert payload["ok"] is True
    assert payload["signature"] is True
    assert payload["signature_role"] == "owner"
    assert payload["owner_signed"] is True


def test_owner_pubkey_mismatch_fails_closed(tmp_path, _no_dep_check):
    uc_dir = _run_workshop(tmp_path)
    priv_hex, _pub_hex = _gen_keypair()
    _other_priv, other_pub = _gen_keypair()
    key_file = tmp_path / "ck.hex"
    key_file.write_text(priv_hex)
    runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "sign",
            "--dir",
            str(uc_dir),
            "--key",
            str(key_file),
            "--signer",
            "ACME",
        ],
    )
    verify = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "verify",
            "--dir",
            str(uc_dir),
            "--pubkey",
            other_pub,
            "--quiet",
        ],
    )
    assert verify.exit_code == 1


def test_signed_wrong_manifest_schema_fails_closed(tmp_path, _no_dep_check):
    uc_dir = _run_workshop(tmp_path)
    manifest_path = uc_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["schema"] = "presidio-hardened/not-a-workshop-manifest@1"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    priv_hex, pub_hex = _gen_keypair()
    key_file = tmp_path / "ck.hex"
    key_file.write_text(priv_hex)
    sign = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "sign",
            "--dir",
            str(uc_dir),
            "--key",
            str(key_file),
            "--signer",
            "ACME",
        ],
    )
    assert sign.exit_code == 0, sign.output

    verify = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "verify",
            "--dir",
            str(uc_dir),
            "--pubkey",
            pub_hex,
            "--quiet",
        ],
    )
    assert verify.exit_code == 1
    payload = json.loads(verify.output.strip().splitlines()[-1])
    assert payload["signature"] is True
    assert payload["schema_ok"] is False


def test_sign_replaces_facilitator_signature_with_warning(tmp_path, _no_dep_check):
    presidio_priv, _presidio_pub = _gen_keypair()
    presidio_key = tmp_path / "pk.hex"
    presidio_key.write_text(presidio_priv)
    uc_dir = _run_workshop(tmp_path, "--sign-key", str(presidio_key), "--signer", "Presidio Group")

    cust_priv, cust_pub = _gen_keypair()
    cust_key = tmp_path / "ck.hex"
    cust_key.write_text(cust_priv)
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "sign",
            "--dir",
            str(uc_dir),
            "--key",
            str(cust_key),
            "--signer",
            "ACME GmbH",
            "--lang",
            "en",
        ],
    )
    assert result.exit_code == 0
    # Replacement warning names the old signer (normalise Rich line wrapping —
    # newlines replace spaces at word boundaries — and stderr capture).
    normalised = re.sub(r"\s+", " ", combined_output(result))
    assert "Presidio Group" in normalised

    verify = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "verify",
            "--dir",
            str(uc_dir),
            "--pubkey",
            cust_pub,
            "--quiet",
        ],
    )
    assert verify.exit_code == 0


# ── Attestation ───────────────────────────────────────────────────────────────


def test_attest_requires_key_fail_closed(tmp_path, _no_dep_check, monkeypatch):
    monkeypatch.delenv("IGA_WORKSHOP_SIGN_KEY", raising=False)
    uc_dir = _run_workshop(tmp_path)
    result = runner.invoke(
        app,
        ["--no-dep-check", "workshop", "attest", "--dir", str(uc_dir), "--engagement", "eng-1"],
    )
    assert result.exit_code == 1
    assert not (uc_dir / "attestation.json").exists()


def _dual_sign_and_attest(tmp_path: Path) -> tuple[Path, str, str]:
    """Full T-B4 ceremony; returns (uc_dir, customer_pub, assessor_pub)."""
    uc_dir = _run_workshop(tmp_path)
    cust_priv, cust_pub = _gen_keypair()
    cust_key = tmp_path / "ck.hex"
    cust_key.write_text(cust_priv)
    r1 = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "sign",
            "--dir",
            str(uc_dir),
            "--key",
            str(cust_key),
            "--signer",
            "ACME",
        ],
    )
    assert r1.exit_code == 0, r1.output

    ass_priv, ass_pub = _gen_keypair()
    ass_key = tmp_path / "ak.hex"
    ass_key.write_text(ass_priv)
    r2 = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "attest",
            "--dir",
            str(uc_dir),
            "--engagement",
            "eng-hc-2026-001",
            "--workshop-date",
            "2026-08-20",
            "--sign-key",
            str(ass_key),
            "--lang",
            "en",
        ],
    )
    assert r2.exit_code == 0, r2.output
    return uc_dir, cust_pub, ass_pub


def test_attest_and_require_attestation_roundtrip(tmp_path, _no_dep_check):
    uc_dir, cust_pub, ass_pub = _dual_sign_and_attest(tmp_path)

    reading = json.loads((uc_dir / "attestation.content.json").read_text())
    manifest = json.loads((uc_dir / "manifest.json").read_text())
    assert reading["attested_content"]["attests"] == sha256_hex(manifest)
    assert reading["attested_content"]["parents"] == [sha256_hex(manifest)]

    verify = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "verify",
            "--dir",
            str(uc_dir),
            "--pubkey",
            cust_pub,
            "--require-attestation",
            "--attestation-pubkey",
            ass_pub,
            "--quiet",
        ],
    )
    assert verify.exit_code == 0, verify.output
    payload = json.loads(verify.output.strip().splitlines()[-1])
    assert payload["ok"] is True and payload["attestation"] is True


def test_attestation_fails_on_bad_reading_schema(tmp_path, _no_dep_check):
    uc_dir, _cust_pub, ass_pub = _dual_sign_and_attest(tmp_path)
    reading_path = uc_dir / "attestation.content.json"
    reading = json.loads(reading_path.read_text())
    reading["schema"] = "presidio-hardened/not-workshop-attestation@1"
    reading_path.write_text(json.dumps(reading, indent=2))

    ok, reason, _signer = verify_attestation(uc_dir, ass_pub)
    assert ok is False
    assert reason == "bad-reading-schema"


def test_attestation_fails_on_tampered_manifest(tmp_path, _no_dep_check):
    uc_dir, cust_pub, ass_pub = _dual_sign_and_attest(tmp_path)
    manifest = json.loads((uc_dir / "manifest.json").read_text())
    manifest["risk_class"] = "low"  # tamper AFTER attestation
    (uc_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    ok, reason, _signer = verify_attestation(uc_dir, ass_pub)
    assert ok is False
    assert reason == "attests-manifest-mismatch"


def test_attestation_fails_with_wrong_assessor_key(tmp_path, _no_dep_check):
    uc_dir, cust_pub, _ass_pub = _dual_sign_and_attest(tmp_path)
    _other_priv, other_pub = _gen_keypair()
    ok, reason, _signer = verify_attestation(uc_dir, other_pub)
    assert ok is False
    assert reason == "signature-invalid"


def test_require_attestation_missing_fails(tmp_path, _no_dep_check):
    uc_dir = _run_workshop(tmp_path)
    _priv, pub = _gen_keypair()
    verify = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "verify",
            "--dir",
            str(uc_dir),
            "--pubkey",
            pub,
            "--require-attestation",
            "--attestation-pubkey",
            pub,
            "--quiet",
        ],
    )
    assert verify.exit_code == 1
    payload = json.loads(verify.output.strip().splitlines()[-1])
    assert payload["attestation"] is False


def test_invalid_public_keys_fail_before_artifact_success(tmp_path, _no_dep_check):
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--select",
            "infusion-pump-dosing",
            "--out",
            str(tmp_path / "out"),
            "--quiet",
            "--assessor-pubkey",
            "not-hex",
        ],
    )
    assert result.exit_code == 1

    uc_dir = _run_workshop(tmp_path / "valid")
    _priv, pub = _gen_keypair()
    verify = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "verify",
            "--dir",
            str(uc_dir),
            "--pubkey",
            pub,
            "--require-attestation",
            "--attestation-pubkey",
            "not-hex",
            "--quiet",
        ],
    )
    assert verify.exit_code == 1


# ── Leave-behind completeness (R3 / R4) ──────────────────────────────────────


def test_leavebehind_ships_signer_ceremony_and_assessor_key(tmp_path, _no_dep_check):
    presidio_priv, presidio_pub = _gen_keypair()
    pk = tmp_path / "pk.hex"
    pk.write_text(presidio_priv)
    uc_dir = _run_workshop(tmp_path, "--sign-key", str(pk))

    manifest = json.loads((uc_dir / "manifest.json").read_text())
    for name in ("sign.py", "SIGNING.md", "assessor.pub"):
        assert name in manifest["artifacts"], name
        content = (uc_dir / name).read_bytes()
        import hashlib

        assert manifest["artifacts"][name]["sha256"] == hashlib.sha256(content).hexdigest()
    assert (uc_dir / "assessor.pub").read_text().strip() == presidio_pub
    # Ceremony doc is bilingual.
    ceremony = (uc_dir / "SIGNING.md").read_text()
    assert "## Deutsch" in ceremony and "## English" in ceremony


def test_workshop_manifest_and_attestation_versions_match_package(tmp_path, _no_dep_check):
    uc_dir, _cust_pub, _ass_pub = _dual_sign_and_attest(tmp_path)
    manifest = json.loads((uc_dir / "manifest.json").read_text())
    reading = json.loads((uc_dir / "attestation.content.json").read_text())
    envelope = json.loads((uc_dir / "attestation.json").read_text())

    assert manifest["tool_version"] == __version__
    assert reading["source_version"] == __version__
    assert envelope["source_version"] == __version__


def test_standalone_signer_works_on_customer_machine(tmp_path, _no_dep_check):
    """Simulate the USB ceremony: keygen + sign via the shipped sign.py only."""
    uc_dir = _run_workshop(tmp_path)
    sign_py = uc_dir / "sign.py"
    key_out = tmp_path / "cust.hex"

    r1 = subprocess.run(
        [sys.executable, str(sign_py), "keygen", "--out", str(key_out)],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r1.returncode == 0, r1.stderr
    pub = Path(str(key_out) + ".pub").read_text().strip()

    r2 = subprocess.run(
        [
            sys.executable,
            str(sign_py),
            "sign",
            "--dir",
            str(uc_dir),
            "--key",
            str(key_out),
            "--signer",
            "ACME GmbH",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert r2.returncode == 0, r2.stderr

    verify = runner.invoke(
        app,
        ["--no-dep-check", "workshop", "verify", "--dir", str(uc_dir), "--pubkey", pub, "--quiet"],
    )
    assert verify.exit_code == 0, verify.output


# ── Localisation ──────────────────────────────────────────────────────────────


def test_new_i18n_keys_bilingual():
    keys = [
        "keygen_done",
        "keygen_pubkey_label",
        "keygen_trust_snippet_label",
        "keygen_err_exists",
        "sign_done",
        "sign_warn_replaces",
        "sign_err_no_key",
        "attest_done",
        "attest_err_no_key",
        "attest_warn_no_owner",
        "attest_err_bad_field",
        "verify_attestation_ok",
        "verify_attestation_fail",
        "verify_attestation_missing",
        "verify_owner_label",
        "workshop_verify_schema_fail",
    ]
    for key in keys:
        entry = STRINGS.get(key)
        assert entry, f"missing i18n key: {key}"
        assert entry.get("de") and entry.get("en"), f"key not bilingual: {key}"
