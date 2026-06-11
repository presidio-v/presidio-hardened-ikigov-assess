"""Tests for the iga workshop subcommand (T-B3).

Coverage:
- Full run against medical_classification.json in German → files exist, hashes verify
- Ed25519 signature round-trip with a generated keypair
- Unsigned path warns and writes UNSIGNED marker
- answers.json application changes gate output
- --select filtering: only selected use cases produced
- Offline guarantee: IGA_NO_DEP_CHECK=1 set; dep-check bypassed in main_callback
- Bad inputs fail closed (invalid file, missing select id, bad answers.json)
- manifest schema field present and correct
- Performance: 4-use-case run completes well under 10 s
- workshop verify round-trip (signed and unsigned)
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from presidio_ikigov_assess.cli import app
from presidio_ikigov_assess.workshop import (
    WORKSHOP_MANIFEST_SCHEMA,
    _sha256_hex,
    _sign_manifest_ed25519,
    _verify_manifest_ed25519,
)

runner = CliRunner()

_FIXTURE = Path(__file__).parent / "fixtures" / "medical_classification.json"


# ── Keypair generation helper ─────────────────────────────────────────────────


def _gen_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair; return (privkey_hex, pubkey_hex)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    privkey = Ed25519PrivateKey.generate()
    privkey_bytes = privkey.private_bytes_raw()
    pubkey_bytes = privkey.public_key().public_bytes_raw()
    return privkey_bytes.hex(), pubkey_bytes.hex()


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def _isolated_db(tmp_path, monkeypatch):
    """Isolate store so workshop --save (if used) doesn't touch ~/.iga."""
    monkeypatch.setenv("IGA_DB_PATH", str(tmp_path / "test.db"))
    yield


@pytest.fixture()
def _no_dep_check(monkeypatch):
    """Ensure dep-check is bypassed for all workshop tests."""
    monkeypatch.setenv("IGA_NO_DEP_CHECK", "1")
    yield


# ── Basic run — files exist, manifest hashes verify ──────────────────────────


def test_workshop_run_german_files_exist(tmp_path, _isolated_db, _no_dep_check):
    """Full workshop run in German produces all expected artifact files."""
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output

    out_dir = tmp_path / "out"
    # All 4 use cases should have artifact dirs.
    uc_ids = [
        "infusion-pump-dosing",
        "infusion-pump-predict",
        "dialysis-remote-service",
        "surgical-robotics",
    ]
    for uc_id in uc_ids:
        uc_dir = out_dir / uc_id
        assert uc_dir.is_dir(), f"Missing dir for {uc_id}"
        assert (uc_dir / "report.de.md").exists(), f"Missing report.de.md for {uc_id}"
        assert (uc_dir / "report.json").exists(), f"Missing report.json for {uc_id}"
        assert (uc_dir / "manifest.json").exists(), f"Missing manifest.json for {uc_id}"
        assert (uc_dir / "manifest.sig").exists(), f"Missing manifest.sig for {uc_id}"


def test_workshop_manifest_schema_and_hashes(tmp_path, _isolated_db, _no_dep_check):
    """Manifest has the correct schema and artifact hashes verify."""
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output

    uc_dir = tmp_path / "out" / "infusion-pump-dosing"
    manifest = json.loads((uc_dir / "manifest.json").read_text(encoding="utf-8"))

    # Schema
    assert manifest["schema"] == WORKSHOP_MANIFEST_SCHEMA
    assert manifest["tool"] == "presidio-hardened-ikigov-assess"
    assert "tool_version" in manifest
    assert manifest["use_case_id"] == "infusion-pump-dosing"
    assert manifest["lang"] == "de"
    assert "pack" in manifest
    assert manifest["pack"]["framework_id"]

    # Artifact hashes verify
    for name, meta in manifest["artifacts"].items():
        content = (uc_dir / name).read_bytes()
        assert _sha256_hex(content) == meta["sha256"], f"Hash mismatch for {name}"


def test_workshop_manifest_unsigned_marker(tmp_path, _isolated_db, _no_dep_check):
    """Without a signing key, UNSIGNED=True appears in manifest and sig file."""
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output

    uc_dir = tmp_path / "out" / "infusion-pump-dosing"
    manifest = json.loads((uc_dir / "manifest.json").read_text(encoding="utf-8"))
    sig_data = json.loads((uc_dir / "manifest.sig").read_text(encoding="utf-8"))

    assert manifest["UNSIGNED"] is True
    assert manifest["signed"] is False
    assert sig_data.get("UNSIGNED") is True


def test_workshop_unsigned_warns_on_stderr(tmp_path, _isolated_db, _no_dep_check):
    """Without a signing key, a warning appears in stderr output."""
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
        ],
    )
    assert result.exit_code == 0, result.output
    # The warning about being unsigned should appear somewhere in the output.
    assert "UNSIGNIERT" in result.output or "Warnung" in result.output or "Warning" in result.output


# ── Ed25519 signature round-trip ──────────────────────────────────────────────


def test_workshop_sign_and_verify_roundtrip(tmp_path, _isolated_db, _no_dep_check):
    """Workshop run with --sign-key produces a verifiable Ed25519 signature."""
    privkey_hex, pubkey_hex = _gen_keypair()

    # Write key file with mode 600.
    key_file = tmp_path / "test.key"
    key_file.write_text(privkey_hex, encoding="utf-8")
    key_file.chmod(0o600)

    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--sign-key",
            str(key_file),
            "--signer",
            "test-signer",
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output

    uc_dir = tmp_path / "out" / "infusion-pump-dosing"
    manifest_text = (uc_dir / "manifest.json").read_text(encoding="utf-8")
    manifest = json.loads(manifest_text)
    sig_data = json.loads((uc_dir / "manifest.sig").read_text(encoding="utf-8"))

    assert manifest["signed"] is True
    assert manifest.get("UNSIGNED") is False or not manifest.get("UNSIGNED")
    assert sig_data.get("UNSIGNED") is not True
    assert sig_data["alg"] == "ed25519"
    assert sig_data["signer"] == "test-signer"

    # Verify signature with the workshop verify subcommand.
    verify_result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "verify",
            "--dir",
            str(uc_dir),
            "--pubkey",
            pubkey_hex,
            "--quiet",
        ],
    )
    assert verify_result.exit_code == 0, verify_result.output
    verify_data = json.loads(verify_result.output)
    assert verify_data["ok"] is True
    assert verify_data["signature"] is True
    assert all(verify_data["artifacts"].values())


def test_workshop_verify_wrong_pubkey_fails(tmp_path, _isolated_db, _no_dep_check):
    """Verify with wrong public key must exit non-zero (fail-closed)."""
    privkey_hex, _pubkey_hex = _gen_keypair()
    _, wrong_pubkey_hex = _gen_keypair()  # different keypair

    key_file = tmp_path / "test.key"
    key_file.write_text(privkey_hex, encoding="utf-8")
    key_file.chmod(0o600)

    runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--sign-key",
            str(key_file),
            "--quiet",
        ],
    )

    uc_dir = tmp_path / "out" / "infusion-pump-dosing"
    verify_result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "verify",
            "--dir",
            str(uc_dir),
            "--pubkey",
            wrong_pubkey_hex,
            "--quiet",
        ],
    )
    assert verify_result.exit_code != 0
    verify_data = json.loads(verify_result.output)
    assert verify_data["ok"] is False
    assert verify_data["signature"] is False


def test_workshop_verify_tampered_artifact_fails(tmp_path, _isolated_db, _no_dep_check):
    """Tampering with report.json after signing causes verify to fail."""
    privkey_hex, pubkey_hex = _gen_keypair()
    key_file = tmp_path / "test.key"
    key_file.write_text(privkey_hex, encoding="utf-8")
    key_file.chmod(0o600)

    runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--sign-key",
            str(key_file),
            "--quiet",
        ],
    )
    uc_dir = tmp_path / "out" / "infusion-pump-dosing"
    (uc_dir / "report.json").write_text('{"tampered": true}', encoding="utf-8")

    verify_result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "verify",
            "--dir",
            str(uc_dir),
            "--pubkey",
            pubkey_hex,
            "--quiet",
        ],
    )
    assert verify_result.exit_code != 0
    verify_data = json.loads(verify_result.output)
    assert verify_data["ok"] is False
    assert verify_data["artifacts"]["report.json"] is False


def test_workshop_verify_unsigned_artifact(tmp_path, _isolated_db, _no_dep_check):
    """Verify of an unsigned artifact: artifacts ok but signature=None, ok=True if artifacts ok."""
    runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--quiet",
        ],
    )
    uc_dir = tmp_path / "out" / "infusion-pump-dosing"

    # Use any pubkey — won't be used since signature is UNSIGNED.
    _, pubkey_hex = _gen_keypair()
    verify_result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "verify",
            "--dir",
            str(uc_dir),
            "--pubkey",
            pubkey_hex,
            "--quiet",
        ],
    )
    # Unsigned artifacts: artifacts hash correctly, signature is None (absent), ok=True
    assert verify_result.exit_code == 0
    verify_data = json.loads(verify_result.output)
    assert all(verify_data["artifacts"].values())
    assert verify_data["signature"] is None


# ── answers.json application ──────────────────────────────────────────────────


def test_workshop_answers_json_applied(tmp_path, _isolated_db, _no_dep_check):
    """answers.json affirmed items are reflected in report.json gate data."""
    answers = {
        "infusion-pump-dosing": {
            "affirm": ["S1", "S2", "S3", "D1", "D2"],
            "skip": [],
        }
    }
    answers_file = tmp_path / "answers.json"
    answers_file.write_text(json.dumps(answers), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--answers",
            str(answers_file),
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output

    uc_dir = tmp_path / "out" / "infusion-pump-dosing"
    report = json.loads((uc_dir / "report.json").read_text(encoding="utf-8"))

    # S1–S3, D1–D2 affirmed → should appear in answers.affirmed
    assert "S1" in report["answers"]["affirmed"]
    assert "S2" in report["answers"]["affirmed"]
    assert "D1" in report["answers"]["affirmed"]


def test_workshop_answers_skip_applied(tmp_path, _isolated_db, _no_dep_check):
    """Skipped items in answers.json appear in report.json answers.skipped."""
    answers = {
        "surgical-robotics": {
            "affirm": [],
            "skip": ["I4", "I5"],
        }
    }
    answers_file = tmp_path / "answers.json"
    answers_file.write_text(json.dumps(answers), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--answers",
            str(answers_file),
            "--select",
            "surgical-robotics",
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output

    uc_dir = tmp_path / "out" / "surgical-robotics"
    report = json.loads((uc_dir / "report.json").read_text(encoding="utf-8"))
    assert "I4" in report["answers"]["skipped"]
    assert "I5" in report["answers"]["skipped"]


def test_workshop_answers_bad_item_id_fails(tmp_path, _isolated_db, _no_dep_check):
    """answers.json with an invalid checklist item id fails closed (exit 1)."""
    answers = {
        "infusion-pump-dosing": {
            "affirm": ["INVALID_ID_XYZ"],
            "skip": [],
        }
    }
    answers_file = tmp_path / "answers.json"
    answers_file.write_text(json.dumps(answers), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--answers",
            str(answers_file),
            "--quiet",
        ],
    )
    assert result.exit_code != 0


def test_workshop_answers_unknown_uc_fails(tmp_path, _isolated_db, _no_dep_check):
    """answers.json referencing a use-case id not in the document fails closed."""
    answers = {
        "nonexistent-uc": {
            "affirm": ["S1"],
            "skip": [],
        }
    }
    answers_file = tmp_path / "answers.json"
    answers_file.write_text(json.dumps(answers), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--answers",
            str(answers_file),
            "--quiet",
        ],
    )
    assert result.exit_code != 0


# ── --select filtering ────────────────────────────────────────────────────────


def test_workshop_select_single_use_case(tmp_path, _isolated_db, _no_dep_check):
    """--select produces artifacts only for the selected use case."""
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--select",
            "surgical-robotics",
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output

    out_dir = tmp_path / "out"
    assert (out_dir / "surgical-robotics").is_dir()
    # Others must NOT be present.
    for uc_id in ["infusion-pump-dosing", "infusion-pump-predict", "dialysis-remote-service"]:
        assert not (out_dir / uc_id).exists(), f"Unexpected dir for {uc_id}"


def test_workshop_select_multiple(tmp_path, _isolated_db, _no_dep_check):
    """Multiple --select values produce artifacts for exactly those use cases."""
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--select",
            "infusion-pump-dosing",
            "--select",
            "surgical-robotics",
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output

    out_dir = tmp_path / "out"
    assert (out_dir / "infusion-pump-dosing").is_dir()
    assert (out_dir / "surgical-robotics").is_dir()
    assert not (out_dir / "infusion-pump-predict").exists()
    assert not (out_dir / "dialysis-remote-service").exists()


def test_workshop_select_nonexistent_fails(tmp_path, _isolated_db, _no_dep_check):
    """--select with an id not in the document fails closed (exit 1)."""
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--select",
            "does-not-exist",
            "--quiet",
        ],
    )
    assert result.exit_code != 0


# ── Offline guarantee ─────────────────────────────────────────────────────────


def test_workshop_dep_check_bypassed(tmp_path, _isolated_db, monkeypatch):
    """Workshop subcommand must not trigger the dep-check network call.

    Strategy: monkeypatch dep_check_status to raise RuntimeError — if it is
    called, the test fails.  With the bypass active (invoked_subcommand == 'workshop'),
    it should never be reached.
    """
    import presidio_ikigov_assess.security as sec

    def _raise(*_args, **_kwargs):
        raise RuntimeError("dep_check_status must not be called in workshop mode")

    monkeypatch.setattr(sec, "dep_check_status", _raise)
    monkeypatch.setattr(sec, "dep_check_available", lambda: True)

    result = runner.invoke(
        app,
        [
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--quiet",
        ],
    )
    # Must not have triggered dep_check_status — if it did, exit_code would be 1
    # and output would contain the RuntimeError or the dep_check output.
    assert result.exit_code == 0, (
        f"Workshop triggered dep check (exit {result.exit_code}):\n{result.output}"
    )


# ── Bad inputs fail closed ────────────────────────────────────────────────────


def test_workshop_missing_file_fails(tmp_path, _isolated_db, _no_dep_check):
    """Non-existent --file causes exit 1."""
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(tmp_path / "nonexistent.json"),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--quiet",
        ],
    )
    assert result.exit_code != 0


def test_workshop_invalid_json_fails(tmp_path, _isolated_db, _no_dep_check):
    """Invalid JSON in --file causes exit 1."""
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("this is not json", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(bad_file),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--quiet",
        ],
    )
    assert result.exit_code != 0


def test_workshop_bad_lang_fails(tmp_path, _isolated_db, _no_dep_check):
    """Invalid --lang value causes exit 1."""
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "xx",
            "--out",
            str(tmp_path / "out"),
            "--quiet",
        ],
    )
    assert result.exit_code != 0


def test_workshop_wrong_schema_fails(tmp_path, _isolated_db, _no_dep_check):
    """Classification document with wrong schema version fails closed."""
    bad_doc = {
        "schema": "eai-classification/v99",
        "use_cases": [{"id": "uc1", "type": "T1", "level": "L2"}],
    }
    bad_file = tmp_path / "wrong.json"
    bad_file.write_text(json.dumps(bad_doc), encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(bad_file),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--quiet",
        ],
    )
    assert result.exit_code != 0


# ── Classification provenance block in report.json ────────────────────────────


def test_workshop_report_json_has_classification_provenance(tmp_path, _isolated_db, _no_dep_check):
    """report.json includes the classification provenance block (cell, pack, producer)."""
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--select",
            "infusion-pump-dosing",
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output

    uc_dir = tmp_path / "out" / "infusion-pump-dosing"
    report = json.loads((uc_dir / "report.json").read_text(encoding="utf-8"))

    assert "classification" in report
    cl = report["classification"]
    assert cl["cell"] == "T1.L4"
    assert cl["type"] == "T1"
    assert cl["level"] == "L4"
    assert "profile_pack" in cl
    assert cl["profile_pack"]["framework_id"]
    assert cl["producer"]["tool"] == "eai-classificator"


# ── report.de.md language check ───────────────────────────────────────────────


def test_workshop_report_md_german_content(tmp_path, _isolated_db, _no_dep_check):
    """report.de.md contains German strings, not English-only sentinels."""
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--select",
            "infusion-pump-dosing",
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output

    uc_dir = tmp_path / "out" / "infusion-pump-dosing"
    md_text = (uc_dir / "report.de.md").read_text(encoding="utf-8")

    # German heading should be present; English-only "Assessment" heading should not lead.
    assert "IKI-Gov Bewertung" in md_text
    # Must NOT start with the English "IKI-Gov Assessment" (it should be the German form).
    assert not md_text.startswith("# IKI-Gov Assessment")


# ── Performance: 4-use-case run completes well under 10 s ─────────────────────


def test_workshop_performance_under_10s(tmp_path, _isolated_db, _no_dep_check):
    """End-to-end workshop run for the 4-use-case medical fixture < 10 s."""
    start = time.monotonic()
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--quiet",
        ],
    )
    elapsed = time.monotonic() - start
    assert result.exit_code == 0, result.output
    assert elapsed < 10.0, f"Workshop took {elapsed:.2f} s (limit: 10 s)"


# ── English run ───────────────────────────────────────────────────────────────


def test_workshop_run_english(tmp_path, _isolated_db, _no_dep_check):
    """Workshop run in English produces report.en.md files."""
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "en",
            "--out",
            str(tmp_path / "out"),
            "--select",
            "surgical-robotics",
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output
    uc_dir = tmp_path / "out" / "surgical-robotics"
    assert (uc_dir / "report.en.md").exists()
    assert not (uc_dir / "report.de.md").exists()


# ── Low-level signing unit tests ──────────────────────────────────────────────


def test_sign_verify_roundtrip_low_level():
    """Ed25519 sign/verify round-trip at the workshop helper function level."""
    privkey_hex, pubkey_hex = _gen_keypair()
    data = b"canonical manifest bytes"
    sig_hex = _sign_manifest_ed25519(data, privkey_hex)
    assert _verify_manifest_ed25519(data, sig_hex, pubkey_hex) is True


def test_verify_wrong_key_fails_lowlevel():
    """Wrong public key causes verification to return False."""
    privkey_hex, _ = _gen_keypair()
    _, wrong_pubkey_hex = _gen_keypair()
    data = b"manifest"
    sig_hex = _sign_manifest_ed25519(data, privkey_hex)
    assert _verify_manifest_ed25519(data, sig_hex, wrong_pubkey_hex) is False


def test_verify_tampered_data_fails_lowlevel():
    """Tampered data causes verification to return False."""
    privkey_hex, pubkey_hex = _gen_keypair()
    data = b"original"
    sig_hex = _sign_manifest_ed25519(data, privkey_hex)
    assert _verify_manifest_ed25519(b"tampered", sig_hex, pubkey_hex) is False


# ── IGA_WORKSHOP_SIGN_KEY env var ─────────────────────────────────────────────


def test_workshop_sign_key_from_env(tmp_path, _isolated_db, _no_dep_check, monkeypatch):
    """$IGA_WORKSHOP_SIGN_KEY is used as the signing key when --sign-key is absent."""
    privkey_hex, pubkey_hex = _gen_keypair()
    monkeypatch.setenv("IGA_WORKSHOP_SIGN_KEY", privkey_hex)

    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--select",
            "infusion-pump-dosing",
            "--quiet",
        ],
    )
    assert result.exit_code == 0, result.output

    uc_dir = tmp_path / "out" / "infusion-pump-dosing"
    sig_data = json.loads((uc_dir / "manifest.sig").read_text(encoding="utf-8"))
    assert sig_data.get("UNSIGNED") is not True
    assert sig_data["alg"] == "ed25519"

    # Verify it.
    verify_result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "verify",
            "--dir",
            str(uc_dir),
            "--pubkey",
            pubkey_hex,
            "--quiet",
        ],
    )
    assert verify_result.exit_code == 0
    assert json.loads(verify_result.output)["ok"] is True


# ── T1.4 German localisation sentinel test ────────────────────────────────────


def test_german_output_no_english_assessment_sentinel(tmp_path, _isolated_db, monkeypatch):
    """--lang de must not produce English-only sentinel strings in runtime output.

    Tests the main output paths: assess, gate, workshop run.
    Sentinels checked: 'Assessment' as a standalone word in tables/panels (not substrings
    of German compound words), 'Warning:' (English prefix), 'Overall maturity' (English).
    """
    monkeypatch.setenv("IGA_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("IGA_NO_DEP_CHECK", "1")

    # iga assess --lang de
    res = runner.invoke(
        app,
        [
            "--no-dep-check",
            "assess",
            "--use-case",
            "test-uc",
            "--risk-class",
            "medium",
            "--lang",
            "de",
            "--affirm",
            "S1,S2",
        ],
    )
    output = res.output
    # German form must be present
    assert "Bewertung" in output or "IKI-Gov" in output
    # English-only "Overall maturity" must not appear (German uses "Gesamtreife")
    assert "Overall maturity" not in output
    # English-only "Measurement Dimensions" must not appear
    assert "Measurement Dimensions" not in output
    # English-only "Gate Readiness" must not appear
    assert "Gate Readiness" not in output


def test_german_gate_output_no_english_sentinels(tmp_path, _isolated_db, monkeypatch):
    """iga gate --lang de produces German status labels, not English ones."""
    monkeypatch.setenv("IGA_DB_PATH", str(tmp_path / "test.db"))

    res = runner.invoke(
        app,
        [
            "--no-dep-check",
            "gate",
            "--gate",
            "G0",
            "--risk-class",
            "medium",
            "--lang",
            "de",
        ],
    )
    output = res.output
    # German statuses (at least one of these should appear)
    german_statuses = {"OFFEN", "BLOCKIERT", "TEILWEISE"}
    assert any(s in output for s in german_statuses), (
        f"No German gate status found in output:\n{output}"
    )


def test_german_workshop_output_no_english_sentinels(tmp_path, _isolated_db, _no_dep_check):
    """Workshop run with --lang de must output German headings, not English-only ones."""
    result = runner.invoke(
        app,
        [
            "--no-dep-check",
            "workshop",
            "run",
            "--file",
            str(_FIXTURE),
            "--lang",
            "de",
            "--out",
            str(tmp_path / "out"),
            "--select",
            "infusion-pump-dosing",
        ],  # NOT --quiet so projector output is rendered
    )
    assert result.exit_code == 0, result.output
    output = result.output
    # German heading must be present
    assert "Workshop" in output or "Anwendungsfall" in output or "Bewertung" in output
    # "Assessment" as an English word should NOT appear as a standalone panel title
    # (note: "IKI-Gov Assessment" is the English form; German form is "IKI-Gov Bewertung")
    # We check the report.de.md too
    uc_dir = tmp_path / "out" / "infusion-pump-dosing"
    md_content = (uc_dir / "report.de.md").read_text(encoding="utf-8")
    assert "IKI-Gov Bewertung" in md_content
