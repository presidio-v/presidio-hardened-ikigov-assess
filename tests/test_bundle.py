"""Tests for the signed evidence-pack export (v0.15.0)."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from presidio_ikigov_assess.bundle import (
    BundleError,
    build_manifest,
    framework_content_hash,
    verify_bundle,
    write_bundle,
)
from presidio_ikigov_assess.cli import app

runner = CliRunner()
MD = "# report\n"
JS = '{"use_case": "x"}'


def test_framework_content_hash_is_stable():
    assert framework_content_hash() == framework_content_hash()
    assert len(framework_content_hash()) == 64


def test_build_manifest_shape():
    m = build_manifest({"report.md": MD, "report.json": JS}, use_case="uc", risk_class="high")
    assert m["schema"] == "presidio-hardened/evidence-pack@1"
    assert set(m["artifacts"]) == {"report.md", "report.json"}
    assert len(m["artifacts"]["report.md"]["sha256"]) == 64
    assert m["framework_content_hash"] == framework_content_hash()


def test_write_and_verify_dir(tmp_path):
    out = write_bundle(
        tmp_path / "pack", report_md=MD, report_json=JS, use_case="uc", risk_class="high"
    )
    assert (out / "manifest.json").exists()
    report = verify_bundle(out)
    assert report["ok"] is True
    assert report["artifacts"] == {"report.md": True, "report.json": True}
    assert report["signature"] is None


def test_tamper_detected(tmp_path):
    out = write_bundle(
        tmp_path / "pack", report_md=MD, report_json=JS, use_case="uc", risk_class="low"
    )
    (out / "report.md").write_text("tampered", encoding="utf-8")
    report = verify_bundle(out)
    assert report["ok"] is False
    assert report["artifacts"]["report.md"] is False


def test_signed_manifest(tmp_path):
    out = write_bundle(
        tmp_path / "pack",
        report_md=MD,
        report_json=JS,
        use_case="uc",
        risk_class="high",
        sign_key="seal-key",
    )
    assert (out / "manifest.sig").exists()
    assert verify_bundle(out, sign_key="seal-key")["signature"] is True
    bad = verify_bundle(out, sign_key="wrong")
    assert bad["signature"] is False and bad["ok"] is False


def test_zip_roundtrip(tmp_path):
    out = write_bundle(
        tmp_path / "pack.zip",
        report_md=MD,
        report_json=JS,
        use_case="uc",
        risk_class="high",
        as_zip=True,
    )
    assert out.suffix == ".zip"
    assert verify_bundle(out)["ok"] is True


def test_verify_bad_bundle_raises(tmp_path):
    (tmp_path / "empty").mkdir()
    with pytest.raises(BundleError):
        verify_bundle(tmp_path / "empty")  # no manifest.json


# ── CLI ──────────────────────────────────────────────────────────────────────


def test_cli_export_and_verify(tmp_path):
    pack = tmp_path / "pack"
    r = runner.invoke(
        app,
        [
            "--no-dep-check",
            "export",
            "--use-case",
            "fraud-scoring",
            "--risk-class",
            "high",
            "--affirm",
            "S1,S2,D1",
            "--bundle",
            str(pack),
            "--quiet",
        ],
    )
    assert r.exit_code == 0, r.stdout
    assert json.loads(r.stdout)["bundle"] == str(pack)

    v = runner.invoke(app, ["--no-dep-check", "verify-bundle", "--bundle", str(pack), "--quiet"])
    assert v.exit_code == 0
    assert json.loads(v.stdout)["ok"] is True


def test_cli_verify_detects_tamper(tmp_path):
    pack = tmp_path / "pack"
    runner.invoke(
        app,
        [
            "--no-dep-check",
            "export",
            "--use-case",
            "uc",
            "--affirm",
            "S1",
            "--bundle",
            str(pack),
            "--quiet",
        ],
    )
    (pack / "report.json").write_text("tampered", encoding="utf-8")
    v = runner.invoke(app, ["--no-dep-check", "verify-bundle", "--bundle", str(pack), "--quiet"])
    assert v.exit_code == 1
    assert json.loads(v.stdout)["ok"] is False


def _export_signed(pack, extra_args, env=None):
    return runner.invoke(
        app,
        ["--no-dep-check", "export", "--use-case", "uc", "--affirm", "S1", "--bundle", str(pack)]
        + extra_args
        + ["--quiet"],
        env=env,
    )


def test_sign_key_file_keeps_key_off_argv(tmp_path):
    # Seal with a key from a file, verify with the same file — round-trips without the
    # secret ever appearing on the command line.
    pack = tmp_path / "pack"
    keyfile = tmp_path / "seal.key"
    keyfile.write_text("file-seal-key\n", encoding="utf-8")  # trailing newline is stripped
    r = _export_signed(pack, ["--sign-key-file", str(keyfile)])
    assert r.exit_code == 0, r.stdout
    assert json.loads(r.stdout)["signed"] is True

    v = runner.invoke(
        app,
        [
            "--no-dep-check",
            "verify-bundle",
            "--bundle",
            str(pack),
            "--sign-key-file",
            str(keyfile),
            "--quiet",
        ],
    )
    assert json.loads(v.stdout)["signature"] is True
    # The file key matches the inline form of the same value.
    inline = runner.invoke(
        app,
        [
            "--no-dep-check",
            "verify-bundle",
            "--bundle",
            str(pack),
            "--sign-key",
            "file-seal-key",
            "--quiet",
        ],
    )
    assert json.loads(inline.stdout)["signature"] is True


def test_sign_key_from_env(tmp_path):
    pack = tmp_path / "pack"
    r = _export_signed(pack, [], env={"IGA_SIGN_KEY": "env-seal-key"})
    assert json.loads(r.stdout)["signed"] is True
    v = runner.invoke(
        app,
        ["--no-dep-check", "verify-bundle", "--bundle", str(pack), "--quiet"],
        env={"IGA_SIGN_KEY": "env-seal-key"},
    )
    assert json.loads(v.stdout)["signature"] is True


def test_empty_env_sign_key_is_unset(tmp_path):
    # An empty IGA_SIGN_KEY must not seal the bundle (treated as absent).
    pack = tmp_path / "pack"
    r = _export_signed(pack, [], env={"IGA_SIGN_KEY": ""})
    assert json.loads(r.stdout)["signed"] is False


def test_sign_key_file_precedes_inline_and_env(tmp_path):
    # File wins over inline and env; the resulting bundle verifies only with the file key.
    pack = tmp_path / "pack"
    keyfile = tmp_path / "seal.key"
    keyfile.write_text("the-file-key", encoding="utf-8")
    r = _export_signed(
        pack,
        ["--sign-key-file", str(keyfile), "--sign-key", "ignored"],
        env={"IGA_SIGN_KEY": "also-ignored"},
    )
    assert r.exit_code == 0, r.stdout
    v = runner.invoke(
        app,
        [
            "--no-dep-check",
            "verify-bundle",
            "--bundle",
            str(pack),
            "--sign-key",
            "the-file-key",
            "--quiet",
        ],
    )
    assert json.loads(v.stdout)["signature"] is True
