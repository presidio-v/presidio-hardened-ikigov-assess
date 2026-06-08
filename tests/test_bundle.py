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
