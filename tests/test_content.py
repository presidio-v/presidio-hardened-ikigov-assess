"""Tests for pluggable regulatory-content packs (v0.16.0)."""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from presidio_ikigov_assess.cli import app
from presidio_ikigov_assess.content import (
    ContentError,
    Coverage,
    builtin_packs,
    euaiact_pack,
    evaluate_coverage,
    iso42001_pack,
    load_packs,
    pack_from_dict,
    pack_to_dict,
    validate_pack,
)
from presidio_ikigov_assess.euaiact import evaluate_euaiact
from presidio_ikigov_assess.gates import evaluate_all_gates
from presidio_ikigov_assess.iso import evaluate_iso_coverage

runner = CliRunner()
SAMPLE = frozenset({"S1", "S2", "S3", "D1", "D2", "T1", "T4", "O1", "I1", "I2"})


def test_pack_hash_stable_and_validate():
    p = iso42001_pack()
    assert p.content_hash == iso42001_pack().content_hash
    assert validate_pack(p) is p


def test_builtin_packs_present():
    packs = builtin_packs()
    assert packs["iso42001"].mapping_kind == "item"
    assert packs["euaiact"].mapping_kind == "gate"


def test_pack_roundtrip():
    p = iso42001_pack()
    back = pack_from_dict(pack_to_dict(p), source="builtin")
    assert back.content_hash == p.content_hash


@pytest.mark.parametrize(
    "affirmed", [frozenset(), SAMPLE, frozenset({"S1"}), frozenset({"I1", "I2", "I3", "I4", "I5"})]
)
def test_iso_pack_matches_legacy(affirmed):
    generic = {t: c.status.value for t, c in evaluate_coverage(iso42001_pack(), affirmed).items()}
    legacy = {t: c.status.value for t, c in evaluate_iso_coverage(affirmed).items()}
    assert generic == legacy


@pytest.mark.parametrize("affirmed", [frozenset(), SAMPLE, frozenset({"S1", "S2", "D1"})])
def test_euaiact_pack_matches_legacy(affirmed):
    gate_results = evaluate_all_gates(affirmed, frozenset(), "high", False)
    generic = evaluate_coverage(euaiact_pack(), affirmed, gate_results)
    legacy = evaluate_euaiact(gate_results)
    equiv = {"OPEN": "covered", "PARTIAL": "partial", "BLOCKED": "gap"}
    for art, cov in legacy.items():
        assert generic[art].status.value == equiv[cov.status]


def test_gate_pack_without_gate_results_raises():
    with pytest.raises(ContentError):
        evaluate_coverage(euaiact_pack(), SAMPLE, gate_results=None)


def test_validate_rejects_bad_pack():
    with pytest.raises(ContentError):
        pack_from_dict(
            {
                "framework_id": "x",
                "mapping_kind": "bogus",
                "target_order": ["a"],
                "mapping": {"a": []},
            }
        )
    with pytest.raises(ContentError):
        pack_from_dict(
            {"framework_id": "x", "mapping_kind": "item", "target_order": ["a"], "mapping": {}}
        )


def _ext_pack_json():
    return json.dumps(
        {
            "framework_id": "demo",
            "version": "9",
            "mapping_kind": "item",
            "target_order": ["X"],
            "target_names": {"X": {"en": "Demo target"}},
            "mapping": {"X": ["S1", "S2"]},
        }
    )


def test_external_pack_loaded_and_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    (tmp_path / "demo.json").write_text(_ext_pack_json())
    packs = load_packs()
    assert packs["demo"].source == "external"
    assert evaluate_coverage(packs["demo"], frozenset({"S1", "S2"}))["X"].status is Coverage.COVERED


def test_external_malformed_pack_raises(tmp_path, monkeypatch):
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    (tmp_path / "bad.json").write_text('{"framework_id": "z"}')
    with pytest.raises(ContentError):
        load_packs()


# ── CLI ──────────────────────────────────────────────────────────────────────


def test_cli_content_list(monkeypatch, tmp_path):
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))  # no external packs
    r = runner.invoke(app, ["--no-dep-check", "content-list", "--quiet"])
    assert r.exit_code == 0, r.stdout
    ids = {p["framework_id"] for p in json.loads(r.stdout)}
    assert {"iso42001", "euaiact"} <= ids


def test_cli_framework_gap_iso_and_euaiact(monkeypatch, tmp_path):
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    iso = runner.invoke(
        app,
        [
            "--no-dep-check",
            "framework-gap",
            "--framework",
            "iso42001",
            "--affirm",
            "S1,S2,D1",
            "--quiet",
        ],
    )
    assert iso.exit_code == 0, iso.stdout
    assert json.loads(iso.stdout)["framework_id"] == "iso42001"

    eu = runner.invoke(
        app,
        [
            "--no-dep-check",
            "framework-gap",
            "--framework",
            "euaiact",
            "--risk-class",
            "high",
            "--affirm",
            "S1,S2,D1,D5",
            "--quiet",
        ],
    )
    assert eu.exit_code == 0, eu.stdout
    assert "coverage" in json.loads(eu.stdout)


def test_cli_framework_gap_unknown_exits_1(monkeypatch, tmp_path):
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    r = runner.invoke(app, ["--no-dep-check", "framework-gap", "--framework", "nope", "--quiet"])
    assert r.exit_code == 1


# ── NIST AI RMF (v0.17.0) ────────────────────────────────────────────────────
from presidio_ikigov_assess.checklist import VALID_ITEM_IDS  # noqa: E402
from presidio_ikigov_assess.content import nist_ai_rmf_pack  # noqa: E402


def test_nist_pack_maps_every_item_once():
    pack = nist_ai_rmf_pack()
    assert pack.framework_id == "nist-ai-rmf" and pack.mapping_kind == "item"
    assert pack.target_order == ("GOVERN", "MAP", "MEASURE", "MANAGE")
    all_sources = [s for sources in pack.mapping.values() for s in sources]
    assert set(all_sources) == set(VALID_ITEM_IDS)  # full coverage
    assert len(all_sources) == len(VALID_ITEM_IDS)  # each exactly once


def test_nist_in_builtin_and_load_packs():
    assert "nist-ai-rmf" in builtin_packs()
    assert "nist-ai-rmf" in load_packs()


def test_nist_coverage_runs():
    cov = evaluate_coverage(
        nist_ai_rmf_pack(), frozenset({"S1", "S2", "S3", "D3", "I1", "I2", "I3", "I5"})
    )
    assert cov["GOVERN"].status is Coverage.COVERED  # all GOVERN items affirmed
    assert cov["MEASURE"].status is Coverage.GAP  # none affirmed


def test_cli_framework_gap_nist(monkeypatch, tmp_path):
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    r = runner.invoke(
        app,
        [
            "--no-dep-check",
            "framework-gap",
            "--framework",
            "nist-ai-rmf",
            "--affirm",
            "S1,S2,S3",
            "--quiet",
        ],
    )
    assert r.exit_code == 0, r.stdout
    out = json.loads(r.stdout)
    assert out["framework_id"] == "nist-ai-rmf"
    assert set(out["coverage"]) == {"GOVERN", "MAP", "MEASURE", "MANAGE"}
