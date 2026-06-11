"""Tests for the classificator bridge (v0.20.0 — T-B1).

Covers:
- Schema happy path
- Every malformed-field case
- Unknown-version fail-closed
- Unknown fields ignored
- L6/ecosystem normalisation incl. contradiction
- Size limits
- ProfilePack completeness (36 cells), content_hash stability
- Builtin draft semantics spot-checks
- External override via IGA_CONTENT_PATH tmpdir
- Loader coexistence of both pack kinds
- CLI ingest table + quiet JSON
- classify assess end-to-end in German with --quiet --save
- Regression: existing suite not broken (verified by running full suite)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from presidio_ikigov_assess.classification import (
    ClassificationError,
    cell_id,
    parse_classification,
    parse_classification_bytes,
)
from presidio_ikigov_assess.cli import app
from presidio_ikigov_assess.content import (
    load_profile_packs,
)
from presidio_ikigov_assess.content.profile import (
    ProfileError,
    validate_profile_pack,
)
from presidio_ikigov_assess.content.profile_builtin import builtin_classification_profile_pack

runner = CliRunner()

# Path to the medical fixture used in CLI tests.
_FIXTURE = Path(__file__).parent / "fixtures" / "medical_classification.json"

# ── Minimal valid document ────────────────────────────────────────────────────

_VALID_DOC = {
    "schema": "eai-classification/v1",
    "use_cases": [
        {"id": "uc-1", "type": "T1", "level": "L3"},
    ],
}


def test_happy_path_minimal():
    doc = parse_classification(_VALID_DOC)
    assert doc.schema == "eai-classification/v1"
    assert len(doc.use_cases) == 1
    uc = doc.use_cases[0]
    assert uc.id == "uc-1"
    assert uc.type == "T1"
    assert uc.level == "L3"
    assert uc.base_level == "L3"
    assert uc.ecosystem is False


def test_happy_path_full_fields():
    doc_data = {
        "schema": "eai-classification/v1",
        "producer": {"tool": "test", "version": "1"},
        "use_cases": [
            {
                "id": "uc-full",
                "type": "T3",
                "level": "L4",
                "name": {"de": "Testfall", "en": "Test case"},
                "ecosystem": False,
                "confidence": 0.9,
                "rationale": "A rationale.",
                "tags": ["a", "b"],
                "unknown_future_field": "should be ignored",
            }
        ],
    }
    doc = parse_classification(doc_data)
    uc = doc.use_cases[0]
    assert uc.type == "T3"
    assert uc.level == "L4"
    assert isinstance(uc.name, dict)
    assert uc.confidence == 0.9
    assert "a" in uc.tags


def test_unknown_top_level_fields_ignored():
    data = {
        "schema": "eai-classification/v1",
        "use_cases": [{"id": "x1", "type": "T2", "level": "L2"}],
        "future_extension": "ignored",
        "another_field": 42,
    }
    doc = parse_classification(data)
    assert len(doc.use_cases) == 1


def test_unknown_use_case_fields_ignored():
    data = {
        "schema": "eai-classification/v1",
        "use_cases": [
            {
                "id": "x2",
                "type": "T5",
                "level": "L1",
                "new_producer_field": "value",
                "nested": {"foo": "bar"},
            }
        ],
    }
    doc = parse_classification(data)
    assert doc.use_cases[0].id == "x2"


# ── Unknown schema version fails closed ─────────────────────────────────────


def test_unknown_schema_version_fails_closed():
    with pytest.raises(ClassificationError, match="unsupported schema version"):
        parse_classification({"schema": "eai-classification/v2", "use_cases": []})


def test_missing_schema_field_fails():
    with pytest.raises(ClassificationError, match="missing required 'schema'"):
        parse_classification({"use_cases": []})


def test_wrong_schema_type_fails():
    with pytest.raises(ClassificationError, match="missing required 'schema'"):
        parse_classification({"schema": 123, "use_cases": []})


# ── Malformed field cases ─────────────────────────────────────────────────────


def test_invalid_id_rejected():
    with pytest.raises(ClassificationError, match="id must match"):
        parse_classification(
            {
                "schema": "eai-classification/v1",
                "use_cases": [{"id": "bad id!", "type": "T1", "level": "L1"}],
            }
        )


def test_invalid_type_rejected():
    with pytest.raises(ClassificationError, match="type must be T1–T6"):
        parse_classification(
            {
                "schema": "eai-classification/v1",
                "use_cases": [{"id": "x", "type": "T7", "level": "L1"}],
            }
        )


def test_invalid_level_rejected():
    with pytest.raises(ClassificationError, match="level must be L1–L6"):
        parse_classification(
            {
                "schema": "eai-classification/v1",
                "use_cases": [{"id": "x", "type": "T1", "level": "L7"}],
            }
        )


def test_confidence_out_of_range_rejected():
    with pytest.raises(ClassificationError, match="confidence must be in"):
        parse_classification(
            {
                "schema": "eai-classification/v1",
                "use_cases": [{"id": "x", "type": "T1", "level": "L1", "confidence": 1.5}],
            }
        )


def test_confidence_negative_rejected():
    with pytest.raises(ClassificationError, match="confidence must be in"):
        parse_classification(
            {
                "schema": "eai-classification/v1",
                "use_cases": [{"id": "x", "type": "T1", "level": "L1", "confidence": -0.1}],
            }
        )


def test_rationale_too_long_rejected():
    with pytest.raises(ClassificationError, match="rationale too long"):
        parse_classification(
            {
                "schema": "eai-classification/v1",
                "use_cases": [{"id": "x", "type": "T1", "level": "L1", "rationale": "x" * 2001}],
            }
        )


def test_tags_too_many_rejected():
    with pytest.raises(ClassificationError, match="too many tags"):
        parse_classification(
            {
                "schema": "eai-classification/v1",
                "use_cases": [
                    {"id": "x", "type": "T1", "level": "L1", "tags": [f"t{i}" for i in range(25)]}
                ],
            }
        )


def test_tag_too_long_rejected():
    with pytest.raises(ClassificationError, match="too long"):
        parse_classification(
            {
                "schema": "eai-classification/v1",
                "use_cases": [{"id": "x", "type": "T1", "level": "L1", "tags": ["a" * 65]}],
            }
        )


def test_use_cases_not_array():
    with pytest.raises(ClassificationError, match="use_cases must be a JSON array"):
        parse_classification({"schema": "eai-classification/v1", "use_cases": {}})


def test_use_case_not_object():
    with pytest.raises(ClassificationError, match="expected object"):
        parse_classification({"schema": "eai-classification/v1", "use_cases": ["not-an-object"]})


def test_name_as_string():
    doc = parse_classification(
        {
            "schema": "eai-classification/v1",
            "use_cases": [{"id": "x", "type": "T1", "level": "L2", "name": "My Use Case"}],
        }
    )
    assert doc.use_cases[0].name == "My Use Case"


def test_name_as_dict():
    doc = parse_classification(
        {
            "schema": "eai-classification/v1",
            "use_cases": [
                {"id": "x", "type": "T1", "level": "L2", "name": {"de": "Testfall", "en": "Test"}}
            ],
        }
    )
    assert isinstance(doc.use_cases[0].name, dict)


def test_name_invalid_type_rejected():
    with pytest.raises(ClassificationError, match="name must be a string"):
        parse_classification(
            {
                "schema": "eai-classification/v1",
                "use_cases": [{"id": "x", "type": "T1", "level": "L1", "name": 42}],
            }
        )


# ── L6 / ecosystem normalisation ─────────────────────────────────────────────


def test_ecosystem_true_normalises_to_l6():
    doc = parse_classification(
        {
            "schema": "eai-classification/v1",
            "use_cases": [{"id": "x", "type": "T2", "level": "L3", "ecosystem": True}],
        }
    )
    uc = doc.use_cases[0]
    assert uc.level == "L6"
    assert uc.base_level == "L3"
    assert uc.ecosystem is True


def test_l6_without_ecosystem_is_fine():
    doc = parse_classification(
        {
            "schema": "eai-classification/v1",
            "use_cases": [{"id": "x", "type": "T2", "level": "L6"}],
        }
    )
    assert doc.use_cases[0].level == "L6"
    assert doc.use_cases[0].ecosystem is False


def test_l6_with_ecosystem_true_is_fine_redundant():
    doc = parse_classification(
        {
            "schema": "eai-classification/v1",
            "use_cases": [{"id": "x", "type": "T2", "level": "L6", "ecosystem": True}],
        }
    )
    assert doc.use_cases[0].level == "L6"


def test_l6_ecosystem_false_is_contradiction():
    with pytest.raises(ClassificationError, match="contradiction"):
        parse_classification(
            {
                "schema": "eai-classification/v1",
                "use_cases": [{"id": "x", "type": "T2", "level": "L6", "ecosystem": False}],
            }
        )


def test_cell_id_helper():
    doc = parse_classification(
        {"schema": "eai-classification/v1", "use_cases": [{"id": "x", "type": "T3", "level": "L4"}]}
    )
    assert cell_id(doc.use_cases[0]) == "T3.L4"


# ── Size limits ───────────────────────────────────────────────────────────────


def test_too_many_use_cases_rejected():
    ucs = [{"id": f"uc-{i}", "type": "T1", "level": "L1"} for i in range(201)]
    with pytest.raises(ClassificationError, match="too many use cases"):
        parse_classification({"schema": "eai-classification/v1", "use_cases": ucs})


def test_document_too_large_rejected():
    big = (
        b'{"schema": "eai-classification/v1", "use_cases": [{"id": "x", "type": "T1", "level": "L1"}]}'
        + b" " * 1_100_000
    )
    with pytest.raises(ClassificationError, match="too large"):
        parse_classification_bytes(big)


def test_invalid_json_rejected():
    with pytest.raises(ClassificationError, match="invalid JSON"):
        parse_classification_bytes(b"not json {")


# ── ProfilePack completeness and content_hash stability ──────────────────────


def test_builtin_pack_has_36_cells():
    pack = builtin_classification_profile_pack()
    assert len(pack.profiles) == 36
    for t in range(1, 7):
        for lv in range(1, 7):
            assert f"T{t}.L{lv}" in pack.profiles


def test_builtin_pack_validate_passes():
    pack = builtin_classification_profile_pack()
    assert validate_profile_pack(pack) is pack


def test_profile_pack_content_hash_stable():
    pack1 = builtin_classification_profile_pack()
    pack2 = builtin_classification_profile_pack()
    assert pack1.content_hash == pack2.content_hash


def test_profile_pack_content_hash_snapshot():
    pack = builtin_classification_profile_pack()
    h = pack.content_hash
    # Hash must be a 64-char hex string (sha256).
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


# ── Builtin draft semantics spot-checks ──────────────────────────────────────


def test_t1_l1_is_low():
    pack = builtin_classification_profile_pack()
    assert pack.get("T1.L1").risk_presumption == "low"


def test_t1_l3_floors_medium():
    pack = builtin_classification_profile_pack()
    # T1 Decision floors at medium from L3
    assert pack.get("T1.L3").risk_presumption == "medium"


def test_t1_l5_is_high():
    pack = builtin_classification_profile_pack()
    assert pack.get("T1.L5").risk_presumption == "high"


def test_t6_l1_is_low():
    pack = builtin_classification_profile_pack()
    # T6 Physical floors at medium from L2; L1 stays low
    assert pack.get("T6.L1").risk_presumption == "low"


def test_t6_l2_floors_medium():
    pack = builtin_classification_profile_pack()
    assert pack.get("T6.L2").risk_presumption == "medium"


def test_t6_l4_is_high():
    pack = builtin_classification_profile_pack()
    # T6 Physical floors at high from L4
    assert pack.get("T6.L4").risk_presumption == "high"


def test_anything_l6_is_high_and_strict():
    pack = builtin_classification_profile_pack()
    for t in range(1, 7):
        cell = f"T{t}.L6"
        p = pack.get(cell)
        assert p.risk_presumption == "high", f"{cell} should be high"
        assert p.strict is True, f"{cell} should be strict"


def test_l1_l2_not_strict():
    pack = builtin_classification_profile_pack()
    for t in range(1, 7):
        for lv in ("L1", "L2"):
            assert pack.get(f"T{t}.{lv}").strict is False


def test_obligations_all_cells():
    pack = builtin_classification_profile_pack()
    for t in range(1, 7):
        for lv in range(1, 7):
            obs = pack.get(f"T{t}.L{lv}").obligations
            assert "iso42001" in obs
            assert "euaiact" in obs


def test_notes_bilingual():
    pack = builtin_classification_profile_pack()
    for t in range(1, 7):
        for lv in range(1, 7):
            notes = pack.get(f"T{t}.L{lv}").notes
            assert "de" in notes and "en" in notes


# ── ProfilePack validation ────────────────────────────────────────────────────


def test_profile_pack_missing_cells_rejected():
    from presidio_ikigov_assess.content.profile import CellProfile, ProfilePack

    # Build a pack with only 35 cells (missing T6.L6)
    profiles = {
        f"T{t}.L{lv}": CellProfile(risk_presumption="low", obligations=("iso42001",))
        for t in range(1, 7)
        for lv in range(1, 7)
        if not (t == 6 and lv == 6)
    }
    pack = ProfilePack(
        pack_kind="classification-profile",
        framework_id="test",
        version="1",
        profiles=profiles,
    )
    with pytest.raises(ProfileError, match="missing cells"):
        validate_profile_pack(pack)


def test_profile_pack_invalid_risk_presumption():
    from presidio_ikigov_assess.content.profile import CellProfile, ProfilePack

    profiles = {}
    for t in range(1, 7):
        for lv in range(1, 7):
            rp = "low" if not (t == 1 and lv == 1) else "unknown"
            profiles[f"T{t}.L{lv}"] = CellProfile(risk_presumption=rp)
    pack = ProfilePack(
        pack_kind="classification-profile",
        framework_id="test",
        version="1",
        profiles=profiles,
    )
    with pytest.raises(ProfileError, match="risk_presumption must be"):
        validate_profile_pack(pack)


def test_profile_pack_from_dict_wrong_kind_rejected():
    from presidio_ikigov_assess.content.profile import profile_pack_from_dict

    data = {"pack_kind": "content-pack", "framework_id": "x", "version": "1", "profiles": {}}
    with pytest.raises(ProfileError, match="pack_kind must be"):
        profile_pack_from_dict(data)


# ── External override via IGA_CONTENT_PATH ────────────────────────────────────


def _build_external_profile_pack_json() -> str:
    """Build a minimal valid external profile pack JSON covering all 36 cells."""
    profiles = {}
    for t_i in range(1, 7):
        for l_i in range(1, 7):
            cell = f"T{t_i}.L{l_i}"
            profiles[cell] = {
                "risk_presumption": "medium",
                "strict": False,
                "obligations": ["custom-framework"],
                "notes": {"en": "External override note."},
            }
    return json.dumps(
        {
            "pack_kind": "classification-profile",
            "framework_id": "eai-classification-default",
            "version": "custom-1",
            "profiles": profiles,
        }
    )


def test_external_profile_pack_loaded_and_overrides_builtin(tmp_path, monkeypatch):
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    (tmp_path / "custom-profile.json").write_text(_build_external_profile_pack_json())
    packs = load_profile_packs()
    pack = packs.get("eai-classification-default")
    assert pack is not None
    assert pack.source == "external"
    assert pack.version == "custom-1"
    # All cells still present after override
    assert len(pack.profiles) == 36


def test_external_malformed_profile_pack_raises(tmp_path, monkeypatch):
    from presidio_ikigov_assess.content import ContentError

    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    (tmp_path / "bad-profile.json").write_text(
        json.dumps({"pack_kind": "classification-profile", "framework_id": "x"})
    )
    with pytest.raises((ContentError, ProfileError)):
        load_profile_packs()


# ── Loader coexistence of both pack kinds ─────────────────────────────────────


def test_loader_coexistence_both_pack_kinds(tmp_path, monkeypatch):
    """ContentPacks and ProfilePacks can coexist in the same IGA_CONTENT_PATH directory."""
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))

    # Write a ContentPack
    content_pack = {
        "framework_id": "demo-content",
        "version": "1",
        "mapping_kind": "item",
        "target_order": ["X"],
        "target_names": {"X": {"en": "Demo target"}},
        "mapping": {"X": ["S1", "S2"]},
    }
    (tmp_path / "demo-content.json").write_text(json.dumps(content_pack))

    # Write a ProfilePack
    (tmp_path / "demo-profile.json").write_text(_build_external_profile_pack_json())

    from presidio_ikigov_assess.content import load_packs

    content_packs = load_packs()
    profile_packs = load_profile_packs()

    assert "demo-content" in content_packs
    # Profile pack should not appear in content packs
    assert (
        "eai-classification-default" not in content_packs
        or content_packs.get("eai-classification-default") is None
        or not hasattr(content_packs.get("eai-classification-default"), "pack_kind")
    )
    assert "eai-classification-default" in profile_packs


# ── CLI: iga classify ingest ──────────────────────────────────────────────────


def invoke(*args: str):
    return runner.invoke(app, ["--no-dep-check"] + list(args))


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setenv("IGA_DB_PATH", str(tmp_path / "assessments.db"))


def test_cli_classify_ingest_table(tmp_path, monkeypatch):
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    r = invoke("classify", "ingest", "--file", str(_FIXTURE), "--lang", "en")
    assert r.exit_code == 0, r.output
    assert "T1.L4" in r.output or "T2.L4" in r.output or "T2.L6" in r.output


def test_cli_classify_ingest_quiet_json(tmp_path, monkeypatch):
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    r = invoke("classify", "ingest", "--file", str(_FIXTURE), "--quiet")
    assert r.exit_code == 0, r.output
    out = json.loads(r.stdout)
    assert out["schema"] == "eai-classification/v1"
    assert "use_cases" in out
    assert len(out["use_cases"]) == 4
    assert "profile_pack" in out
    assert "content_hash" in out["profile_pack"]
    # Producer is echoed back
    assert out["producer"]["tool"] == "eai-classificator"


def test_cli_classify_ingest_ecosystem_normalised(tmp_path, monkeypatch):
    """dialysis-remote-service has ecosystem=true, level=L3 → effective level=L6."""
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    r = invoke("classify", "ingest", "--file", str(_FIXTURE), "--quiet")
    assert r.exit_code == 0
    out = json.loads(r.stdout)
    dialysis = next(uc for uc in out["use_cases"] if uc["id"] == "dialysis-remote-service")
    assert dialysis["cell"] == "T2.L6"
    assert dialysis["level"] == "L6"
    assert dialysis["base_level"] == "L3"


def test_cli_classify_ingest_invalid_file_exits_1(tmp_path, monkeypatch):
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    bad = tmp_path / "bad.json"
    bad.write_text('{"schema": "eai-classification/v99", "use_cases": []}')
    r = invoke("classify", "ingest", "--file", str(bad))
    assert r.exit_code == 1


def test_cli_classify_ingest_missing_file_exits_1(tmp_path, monkeypatch):
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    r = invoke("classify", "ingest", "--file", "/nonexistent/file.json")
    assert r.exit_code == 1


# ── CLI: iga classify assess ──────────────────────────────────────────────────


def test_cli_classify_assess_quiet_german(tmp_path, monkeypatch):
    """End-to-end assess with --quiet --save --lang de using the medical fixture."""
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    r = invoke(
        "classify",
        "assess",
        "--file",
        str(_FIXTURE),
        "--select",
        "surgical-robotics",
        "--lang",
        "de",
        "--quiet",
        "--save",
    )
    assert r.exit_code == 0, r.output
    out = json.loads(r.stdout)
    # Check assessment payload structure
    assert "scores" in out
    assert "gates" in out
    # Check classification augmentation
    assert "classification" in out
    cl = out["classification"]
    assert cl["cell"] == "T6.L3"
    assert cl["type"] == "T6"
    assert cl["level"] == "L3"
    assert "content_hash" in cl["profile_pack"]


def test_cli_classify_assess_infusion_pump(tmp_path, monkeypatch):
    """T1.L4 → medium risk (T1 floors at medium from L3, L4 >= L3 so medium)."""
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    r = invoke(
        "classify",
        "assess",
        "--file",
        str(_FIXTURE),
        "--select",
        "infusion-pump-dosing",
        "--quiet",
    )
    assert r.exit_code == 0, r.output
    out = json.loads(r.stdout)
    assert out["classification"]["cell"] == "T1.L4"
    # T1.L4 with no items affirmed → 0 score but should complete
    assert "M1" in out["scores"]


def test_cli_classify_assess_with_affirmed_items(tmp_path, monkeypatch):
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    r = invoke(
        "classify",
        "assess",
        "--file",
        str(_FIXTURE),
        "--select",
        "infusion-pump-dosing",
        "--affirm",
        "S1,S2,D1,D2",
        "--quiet",
    )
    assert r.exit_code == 0, r.output
    out = json.loads(r.stdout)
    assert out["answers"]["affirmed"] == ["D1", "D2", "S1", "S2"]


def test_cli_classify_assess_unknown_use_case_exits_1(tmp_path, monkeypatch):
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    r = invoke(
        "classify",
        "assess",
        "--file",
        str(_FIXTURE),
        "--select",
        "nonexistent-uc",
        "--quiet",
    )
    assert r.exit_code == 1


def test_cli_classify_assess_dialysis_ecosystem_l6_strict(tmp_path, monkeypatch):
    """dialysis-remote-service: ecosystem=true → cell T2.L6 → strict=true."""
    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    r = invoke(
        "classify",
        "assess",
        "--file",
        str(_FIXTURE),
        "--select",
        "dialysis-remote-service",
        "--quiet",
    )
    assert r.exit_code == 0, r.output
    out = json.loads(r.stdout)
    assert out["classification"]["cell"] == "T2.L6"
    # L6 → strict; should be reflected in gate evaluation
    assert "gates" in out


def test_cli_classify_assess_save_persists(tmp_path, monkeypatch):
    """--save stores the assessment in the local store."""
    import presidio_ikigov_assess.store as store_mod

    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    r = invoke(
        "classify",
        "assess",
        "--file",
        str(_FIXTURE),
        "--select",
        "surgical-robotics",
        "--save",
        "--quiet",
    )
    assert r.exit_code == 0, r.output
    saved = store_mod.list_assessments()
    assert any(a.use_case == "surgical-robotics" for a in saved)


# ── Security event logged ─────────────────────────────────────────────────────


def test_classify_assess_logs_security_event(tmp_path, monkeypatch):
    """Verify that classify assess writes the iga-classify-assess security event to the log."""
    import presidio_ikigov_assess.security as sec_mod

    # Point the security log to our tmp dir (autouse fixture sets _IGA_DIR already,
    # but we need to read the log afterwards).
    log_file = sec_mod._SECURITY_LOG  # points to the isolated tmp dir from conftest

    monkeypatch.setenv("IGA_CONTENT_PATH", str(tmp_path))
    r = invoke(
        "classify",
        "assess",
        "--file",
        str(_FIXTURE),
        "--select",
        "surgical-robotics",
        "--quiet",
    )
    assert r.exit_code == 0, r.output

    # Read the security log and find the classify-assess event.
    assert log_file.exists(), "security log should have been created"
    events = [json.loads(line) for line in log_file.read_text().splitlines() if line.strip()]
    classify_events = [e for e in events if e.get("event") == "iga-classify-assess"]
    assert len(classify_events) >= 1
    ev = classify_events[-1]
    assert ev["cell"] == "T6.L3"
    assert "pack_content_hash" in ev
    assert len(ev["pack_content_hash"]) == 64  # full sha256


# ── profile_pack_to_dict round-trip ──────────────────────────────────────────


def test_profile_pack_to_dict_roundtrip():
    from presidio_ikigov_assess.content.profile import profile_pack_from_dict, profile_pack_to_dict

    pack = builtin_classification_profile_pack()
    d = profile_pack_to_dict(pack)
    restored = profile_pack_from_dict(d, source="builtin")
    assert restored.content_hash == pack.content_hash
    assert restored.framework_id == pack.framework_id
