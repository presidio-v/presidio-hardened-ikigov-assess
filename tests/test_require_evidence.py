"""``--require-evidence`` is fail-closed everywhere (v0.26.0 S-1).

Before v0.26.0 the flag only filtered ``--evidence`` inputs: a bare ``--affirm``
(or wizard answer) still counted, so ``--require-evidence --trust '{}'`` over all 25
items reported 100 % and every gate OPEN. Without ``--evidence`` the flag was not
read at all. These tests pin the corrected contract:

- the two reported commands score 0 % with every gate BLOCKED;
- an empty trust store, a signer not in the store, a tampered signature and a wrong
  key each affirm nothing;
- mixed ``--affirm`` + ``--evidence``: only the evidenced items count, the rest are
  ``asserted`` and shown as such;
- ``gate``, ``report`` (both formats), ``export`` (manifest + report.json), the three
  gap commands, ``certify`` and the MCP tool apply the same policy and mark items;
- without the flag nothing changes (scores, gates, exit codes).
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from presidio_ikigov_assess import mcp_server
from presidio_ikigov_assess.checklist import VALID_ITEM_IDS
from presidio_ikigov_assess.cli import app
from presidio_ikigov_assess.evidence import (
    EVIDENCE_VERIFIED,
    SELF,
    EvidenceRef,
    evidence_block,
    expected_signature,
    resolve_affirmations,
)

runner = CliRunner()

ALL = ",".join(sorted(VALID_ITEM_IDS))
CH = "abc123def456"
SIGNER = "presidio-hardened-ai"
KEY = "shared-key"


def _ch(item_id: str) -> str:
    """One content hash per item: a ref reused across items verifies for none (audit C-1)."""
    return hashlib.sha256(f"{CH}:{item_id}".encode()).hexdigest()[:24]


def _ref(item_id: str, *, signer: str = SIGNER, signature: str | None = None) -> dict:
    return {
        "item_id": item_id,
        "source": "presidio-hardened-ai",
        "source_version": "0.30.0",
        "ledger_ref": "pai-ledger:seq/1",
        "content_hash": _ch(item_id),
        "signer": signer,
        "signature": signature or expected_signature(_ch(item_id), signer, KEY),
        "claimed_at": "2026-06-12T00:00:00+00:00",
    }


def _files(tmp_path: Path, refs: list[dict] | None, trust: dict | None) -> list[str]:
    args: list[str] = []
    if refs is not None:
        ev = tmp_path / "evidence.json"
        ev.write_text(json.dumps({"schema": "presidio-hardened/evidence-ref@1", "evidence": refs}))
        args += ["--evidence", str(ev)]
    if trust is not None:
        tr = tmp_path / "trust.json"
        tr.write_text(json.dumps(trust))
        args += ["--trust", str(tr)]
    return args


def _assess(*args: str) -> dict:
    r = runner.invoke(app, ["--no-dep-check", "assess", "-u", "ics", "-r", "high", *args, "-q"])
    assert r.exit_code == 0, r.output
    return json.loads(r.stdout)


def _statuses(payload: dict) -> set[str]:
    return {g["status"] for g in payload["gates"].values()}


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


# ── the reported commands ─────────────────────────────────────────────────────


def test_reported_command_with_empty_trust_store_scores_zero_and_blocks(tmp_path):
    payload = _assess("--affirm", ALL, "--require-evidence", *_files(tmp_path, None, {}))
    assert payload["overall"] == 0.0
    assert _statuses(payload) == {"BLOCKED"}
    assert payload["answers"]["affirmed"] == []
    assert set(payload["answers"]["asserted"]) == VALID_ITEM_IDS
    cov = payload["evidence_coverage"]
    assert cov["require_evidence"] is True
    assert cov["asserted_not_counted"] == 25
    assert cov["affirmed_total"] == 0


def test_reported_command_without_trust_scores_zero_and_blocks():
    payload = _assess("--affirm", ALL, "--require-evidence")
    assert payload["overall"] == 0.0 and _statuses(payload) == {"BLOCKED"}
    assert payload["answers"]["affirmed"] == []
    assert len(payload["answers"]["asserted"]) == 25


def test_asserted_items_are_named_on_stderr():
    r = runner.invoke(
        app,
        ["--no-dep-check", "assess", "--affirm", "S1,S2", "--require-evidence", "-q"],
    )
    assert r.exit_code == 0
    assert "--require-evidence" in r.output and "S1, S2" in r.output


def test_without_the_flag_nothing_changes():
    payload = _assess("--affirm", ALL)
    assert payload["overall"] == 100.0 and _statuses(payload) == {"OPEN"}
    assert payload["answers"]["asserted"] == []
    # Every affirmed row now says how it was substantiated, even without evidence.
    assert all(i["provenance"] == SELF for i in payload["answers"]["items"])
    assert payload["evidence_coverage"]["require_evidence"] is False


# ── the --evidence path stays fail-closed ─────────────────────────────────────


@pytest.mark.parametrize(
    "refs, trust",
    [
        ([_ref("D1")], {}),  # empty trust store
        ([_ref("D1", signer="unknown-signer")], {SIGNER: KEY}),  # signer not in store
        ([_ref("D1", signature="00" * 32)], {SIGNER: KEY}),  # tampered signature
        ([_ref("D1")], {SIGNER: "rotated-wrong-key"}),  # wrong / unknown key
        ([_ref("D1")], None),  # no trust store at all
    ],
)
def test_unverifiable_evidence_affirms_nothing_and_bare_affirm_does_not_rescue(
    tmp_path, refs, trust
):
    payload = _assess("--affirm", "D1,S1", "--require-evidence", *_files(tmp_path, refs, trust))
    assert payload["answers"]["affirmed"] == []
    assert payload["answers"]["asserted"] == ["D1", "S1"]
    assert payload["overall"] == 0.0


def test_malformed_evidence_file_exits_one(tmp_path):
    bad = tmp_path / "evidence.json"
    bad.write_text('{"schema":"presidio-hardened/evidence-ref@1","evidence":[{"item_id":"D1"}]')
    r = runner.invoke(
        app,
        ["--no-dep-check", "assess", "--affirm", ALL, "--require-evidence", "--evidence", str(bad)],
    )
    assert r.exit_code == 1


def test_mixed_affirm_and_evidence_counts_only_the_evidenced_items(tmp_path):
    payload = _assess(
        "--affirm",
        "S1,S2,D1",
        "--require-evidence",
        *_files(tmp_path, [_ref("D1"), _ref("O5")], {SIGNER: KEY}),
    )
    assert payload["answers"]["affirmed"] == ["D1", "O5"]
    assert payload["answers"]["asserted"] == ["S1", "S2"]
    by_id = {i["id"]: i for i in payload["answers"]["items"]}
    assert by_id["D1"]["status"] == "affirmed" and by_id["D1"]["provenance"] == EVIDENCE_VERIFIED
    assert by_id["S1"]["status"] == "asserted" and by_id["S1"]["provenance"] == SELF
    assert by_id["T1"]["status"] == "denied" and "provenance" not in by_id["T1"]
    assert payload["overall"] < 100.0
    assert payload["evidence_coverage"]["verified"] == 2


def test_evidence_cannot_affirm_an_explicitly_skipped_item_under_the_flag(tmp_path):
    payload = _assess(
        "--skip", "D1", "--require-evidence", *_files(tmp_path, [_ref("D1")], {SIGNER: KEY})
    )
    assert payload["answers"]["affirmed"] == [] and "D1" in payload["answers"]["skipped"]


# ── resolve_affirmations is the single merge point ────────────────────────────


def test_resolve_affirmations_counted_set_is_subset_of_verified():
    refs = [EvidenceRef(**_ref("D1")), EvidenceRef(**_ref("O5", signer="nobody"))]
    aff = resolve_affirmations(
        frozenset({"S1", "D1", "O5"}), frozenset(), refs, {SIGNER: KEY}, require_evidence=True
    )
    assert aff.affirmed == frozenset({"D1"})
    assert aff.asserted == frozenset({"S1", "O5"})
    assert aff.provenance == {"D1": EVIDENCE_VERIFIED, "O5": SELF, "S1": SELF}
    assert aff.coverage["asserted_not_counted"] == 2 and aff.coverage["require_evidence"]
    block = evidence_block(aff)
    assert block["verified"] == ["D1"] and block["asserted_not_counted"] == ["O5", "S1"]
    off = resolve_affirmations(
        frozenset({"S1", "D1", "O5"}), frozenset(), refs, {SIGNER: KEY}, require_evidence=False
    )
    assert off.affirmed == frozenset({"S1", "D1", "O5"}) and off.asserted == frozenset()


# ── every other command applies the same policy ───────────────────────────────


def test_gate_is_blocked_and_assert_gate_exits_three(tmp_path):
    r = runner.invoke(
        app,
        [
            "--no-dep-check",
            "gate",
            "-g",
            "G3",
            "-r",
            "high",
            "--affirm",
            ALL,
            "--require-evidence",
            *_files(tmp_path, None, {}),
            "--assert-gate",
            "G3",
            "-q",
        ],
    )
    assert r.exit_code == 3, r.output
    data = json.loads(r.stdout)
    assert data["status"] == "BLOCKED"
    assert data["evidence"]["require_evidence"] is True
    assert len(data["evidence"]["asserted_not_counted"]) == 25
    plain = runner.invoke(
        app, ["--no-dep-check", "gate", "-g", "G3", "-r", "high", "--affirm", ALL, "-q"]
    )
    assert json.loads(plain.stdout)["status"] == "OPEN"


def test_report_marks_items_in_both_formats():
    base = ["--no-dep-check", "report", "-u", "ics", "-r", "high", "--affirm", ALL]
    as_json = runner.invoke(app, [*base, "--require-evidence", "-f", "json"])
    payload = json.loads(as_json.stdout)
    assert payload["overall"] == 0.0 and len(payload["answers"]["asserted"]) == 25
    as_md = runner.invoke(app, [*base, "--require-evidence", "-f", "markdown"])
    assert "asserted (not counted)" in as_md.stdout
    assert "25 asserted and not counted" in as_md.stdout
    assert "| Evidence |" in as_md.stdout
    plain_md = runner.invoke(app, [*base, "-f", "markdown"])
    assert "self-attested" in plain_md.stdout and "0 asserted" in plain_md.stdout


def test_signed_export_marks_assertions_in_manifest_and_report(tmp_path):
    out = tmp_path / "pack"
    r = runner.invoke(
        app,
        [
            "--no-dep-check",
            "export",
            "-u",
            "ics",
            "-r",
            "high",
            "--affirm",
            ALL,
            "--require-evidence",
            "--bundle",
            str(out),
            "--sign-key",
            "k",
            "-q",
        ],
    )
    assert r.exit_code == 0, r.output
    manifest = json.loads((out / "manifest.json").read_text())
    assert manifest["evidence"]["require_evidence"] is True
    assert len(manifest["evidence"]["asserted_not_counted"]) == 25
    assert manifest["evidence"]["verified"] == []
    report = json.loads((out / "report.json").read_text())
    assert report["overall"] == 0.0 and len(report["answers"]["asserted"]) == 25
    assert "asserted (not counted)" in (out / "report.md").read_text()
    # The manifest is inside the signed bytes: the marking cannot be stripped.
    ok = runner.invoke(
        app, ["--no-dep-check", "verify-bundle", "--bundle", str(out), "--sign-key", "k"]
    )
    assert ok.exit_code == 0, ok.output


def test_signed_export_without_the_flag_still_says_self_attested(tmp_path):
    out = tmp_path / "pack"
    runner.invoke(
        app,
        [
            "--no-dep-check",
            "export",
            "--affirm",
            ALL,
            "--bundle",
            str(out),
            "--sign-key",
            "k",
            "-q",
        ],
    )
    manifest = json.loads((out / "manifest.json").read_text())
    assert len(manifest["evidence"]["self_attested"]) == 25
    assert manifest["evidence"]["verified"] == []
    assert manifest["evidence"]["require_evidence"] is False


@pytest.mark.parametrize(
    "command",
    [
        ["iso-gap"],
        ["euaiact-gap", "-r", "high"],
        ["framework-gap", "--framework", "nist-ai-rmf"],
    ],
)
def test_gap_commands_apply_the_policy_and_carry_the_marking(command):
    r = runner.invoke(
        app, ["--no-dep-check", *command, "--affirm", ALL, "--require-evidence", "-q"]
    )
    assert r.exit_code == 0, r.output
    data = json.loads(r.stdout)
    assert data["evidence"]["require_evidence"] is True
    assert len(data["evidence"]["asserted_not_counted"]) == 25
    serialised = json.dumps(data)
    assert '"covered"' not in serialised and '"OPEN"' not in serialised


def test_certify_drops_bare_affirmations_and_records_the_policy(tmp_path):
    out = tmp_path / "cert.json"
    r = runner.invoke(
        app,
        [
            "--no-dep-check",
            "certify",
            "-g",
            "G0",
            "--affirm",
            "S1,S2,S3",
            "--require-evidence",
            "--issuer",
            "x",
            "--sign-alg",
            "hmac-sha256",
            "--sign-key",
            "k",
            "-o",
            str(out),
            "-q",
        ],
    )
    assert r.exit_code == 0, r.output
    doc = json.loads(out.read_text())
    assert doc["decision"] == "BLOCKED" and doc["require_evidence"] is True
    assert doc["grounding"] == "evidence-verified"  # nothing self-attested was affirmed
    assert {e["status"] for e in doc["affirmation_set"]} == {"denied"}


def test_mcp_tool_applies_the_policy():
    payload = mcp_server.assess_with_evidence(
        affirmed=sorted(VALID_ITEM_IDS),
        evidence=[],
        trust={},
        risk_class="high",
        require_evidence=True,
    )
    assert payload["overall"] == 0.0 and _statuses(payload) == {"BLOCKED"}
    assert len(payload["answers"]["asserted"]) == 25
    mixed = mcp_server.assess_with_evidence(
        affirmed=["S1", "D1"],
        evidence=[_ref("D1")],
        trust={SIGNER: KEY},
        risk_class="high",
        require_evidence=True,
    )
    assert mixed["answers"]["affirmed"] == ["D1"] and mixed["answers"]["asserted"] == ["S1"]
    legacy = mcp_server.assess_with_evidence(affirmed=["S1"], evidence=[], trust={})
    assert legacy["answers"]["affirmed"] == ["S1"] and legacy["answers"]["asserted"] == []


def test_new_i18n_keys_bilingual():
    from presidio_ikigov_assess.i18n import STRINGS

    for key in (
        "answer_asserted",
        "col_provenance",
        "provenance_self",
        "provenance_evidence",
        "provenance_evidence-verified",
        "asserted_label",
        "evidence_summary_line",
        "require_evidence_asserted_notice",
        "require_evidence_no_trust_notice",
    ):
        entry = STRINGS.get(key)
        assert entry and entry.get("de") and entry.get("en"), key
