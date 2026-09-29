"""Signed, audit-ready evidence-pack export (v0.15.0).

Bundles an assessment into a self-contained, tamper-evident package an auditor can
keep: the rendered report (Markdown + JSON) plus a ``manifest.json`` that content-hashes
every artifact and pins the *framework content* that produced it (checklist text, the
ISO/IEC 42001 matrix, the EU AI Act gate→article table). Re-hashing the artifacts against
the manifest detects any post-hoc edit; an optional detached HMAC signature over the
manifest binds the bundle as a whole.

Reproducible: the same answers and framework content yield identical artifact hashes and
the same ``framework_content_hash`` — only the manifest timestamp differs between runs.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from presidio_ikigov_assess import __version__
from presidio_ikigov_assess.checklist import CHECKLIST, ISO_CLAUSES_BY_ITEM
from presidio_ikigov_assess.euaiact import EU_AI_ACT_ARTICLE_GATES
from presidio_ikigov_assess.sanitize import escape_for_report

MANIFEST_SCHEMA = "presidio-hardened/evidence-pack@1"


#: Upper bound on one member read during verification. Bundles and leave-behinds
#: hold small text reports; a manifest naming anything larger is refused rather
#: than read into memory.
MAX_MEMBER_BYTES = 8 * 1024 * 1024


class BundleError(RuntimeError):
    """Raised when a bundle cannot be written or fails verification."""


def _sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _canonical(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def framework_content_hash() -> str:
    """Stable hash of the framework content that drives an assessment.

    Pins the checklist (ids, bilingual text, dimensions, gates) and the ISO/EU AI Act
    mapping tables, so a manifest records exactly which framework content was in force.
    """
    payload = {
        "checklist": [
            [item.id, item.text_de, item.text_en, item.m_dimension, list(item.gates)]
            for item in CHECKLIST
        ],
        "iso_clauses_by_item": {k: list(v) for k, v in sorted(ISO_CLAUSES_BY_ITEM.items())},
        "euaiact_article_gates": {k: list(v) for k, v in sorted(EU_AI_ACT_ARTICLE_GATES.items())},
    }
    return _sha256_hex(_canonical(payload))


def build_manifest(
    artifacts: dict[str, str],
    *,
    use_case: str,
    risk_class: str,
    evidence: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build the manifest: per-artifact sha256 + framework hash + provenance.

    ``evidence`` (v0.26.0 S-1) is the marking block: which affirmed items were
    verified, evidence-backed or self-attested, and which were asserted but not
    counted under ``--require-evidence``. It sits in the manifest, so a signed
    pack states on its face what its numbers rest on.
    """
    manifest: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "tool": "presidio-hardened-ikigov-assess",
        "tool_version": __version__,
        "use_case": escape_for_report(use_case),
        "risk_class": risk_class,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "framework_content_hash": framework_content_hash(),
        "artifacts": {
            name: {"sha256": _sha256_hex(content)} for name, content in sorted(artifacts.items())
        },
    }
    if evidence is not None:
        manifest["evidence"] = evidence
    return manifest


def sign_manifest(manifest_bytes: str, key: str) -> str:
    """Detached HMAC-SHA256 over the exact manifest.json bytes (optional integrity seal)."""
    return hmac.new(key.encode("utf-8"), manifest_bytes.encode("utf-8"), hashlib.sha256).hexdigest()


def write_bundle(
    out_path: str | Path,
    *,
    report_md: str,
    report_json: str,
    use_case: str,
    risk_class: str,
    as_zip: bool = False,
    sign_key: str | None = None,
    evidence: dict[str, object] | None = None,
) -> Path:
    """Write the evidence pack to a directory (or a ``.zip``). Returns the path written."""
    artifacts = {"report.md": report_md, "report.json": report_json}
    manifest = build_manifest(
        artifacts, use_case=use_case, risk_class=risk_class, evidence=evidence
    )
    manifest_text = json.dumps(manifest, indent=2, ensure_ascii=False)
    files = dict(artifacts)
    files["manifest.json"] = manifest_text
    if sign_key is not None:
        files["manifest.sig"] = sign_manifest(manifest_text, sign_key)

    out_path = Path(out_path)
    if as_zip:
        import zipfile

        out_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for name, content in sorted(files.items()):
                zf.writestr(name, content)
    else:
        out_path.mkdir(parents=True, exist_ok=True)
        for name, content in files.items():
            write_text_nofollow(out_path / name, content)
    return out_path


def write_text_nofollow(path: Path, text: str) -> None:
    """Write *text* to *path* without following a symlink planted at *path*.

    Output directories can be shared or handed over, so a pre-existing symlink
    named like an artifact would otherwise redirect the write onto its target.
    Raises :class:`OSError` (``ELOOP``) instead; callers already report OSError.
    """
    if path.is_symlink():
        raise OSError(errno.ELOOP, "refusing to write through a symlink", str(path))
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def member_path(root: Path, name: object) -> Path:
    """Resolve a manifest member *name* to a regular file directly inside *root*.

    Manifest names are attacker-controlled when verifying a handed-over bundle:
    only a plain file name is accepted (no separators, ``..``, absolute paths or
    NUL), and the member must be a regular file, not a symlink or device, so
    verification can neither read outside the bundle nor act as a hash oracle
    for files the caller never meant to hand over.
    """
    if (
        not isinstance(name, str)
        or name in ("", ".", "..")
        or "/" in name
        or "\\" in name
        or "\0" in name
    ):
        raise BundleError(f"invalid bundle member name: {name!r:.80}")
    path = root / name
    if path.is_symlink():
        raise BundleError(f"bundle member is a symlink: {name}")
    if not path.exists():
        raise BundleError(f"missing bundle member: {name}")
    if not path.is_file():
        raise BundleError(f"bundle member is not a regular file: {name}")
    return path


def read_member_bytes(path: Path) -> bytes:
    """Read *path*, refusing anything over :data:`MAX_MEMBER_BYTES`."""
    with path.open("rb") as fh:
        data = fh.read(MAX_MEMBER_BYTES + 1)
    if len(data) > MAX_MEMBER_BYTES:
        raise BundleError(f"bundle member exceeds {MAX_MEMBER_BYTES} bytes: {path.name}")
    return data


def _read_member(bundle: Path, name: str) -> str:
    if bundle.is_dir():
        return read_member_bytes(member_path(bundle, name)).decode("utf-8")
    import zipfile

    try:
        with zipfile.ZipFile(bundle) as zf:
            info = zf.getinfo(name)
            if info.file_size > MAX_MEMBER_BYTES:
                raise BundleError(f"bundle member exceeds {MAX_MEMBER_BYTES} bytes: {name}")
            return zf.read(info).decode("utf-8")
    except (KeyError, zipfile.BadZipFile) as exc:
        raise BundleError(f"cannot read {name} from zip: {exc}") from exc


def verify_bundle(bundle: str | Path, *, sign_key: str | None = None) -> dict[str, object]:
    """Verify a bundle: re-hash artifacts against the manifest and (optionally) the signature.

    Returns a report ``{"ok", "artifacts": {name: bool}, "signature": bool | None}``.
    Fail-closed: any missing member, hash mismatch, or bad signature yields ``ok=False``.
    """
    bundle = Path(bundle)
    try:
        manifest = json.loads(_read_member(bundle, "manifest.json"))
    except json.JSONDecodeError as exc:
        raise BundleError(f"invalid manifest.json: {exc.msg}") from exc

    artifact_results: dict[str, bool] = {}
    for name, meta in manifest.get("artifacts", {}).items():
        try:
            content = _read_member(bundle, name)
        except BundleError:
            artifact_results[name] = False
            continue
        artifact_results[name] = hmac.compare_digest(_sha256_hex(content), meta.get("sha256", ""))

    signature_ok: bool | None = None
    if sign_key is not None:
        manifest_text = _read_member(bundle, "manifest.json")
        try:
            recorded = _read_member(bundle, "manifest.sig")
        except BundleError:
            recorded = ""
        signature_ok = hmac.compare_digest(sign_manifest(manifest_text, sign_key), recorded)

    ok = all(artifact_results.values()) and (signature_ok is not False)
    return {"ok": ok, "artifacts": artifact_results, "signature": signature_ok}
