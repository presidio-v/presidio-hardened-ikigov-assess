"""``iga workshop`` subcommand — live customer-workshop tool (T-B3).

Generates a signed leave-behind artifact per use case from an eai-classification/v1
document.  Designed for offline use at customer sites (air-gapped environments).

Offline design note
-------------------
``iga workshop`` explicitly bypasses the startup dependency-check (``--no-dep-check``
equivalent) because it is intended for use on air-gapped customer sites where network
access is unavailable.  The dep-check calls ``pip-audit`` which requires network access
to fetch advisory data; running it at a customer site would hang, then time out, then
emit a noisy "inconclusive" warning — the opposite of a smooth projector experience.
Security posture is maintained: the tool is pre-vetted on the founder's machine before
use, and the ``--no-dep-check`` bypass is a documented, intentional design choice, not
a security regression.

Artifact layout per use case
-----------------------------
<out>/<use_case_id>/
  report.<lang>.md      — Markdown leave-behind in the requested language
  report.json           — Full assessment JSON (incl. classification provenance block)
  manifest.json         — Content-hashed manifest (presidio-hardened/workshop-leavebehind@1)
  manifest.sig          — Ed25519 detached signature (optional; UNSIGNED marker if absent)

Signing
-------
Ed25519 signing uses the same ``cryptography`` optional extra as evidence.py.
Private key: raw 32-byte hex (64 hex chars), read from --sign-key file or
$IGA_WORKSHOP_SIGN_KEY.  File is mode-checked (warn if not 0o600, do not abort).
If no key is provided, the artifact is written unsigned with an UNSIGNED marker
in manifest.json and a stderr warning.  Workshop must not fail because the
[crypto] extra is missing: signing is best-effort, unsigned artifacts are valid.

Verification
------------
``iga workshop verify --dir <use_case_dir> --pubkey <hex>`` re-hashes the artifacts
and verifies the Ed25519 signature.  Round-trip tested.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from presidio_ikigov_assess import __version__
from presidio_ikigov_assess import content as content_mod
from presidio_ikigov_assess.classification import (
    ClassificationDocument,
    ClassificationError,
    ClassifiedUseCase,
    cell_id,
    parse_classification_bytes,
)
from presidio_ikigov_assess.content.profile import CellProfile
from presidio_ikigov_assess.gates import GateStatus, evaluate_all_gates
from presidio_ikigov_assess.i18n import RISK_LABEL_KEY, t
from presidio_ikigov_assess.renderer import (
    build_payload,
    render_markdown,
)
from presidio_ikigov_assess.sanitize import (
    ValidationError,
    validate_lang,
    validate_output_path,
)
from presidio_ikigov_assess.scoring import compute_scores
from presidio_ikigov_assess.security import log_security_event

workshop_app = typer.Typer(
    name="workshop",
    help="Offline customer-workshop tool — signed leave-behind artifacts per use case.",
    add_completion=False,
    no_args_is_help=True,
)
# Dep-check bypass: cli.py main_callback detects invoked_subcommand == "workshop"
# and sets _NO_DEP_CHECK = True automatically. This means workshop commands never
# trigger the pip-audit network call, which is correct for air-gapped customer sites.

_console = Console()
_err_console = Console(stderr=True)

WORKSHOP_MANIFEST_SCHEMA = "presidio-hardened/workshop-leavebehind@1"

# Maximum byte lengths for answers.json fields (mirrors sanitize.py limits).
_MAX_ANSWERS_BYTES = 65_536
_MAX_ID_LEN = 128

# Ed25519 private key: 32 bytes → 64 hex chars
_ED25519_PRIVKEY_HEX_LEN = 64
# Ed25519 public key: 32 bytes → 64 hex chars
_ED25519_PUBKEY_HEX_LEN = 64


# ── Helpers shared with classify.py (extracted here) ─────────────────────────


def _read_classification_file(path: str, lang: str) -> ClassificationDocument:
    """Read and parse a classification document, exit 1 on error."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        _err_console.print(f"[red]{t('workshop_err_file', lang, path=path)}[/red]: {exc}")
        raise typer.Exit(1) from exc
    try:
        return parse_classification_bytes(raw)
    except ClassificationError as exc:
        _err_console.print(f"[red]{t('workshop_err_parse', lang, detail=str(exc))}[/red]")
        raise typer.Exit(1) from exc


def _resolve_profile_pack(lang: str) -> content_mod.ProfilePack:
    packs = content_mod.load_profile_packs()
    pack = next(iter(packs.values()), None)
    if pack is None:
        _err_console.print(f"[red]{t('workshop_err_no_pack', lang)}[/red]")
        raise typer.Exit(1)
    return pack


def _uc_display_name(uc: ClassifiedUseCase, lang: str) -> str:
    """Return the best display name for a use case in the requested language."""
    if isinstance(uc.name, dict):
        return uc.name.get(lang) or uc.name.get("en") or uc.id
    if isinstance(uc.name, str) and uc.name:
        return uc.name
    return uc.id


def _note_for_profile(profile: CellProfile, lang: str) -> str:
    return profile.notes.get(lang) or profile.notes.get("en") or ""


# ── Ed25519 signing / verification ───────────────────────────────────────────


def _require_ed25519():
    """Return the ed25519 module or raise a clear error."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        return ed25519
    except ImportError as exc:
        raise typer.Exit(1) from exc


def _sign_manifest_ed25519(manifest_bytes: bytes, private_key_hex: str) -> str:
    """Sign manifest bytes with Ed25519; return hex-encoded signature."""
    ed25519 = _require_ed25519()
    privkey = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    sig = privkey.sign(manifest_bytes)
    return sig.hex()


def _verify_manifest_ed25519(
    manifest_bytes: bytes, signature_hex: str, public_key_hex: str
) -> bool:
    """Verify an Ed25519 signature over manifest bytes. Fail-closed."""
    try:
        ed25519 = _require_ed25519()
        pubkey = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pubkey.verify(bytes.fromhex(signature_hex), manifest_bytes)
        return True
    except Exception:
        return False


def _check_key_file_permissions(path: Path) -> None:
    """Warn if the key file is world- or group-readable (mode check, not abort)."""
    try:
        mode = path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            _err_console.print(
                f"[yellow]{t('workshop_warn_key_permissions', 'de', path=str(path))}[/yellow]"
            )
    except OSError:
        pass  # Cannot stat; ignore silently


def _resolve_sign_key(sign_key_path: Optional[str]) -> Optional[str]:
    """Resolve Ed25519 private key hex from --sign-key file or $IGA_WORKSHOP_SIGN_KEY."""
    if sign_key_path is not None:
        p = Path(sign_key_path)
        _check_key_file_permissions(p)
        try:
            raw = p.read_text(encoding="utf-8").strip()
        except OSError as exc:
            _err_console.print(f"[red]{t('workshop_err_key_read', 'de', path=str(p))}[/red]: {exc}")
            raise typer.Exit(1) from exc
        return raw
    env_val = os.environ.get("IGA_WORKSHOP_SIGN_KEY", "").strip()
    return env_val if env_val else None


# ── Manifest / artifact hashing ──────────────────────────────────────────────


def _sha256_hex(data: str | bytes) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _canonical_json(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _build_workshop_manifest(
    artifacts: dict[str, str],
    *,
    use_case_id: str,
    cell: str,
    risk_class: str,
    pack_framework_id: str,
    pack_version: str,
    pack_content_hash: str,
    lang: str,
    signed: bool,
) -> dict[str, object]:
    return {
        "schema": WORKSHOP_MANIFEST_SCHEMA,
        "tool": "presidio-hardened-ikigov-assess",
        "tool_version": __version__,
        "use_case_id": use_case_id,
        "cell": cell,
        "risk_class": risk_class,
        "lang": lang,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "pack": {
            "framework_id": pack_framework_id,
            "version": pack_version,
            "content_hash": pack_content_hash,
        },
        "artifacts": {
            name: {"sha256": _sha256_hex(content)} for name, content in sorted(artifacts.items())
        },
        "signed": signed,
        "UNSIGNED": not signed,  # explicit marker for unsigned artifacts
    }


def _write_use_case_artifact(
    out_dir: Path,
    *,
    uc: ClassifiedUseCase,
    cell_profile: CellProfile,
    pack: content_mod.ProfilePack,
    affirmed: frozenset[str],
    skipped: frozenset[str],
    lang: str,
    sign_key_hex: Optional[str],
    signer_name: Optional[str],
    classification_doc: ClassificationDocument,
) -> Path:
    """Write the leave-behind artifact for one use case. Returns the directory written."""
    cid = cell_id(uc)
    risk_class = cell_profile.risk_presumption
    strict = cell_profile.strict

    scores = compute_scores(affirmed, skipped, risk_class)
    gate_results = evaluate_all_gates(affirmed, skipped, risk_class, strict)

    # Build full JSON payload with classification provenance block.
    payload = build_payload(
        uc.id,
        risk_class,
        scores,
        gate_results,
        affirmed,
        skipped,
        lang,
    )
    payload["classification"] = {
        "cell": cid,
        "type": uc.type,
        "level": uc.level,
        "base_level": uc.base_level,
        "ecosystem": uc.ecosystem,
        "profile_pack": {
            "framework_id": pack.framework_id,
            "version": pack.version,
            "content_hash": pack.content_hash,
        },
        "producer": classification_doc.producer,
    }

    report_json_str = json.dumps(payload, indent=2, ensure_ascii=False)
    report_md_str = render_markdown(
        uc.id,
        risk_class,
        scores,
        gate_results,
        affirmed,
        skipped,
        lang,
    )

    report_filename = f"report.{lang}.md"
    artifacts: dict[str, str] = {
        report_filename: report_md_str,
        "report.json": report_json_str,
    }

    signed = sign_key_hex is not None
    manifest = _build_workshop_manifest(
        artifacts,
        use_case_id=uc.id,
        cell=cid,
        risk_class=risk_class,
        pack_framework_id=pack.framework_id,
        pack_version=pack.version,
        pack_content_hash=pack.content_hash,
        lang=lang,
        signed=signed,
    )

    manifest_bytes = _canonical_json(manifest)
    manifest_pretty = json.dumps(manifest, indent=2, ensure_ascii=False)

    uc_dir = out_dir / uc.id
    uc_dir.mkdir(parents=True, exist_ok=True)

    # Write report files.
    (uc_dir / report_filename).write_text(report_md_str, encoding="utf-8")
    (uc_dir / "report.json").write_text(report_json_str, encoding="utf-8")
    (uc_dir / "manifest.json").write_text(manifest_pretty, encoding="utf-8")

    if sign_key_hex is not None:
        try:
            sig_hex = _sign_manifest_ed25519(manifest_bytes, sign_key_hex)
            sig_content = json.dumps(
                {
                    "alg": "ed25519",
                    "signer": signer_name or "unknown",
                    "signature": sig_hex,
                },
                indent=2,
            )
            (uc_dir / "manifest.sig").write_text(sig_content, encoding="utf-8")
        except Exception as exc:
            _err_console.print(
                f"[yellow]{t('workshop_warn_sign_failed', lang, uc=uc.id, err=str(exc))}[/yellow]"
            )
            # Write UNSIGNED marker
            (uc_dir / "manifest.sig").write_text(
                json.dumps({"UNSIGNED": True, "reason": str(exc)}, indent=2),
                encoding="utf-8",
            )
    else:
        # No key provided — write explicit UNSIGNED marker.
        (uc_dir / "manifest.sig").write_text(
            json.dumps({"UNSIGNED": True}, indent=2),
            encoding="utf-8",
        )

    return uc_dir


# ── Projector-quality console rendering ──────────────────────────────────────

_GATE_COLOUR = {
    GateStatus.OPEN: "bold green",
    GateStatus.PARTIAL: "bold yellow",
    GateStatus.BLOCKED: "bold red",
}

_RISK_PANEL_COLOUR = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
}


def _render_projector(
    uc: ClassifiedUseCase,
    cell_profile: CellProfile,
    pack: content_mod.ProfilePack,
    lang: str,
) -> None:
    """Render a large-format, high-contrast projector view for one use case."""
    cid = cell_id(uc)
    display_name = _uc_display_name(uc, lang)
    risk_class = cell_profile.risk_presumption
    risk_label = t(RISK_LABEL_KEY[risk_class], lang)
    note = _note_for_profile(cell_profile, lang)
    strict = cell_profile.strict

    _console.print()
    # ── Use-case heading ────────────────────────────────────────────────────
    panel_colour = _RISK_PANEL_COLOUR.get(risk_class, "white")
    heading = Text()
    heading.append(f"{display_name}\n", style="bold white")
    heading.append(f"  {t('workshop_cell_label', lang)}: {cid}   ", style="dim")
    heading.append(f"{t('workshop_risk_label', lang)}: ", style="dim")
    heading.append(risk_label, style=f"bold {panel_colour}")
    if strict:
        heading.append(f"   {t('workshop_strict_label', lang)}", style="bold yellow")
    _console.print(
        Panel(
            heading,
            title=f"[bold]{t('workshop_panel_title', lang)}[/bold]",
            border_style=panel_colour,
            expand=True,
        )
    )

    # ── Cell note ───────────────────────────────────────────────────────────
    if note:
        # Keep note readable; strip DRAFT prefix for projector display
        clean_note = note.replace("ENTWURF: ", "").replace("DRAFT: ", "")
        _console.print(f"[italic dim]{clean_note}[/italic dim]")

    # ── Compute gate status ─────────────────────────────────────────────────
    affirmed: frozenset[str] = frozenset()
    skipped: frozenset[str] = frozenset()
    gate_results = evaluate_all_gates(affirmed, skipped, risk_class, strict)

    # ── Gate status row ─────────────────────────────────────────────────────
    _console.print()
    _console.print(f"[bold]{t('workshop_gates_header', lang)}[/bold]")
    _console.print()

    gate_tbl = Table.grid(padding=(0, 3))
    for gate_id, result in sorted(gate_results.items()):
        colour = _GATE_COLOUR[result.status]
        status_str = t(result.status.value, lang)
        lifecycle = t(f"gate_{gate_id}", lang)
        gate_tbl.add_row(
            Text(gate_id, style="bold"),
            Text(f"[{status_str}]", style=colour),
            Text(lifecycle, style="dim"),
        )
    _console.print(gate_tbl)
    _console.print()


def _render_projector_with_answers(
    uc: ClassifiedUseCase,
    cell_profile: CellProfile,
    pack: content_mod.ProfilePack,
    affirmed: frozenset[str],
    skipped: frozenset[str],
    lang: str,
) -> None:
    """Render a large-format projector view with actual answer data."""
    cid = cell_id(uc)
    display_name = _uc_display_name(uc, lang)
    risk_class = cell_profile.risk_presumption
    risk_label = t(RISK_LABEL_KEY[risk_class], lang)
    note = _note_for_profile(cell_profile, lang)
    strict = cell_profile.strict

    scores = compute_scores(affirmed, skipped, risk_class)
    gate_results = evaluate_all_gates(affirmed, skipped, risk_class, strict)

    _console.print()
    panel_colour = _RISK_PANEL_COLOUR.get(risk_class, "white")
    heading = Text()
    heading.append(f"{display_name}\n", style="bold white")
    heading.append(f"  {t('workshop_cell_label', lang)}: {cid}   ", style="dim")
    heading.append(f"{t('workshop_risk_label', lang)}: ", style="dim")
    heading.append(risk_label, style=f"bold {panel_colour}")
    if strict:
        heading.append(f"   {t('workshop_strict_label', lang)}", style="bold yellow")
    _console.print(
        Panel(
            heading,
            title=f"[bold]{t('workshop_panel_title', lang)}[/bold]",
            border_style=panel_colour,
            expand=True,
        )
    )

    if note:
        clean_note = note.replace("ENTWURF: ", "").replace("DRAFT: ", "")
        _console.print(f"[italic dim]{clean_note}[/italic dim]")

    # ── Score summary ───────────────────────────────────────────────────────
    _console.print()
    _console.print(f"  {t('overall_label', lang)}: [bold]{scores.overall:.0f} %[/bold]")

    # ── Gate status row ─────────────────────────────────────────────────────
    _console.print()
    _console.print(f"[bold]{t('workshop_gates_header', lang)}[/bold]")
    _console.print()

    gate_tbl = Table.grid(padding=(0, 3))
    for gate_id, result in sorted(gate_results.items()):
        colour = _GATE_COLOUR[result.status]
        status_str = t(result.status.value, lang)
        lifecycle = t(f"gate_{gate_id}", lang)
        # Blocking items in compact form
        blocking = ""
        if result.blocking_items:
            ids = ", ".join(item.id for item in result.blocking_items[:3])
            extra = len(result.blocking_items) - 3
            blocking = ids + (f" +{extra}" if extra > 0 else "")
        gate_tbl.add_row(
            Text(gate_id, style="bold"),
            Text(f"[{status_str}]", style=colour),
            Text(lifecycle, style="dim"),
            Text(blocking, style="italic red") if blocking else Text(""),
        )
    _console.print(gate_tbl)
    _console.print()


# ── answers.json parsing ──────────────────────────────────────────────────────


def _parse_answers_file(
    path: str, doc: ClassificationDocument, lang: str
) -> dict[str, dict[str, list[str]]]:
    """Parse and validate an answers.json file.

    Format: {use_case_id: {"affirm": [...], "skip": [...]}}
    Validates all use_case_ids exist in the document; validates all item IDs.
    """
    from presidio_ikigov_assess.sanitize import validate_item_ids

    try:
        raw_bytes = Path(path).read_bytes()
    except OSError as exc:
        _err_console.print(f"[red]{t('workshop_err_answers_read', lang, path=path)}[/red]: {exc}")
        raise typer.Exit(1) from exc

    if len(raw_bytes) > _MAX_ANSWERS_BYTES:
        _err_console.print(f"[red]{t('workshop_err_answers_too_large', lang)}[/red]")
        raise typer.Exit(1)

    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        _err_console.print(f"[red]{t('workshop_err_answers_json', lang, err=str(exc))}[/red]")
        raise typer.Exit(1) from exc

    if not isinstance(data, dict):
        _err_console.print(f"[red]{t('workshop_err_answers_format', lang)}[/red]")
        raise typer.Exit(1)

    valid_ids = {uc.id for uc in doc.use_cases}
    result: dict[str, dict[str, list[str]]] = {}

    for uc_id, v in data.items():
        if not isinstance(uc_id, str) or len(uc_id) > _MAX_ID_LEN:
            _err_console.print(
                f"[red]{t('workshop_err_answers_bad_id', lang, id=uc_id[:40])}[/red]"
            )
            raise typer.Exit(1)
        if uc_id not in valid_ids:
            _err_console.print(f"[red]{t('workshop_err_answers_unknown_uc', lang, id=uc_id)}[/red]")
            raise typer.Exit(1)
        if not isinstance(v, dict):
            _err_console.print(f"[red]{t('workshop_err_answers_format', lang)}[/red]")
            raise typer.Exit(1)

        affirm_raw = ",".join(v.get("affirm", []))
        skip_raw = ",".join(v.get("skip", []))
        try:
            affirm_ids = list(validate_item_ids(affirm_raw))
            skip_ids = list(validate_item_ids(skip_raw))
        except ValidationError as exc:
            _err_console.print(
                f"[red]{t('workshop_err_answers_item_id', lang, err=str(exc))}[/red]"
            )
            raise typer.Exit(1) from exc

        result[uc_id] = {"affirm": affirm_ids, "skip": skip_ids}

    return result


# ── Main workshop command ─────────────────────────────────────────────────────


@workshop_app.command(name="run")
def workshop_run(
    file: str = typer.Option(
        ...,
        "--file",
        "-f",
        help="Path to the eai-classification/v1 JSON document.",
    ),
    select: Optional[list[str]] = typer.Option(
        None,
        "--select",
        help="Use-case id(s) to include (repeatable). Default: all.",
    ),
    lang: str = typer.Option(
        "de",
        "--lang",
        "-l",
        help="Output language: de | en (default: de).",
    ),
    out: str = typer.Option(
        "",
        "--out",
        help="Output directory (default: ./workshop-out/<date>/).",
    ),
    answers: Optional[str] = typer.Option(
        None,
        "--answers",
        help="Answers JSON: {use_case_id: {affirm: [...], skip: [...]}}.",
    ),
    sign_key: Optional[str] = typer.Option(
        None,
        "--sign-key",
        help="Path to Ed25519 private key file (hex). Also reads $IGA_WORKSHOP_SIGN_KEY.",
    ),
    signer: Optional[str] = typer.Option(
        None,
        "--signer",
        help="Signer name embedded in manifest.sig (e.g. 'Presidio Group').",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Suppress projector output; write artifacts only.",
    ),
) -> None:
    """Run the workshop: generate signed leave-behind artifacts per use case.

    OFFLINE-CAPABLE: does not touch the network. The dependency check is
    bypassed automatically (see module docstring).
    """
    try:
        lang = validate_lang(lang)
    except ValidationError as exc:
        _err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc

    # Read and parse the classification document.
    doc = _read_classification_file(file, lang)
    pack = _resolve_profile_pack(lang)

    # Filter use cases.
    if select:
        # Validate each selected id.
        for sel_id in select:
            if not any(uc.id == sel_id for uc in doc.use_cases):
                _err_console.print(
                    f"[red]{t('workshop_err_select_not_found', lang, id=sel_id)}[/red]"
                )
                raise typer.Exit(1)
        ucs = [uc for uc in doc.use_cases if uc.id in set(select)]
    else:
        ucs = list(doc.use_cases)

    if not ucs:
        _err_console.print(f"[red]{t('workshop_err_no_use_cases', lang)}[/red]")
        raise typer.Exit(1)

    # Resolve output directory.
    if out:
        try:
            out_dir = Path(validate_output_path(out))
        except ValidationError as exc:
            _err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from exc
    else:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        out_dir = Path("workshop-out") / date_str

    # Parse answers file if provided.
    answers_map: dict[str, dict[str, list[str]]] = {}
    if answers is not None:
        try:
            answers_path = validate_output_path(answers)
        except ValidationError as exc:
            _err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from exc
        answers_map = _parse_answers_file(answers_path, doc, lang)

    # Resolve signing key.
    sign_key_hex = _resolve_sign_key(sign_key)
    if sign_key_hex is None:
        _err_console.print(f"[yellow]{t('workshop_warn_unsigned', lang)}[/yellow]")

    if not quiet:
        _console.print()
        _console.print(
            Panel(
                f"[bold]{t('workshop_header_title', lang)}[/bold]\n"
                f"[dim]{len(ucs)} {t('workshop_header_use_cases', lang)}  |  "
                f"{t('workshop_header_lang', lang)}: {lang.upper()}  |  "
                f"{t('workshop_header_signed', lang)}: "
                f"{'✓' if sign_key_hex else t('workshop_unsigned_marker', lang)}[/dim]",
                border_style="blue",
                expand=True,
            )
        )

    # Generate artifacts for each use case.
    written_dirs: list[Path] = []
    for uc in ucs:
        cid = cell_id(uc)
        cell_profile = pack.get(cid)

        # Resolve affirmed/skipped for this use case.
        uc_answers = answers_map.get(uc.id, {})
        affirmed = frozenset(uc_answers.get("affirm", []))
        skipped = frozenset(uc_answers.get("skip", []))

        # Projector rendering (non-quiet).
        if not quiet:
            _render_projector_with_answers(uc, cell_profile, pack, affirmed, skipped, lang)

        # Write leave-behind artifact.
        try:
            uc_dir = _write_use_case_artifact(
                out_dir,
                uc=uc,
                cell_profile=cell_profile,
                pack=pack,
                affirmed=affirmed,
                skipped=skipped,
                lang=lang,
                sign_key_hex=sign_key_hex,
                signer_name=signer,
                classification_doc=doc,
            )
            written_dirs.append(uc_dir)
        except OSError as exc:
            _err_console.print(
                f"[red]{t('workshop_err_write', lang, uc=uc.id, err=str(exc))}[/red]"
            )
            raise typer.Exit(1) from exc

        if not quiet:
            _console.print(f"[green]  ✓ {t('workshop_artifact_written', lang)}: {uc_dir}[/green]")

    log_security_event(
        {
            "event": "iga-workshop-run",
            "use_cases": len(ucs),
            "signed": sign_key_hex is not None,
            "lang": lang,
            "out_dir": str(out_dir),
        }
    )

    if not quiet:
        _console.print()
        _console.print(
            f"[bold]{t('workshop_done', lang, n=len(written_dirs), dir=str(out_dir))}[/bold]"
        )


# ── workshop verify subcommand ────────────────────────────────────────────────


@workshop_app.command(name="verify")
def workshop_verify(
    dir_path: str = typer.Option(
        ...,
        "--dir",
        "-d",
        help="Use-case artifact directory (containing manifest.json and manifest.sig).",
    ),
    pubkey: str = typer.Option(
        ...,
        "--pubkey",
        help="Ed25519 public key in hex (64 hex chars).",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Emit machine-readable JSON only.",
    ),
) -> None:
    """Verify a workshop leave-behind artifact: re-hash artifacts and verify Ed25519 signature."""
    try:
        dir_path = validate_output_path(dir_path)
    except ValidationError as exc:
        _err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc

    artifact_dir = Path(dir_path)
    if not artifact_dir.is_dir():
        _err_console.print(f"[red]{t('workshop_verify_err_not_dir', 'de', path=dir_path)}[/red]")
        raise typer.Exit(1)

    # Load manifest.
    manifest_path = artifact_dir / "manifest.json"
    if not manifest_path.exists():
        _err_console.print(f"[red]{t('workshop_verify_err_no_manifest', 'de')}[/red]")
        raise typer.Exit(1)

    manifest_text = manifest_path.read_text(encoding="utf-8")
    try:
        manifest = json.loads(manifest_text)
    except json.JSONDecodeError as exc:
        _err_console.print(
            f"[red]{t('workshop_verify_err_bad_manifest', 'de', err=str(exc))}[/red]"
        )
        raise typer.Exit(1) from exc

    # Re-hash artifacts.
    artifact_results: dict[str, bool] = {}
    for name, meta in manifest.get("artifacts", {}).items():
        artifact_path = artifact_dir / name
        if not artifact_path.exists():
            artifact_results[name] = False
            continue
        content = artifact_path.read_bytes()
        expected_hash = meta.get("sha256", "")
        actual_hash = _sha256_hex(content)
        artifact_results[name] = actual_hash == expected_hash

    # Verify Ed25519 signature.
    sig_path = artifact_dir / "manifest.sig"
    signature_ok: bool | None = None
    if sig_path.exists():
        sig_text = sig_path.read_text(encoding="utf-8")
        try:
            sig_data = json.loads(sig_text)
            if sig_data.get("UNSIGNED"):
                signature_ok = None  # no signature was written
            else:
                sig_hex = sig_data.get("signature", "")
                # Use the canonical bytes of the manifest for verification.
                manifest_canonical = _canonical_json(manifest)
                signature_ok = _verify_manifest_ed25519(manifest_canonical, sig_hex, pubkey)
        except (json.JSONDecodeError, Exception):
            signature_ok = False

    all_artifacts_ok = all(artifact_results.values()) if artifact_results else False
    ok = all_artifacts_ok and (signature_ok is not False)

    log_security_event(
        {
            "event": "iga-workshop-verify",
            "ok": ok,
            "artifacts_ok": all_artifacts_ok,
            "signature_ok": signature_ok,
        }
    )

    if quiet:
        print(
            json.dumps(
                {
                    "ok": ok,
                    "artifacts": artifact_results,
                    "signature": signature_ok,
                }
            )
        )
    else:
        for name, art_ok in artifact_results.items():
            colour = "green" if art_ok else "red"
            mark = "OK  " if art_ok else "FAIL"
            _console.print(f"[{colour}]{mark}[/{colour}] {name}")
        if signature_ok is True:
            _console.print(f"[green]{t('workshop_verify_sig_ok', 'de')}[/green]")
        elif signature_ok is False:
            _console.print(f"[red]{t('workshop_verify_sig_fail', 'de')}[/red]")
        else:
            _console.print(f"[yellow]{t('workshop_verify_unsigned', 'de')}[/yellow]")

    if not ok:
        raise typer.Exit(1)
