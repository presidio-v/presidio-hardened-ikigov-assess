"""``iga classify`` command group — classificator bridge (v0.20.0).

Sub-commands:
  iga classify ingest  — validate a classification document and render the cell→profile table
  iga classify assess  — resolve a use-case profile then run the full assess pipeline

All user-facing strings go through i18n.py.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from presidio_ikigov_assess import content as content_mod
from presidio_ikigov_assess import store
from presidio_ikigov_assess.classification import (
    ClassificationDocument,
    ClassificationError,
    ClassifiedUseCase,
    cell_id,
    parse_classification_bytes,
)
from presidio_ikigov_assess.content.profile import CellProfile
from presidio_ikigov_assess.gates import evaluate_all_gates
from presidio_ikigov_assess.i18n import t
from presidio_ikigov_assess.renderer import (
    print_assessment,
    render_json,
)
from presidio_ikigov_assess.sanitize import (
    ValidationError,
    validate_lang,
    validate_output_path,
    validate_use_case,
)
from presidio_ikigov_assess.scoring import compute_scores
from presidio_ikigov_assess.security import (
    SessionLimitError,
    enforce_persistent_session_limit,
    log_security_event,
    session_limit,
)

classify_app = typer.Typer(
    name="classify",
    help="Classificator bridge — ingest eai-classification/v1 documents and run profiled assessments.",
    add_completion=False,
    no_args_is_help=True,
)

_console = Console()
_err_console = Console(stderr=True)


def _validated(value: str, validator, lang: str) -> str:
    try:
        return validator(value)
    except ValidationError as exc:
        _err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc


def _read_classification_file(path: str, lang: str) -> ClassificationDocument:
    """Read and parse a classification document from a file, exiting 1 on error."""
    path_v = _validated(path, validate_output_path, lang)
    try:
        raw = Path(path_v).read_bytes()
    except OSError as exc:
        _err_console.print(f"[red]Error:[/red] {t('classify_err_file', lang, path=path_v)}: {exc}")
        raise typer.Exit(1) from exc
    try:
        doc = parse_classification_bytes(raw)
    except ClassificationError as exc:
        _err_console.print(f"[red]Error:[/red] {t('classify_err_parse', lang, detail=str(exc))}")
        raise typer.Exit(1) from exc
    return doc


def _resolve_profile_pack(
    profile_framework_id: Optional[str],
    lang: str,
) -> content_mod.ProfilePack:
    """Resolve the profile pack by framework_id, defaulting to the built-in pack."""
    packs = content_mod.load_profile_packs()
    if profile_framework_id is None:
        # Use the first (usually only) available pack, falling back to builtin.
        pack = next(iter(packs.values()), None)
    else:
        pack = packs.get(profile_framework_id)
    if pack is None:
        fid = profile_framework_id or "<none>"
        _err_console.print(f"[red]Error:[/red] {t('classify_err_no_profile', lang, fid=fid)}")
        raise typer.Exit(1)
    return pack


def _note_for_profile(profile: CellProfile, lang: str) -> str:
    """Return the localised note for a cell profile, falling back to ''."""
    return profile.notes.get(lang) or profile.notes.get("en") or ""


def _risk_label(rp: str, lang: str) -> str:
    key = f"classify_risk_{rp}"
    return t(key, lang)


@classify_app.command(name="ingest")
def ingest(
    file: str = typer.Option(
        ...,
        "--file",
        "-f",
        help="Path to the eai-classification/v1 JSON document.",
    ),
    lang: str = typer.Option(
        "en",
        "--lang",
        "-l",
        help="Output language: de | en.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Emit machine-readable JSON (includes pack content_hash and producer echo).",
    ),
    profile: Optional[str] = typer.Option(
        None,
        "--profile",
        help="Profile pack framework_id to use (default: built-in eai-classification-default).",
    ),
) -> None:
    """Validate an eai-classification/v1 document and resolve each use case to its risk profile.

    Human output: table (use case, cell, risk presumption, strict, obligations, note).
    --quiet: machine JSON including pack content_hash and producer echo.
    Exits 1 on validation failure with an actionable message.
    """
    lang = _validated(lang, validate_lang, lang)
    doc = _read_classification_file(file, lang)
    pack = _resolve_profile_pack(profile, lang)

    results = []
    for uc in doc.use_cases:
        cid = cell_id(uc)
        cell_profile = pack.get(cid)
        results.append(
            {
                "id": uc.id,
                "cell": cid,
                "type": uc.type,
                "level": uc.level,
                "base_level": uc.base_level,
                "ecosystem": uc.ecosystem,
                "risk_presumption": cell_profile.risk_presumption,
                "strict": cell_profile.strict,
                "obligations": list(cell_profile.obligations),
                "note": _note_for_profile(cell_profile, lang),
                "name": uc.name
                if isinstance(uc.name, str)
                else (uc.name.get(lang) or uc.name.get("en") or "")
                if isinstance(uc.name, dict)
                else "",
                "confidence": uc.confidence,
                "tags": list(uc.tags),
            }
        )

    log_security_event(
        {
            "event": "iga-classify-ingest",
            "use_cases": len(results),
            "profile_pack": pack.framework_id,
            "pack_content_hash": pack.content_hash[:16],
            "lang": lang,
        }
    )

    if quiet:
        out = {
            "schema": doc.schema,
            "producer": doc.producer,
            "profile_pack": {
                "framework_id": pack.framework_id,
                "version": pack.version,
                "content_hash": pack.content_hash,
            },
            "use_cases": results,
        }
        print(json.dumps(out, ensure_ascii=False))
        return

    title = t("classify_ingest_title", lang)
    tbl = Table(title=title, show_header=True, header_style="bold")
    tbl.add_column(t("classify_col_id", lang))
    tbl.add_column(t("classify_col_cell", lang))
    tbl.add_column(t("classify_col_risk", lang))
    tbl.add_column(t("classify_col_strict", lang))
    tbl.add_column(t("classify_col_obligations", lang))
    tbl.add_column(t("classify_col_note", lang), max_width=60, no_wrap=False)

    _risk_colour = {"low": "green", "medium": "yellow", "high": "red"}
    for r in results:
        rp = r["risk_presumption"]
        col = _risk_colour.get(rp, "white")
        strict_str = "✓" if r["strict"] else ""
        obs_str = ", ".join(r["obligations"])
        note_str = r["note"][:120] + "…" if len(r["note"]) > 120 else r["note"]
        tbl.add_row(
            r["id"],
            r["cell"],
            f"[{col}]{_risk_label(rp, lang)}[/{col}]",
            strict_str,
            obs_str,
            note_str,
        )

    _console.print(tbl)
    if doc.producer:
        prod_str = json.dumps(doc.producer) if not isinstance(doc.producer, str) else doc.producer
        _console.print(f"[dim]producer: {prod_str[:80]}[/dim]")
    _console.print(
        f"[dim]profile pack: {pack.framework_id} v{pack.version} ({pack.content_hash[:12]})[/dim]"
    )


@classify_app.command(name="assess")
def classify_assess(
    file: str = typer.Option(
        ...,
        "--file",
        "-f",
        help="Path to the eai-classification/v1 JSON document.",
    ),
    select: str = typer.Option(
        ...,
        "--select",
        help="Use-case id to assess (must exist in the classification document).",
    ),
    lang: str = typer.Option(
        "en",
        "--lang",
        "-l",
        help="Output language: de | en.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Emit machine-readable JSON only.",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        help="Persist this assessment to the local store (~/.iga/assessments.db).",
    ),
    affirm: Optional[str] = typer.Option(
        None,
        "--affirm",
        help="Comma-separated list of affirmed checklist item IDs, e.g. S1,S2,D1.",
    ),
    skip: Optional[str] = typer.Option(
        None,
        "--skip",
        help="Comma-separated list of skipped checklist item IDs.",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Additionally tighten strict mode. Profile strict=true cannot be loosened.",
    ),
    evidence: Optional[str] = typer.Option(
        None,
        "--evidence",
        help="Signed EvidenceRef JSON from a presidio-hardened-* control.",
    ),
    trust: Optional[str] = typer.Option(
        None,
        "--trust",
        help="Trust-store JSON {signer: key} for evidence signature verification.",
    ),
    require_evidence: bool = typer.Option(
        False,
        "--require-evidence",
        help="Only evidence-verified items count as affirmed.",
    ),
    profile: Optional[str] = typer.Option(
        None,
        "--profile",
        help="Profile pack framework_id to use (default: built-in eai-classification-default).",
    ),
) -> None:
    """Resolve a use case's profile and run the full IKI-Gov assessment pipeline.

    The use-case's risk_class and strict flag are pre-set from the profile pack.
    --strict may further tighten but profile strict=true cannot be loosened by flags.
    Logs a security event 'iga-classify-assess' including cell and pack content_hash.
    Exits 1 on validation failure.
    """
    from presidio_ikigov_assess import evidence as evidence_mod
    from presidio_ikigov_assess.sanitize import validate_item_ids

    lang = _validated(lang, validate_lang, lang)
    select = _validated(select, validate_use_case, lang)

    doc = _read_classification_file(file, lang)
    pack = _resolve_profile_pack(profile, lang)

    # Find the selected use case in the document.
    uc: ClassifiedUseCase | None = next((u for u in doc.use_cases if u.id == select), None)
    if uc is None:
        _err_console.print(
            f"[red]Error:[/red] {t('classify_err_use_case_not_found', lang, id=select)}"
        )
        raise typer.Exit(1)

    cid = cell_id(uc)
    cell_profile = pack.get(cid)

    # Resolve risk_class and strict from profile.
    risk_class = cell_profile.risk_presumption  # already "low"|"medium"|"high"
    # Profile strict cannot be loosened, but --strict can further tighten.
    effective_strict = cell_profile.strict or strict
    if cell_profile.strict and not strict:
        # Inform the user that strict is profile-mandated.
        if not quiet:
            _err_console.print(f"[dim]{t('classify_profile_strict_locked', lang)}[/dim]")

    try:
        enforce_persistent_session_limit()
    except SessionLimitError:
        _err_console.print(f"[red]{t('rate_limit_exceeded', lang, limit=session_limit())}[/red]")
        raise typer.Exit(1)

    # Parse --affirm / --skip.
    try:
        affirmed_ids = frozenset(validate_item_ids(affirm or ""))
        skipped_ids = frozenset(validate_item_ids(skip or ""))
    except ValidationError as exc:
        _err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc

    overlap = affirmed_ids & skipped_ids
    if overlap:
        _err_console.print(
            f"[red]Error:[/red] Item IDs appear in both --affirm and --skip: "
            f"{', '.join(sorted(overlap))}"
        )
        raise typer.Exit(1)

    # Apply evidence if provided.
    provenance: dict[str, str] | None = None
    ev_coverage: dict[str, object] | None = None
    if evidence is not None:
        evidence_path = _validated(evidence, validate_output_path, lang)
        try:
            raw_evidence = Path(evidence_path).read_text(encoding="utf-8")
            refs = evidence_mod.load_evidence(raw_evidence)
            trust_store = None
            if trust is not None:
                trust_path = _validated(trust, validate_output_path, lang)
                trust_raw = Path(trust_path).read_text(encoding="utf-8")
                trust_store = evidence_mod.load_trust_store(trust_raw)
            result = evidence_mod.classify(refs, trust_store, require_verified=require_evidence)
        except evidence_mod.EvidenceError as exc:
            _err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from exc

        affirmed_via_evidence = result.affirmed - skipped_ids
        affirmed_ids = affirmed_ids | affirmed_via_evidence
        provenance = evidence_mod.merge_provenance(affirmed_ids, result.provenance)
        ev_coverage = evidence_mod.evidence_coverage(provenance)

        log_security_event(
            {
                "event": "iga-evidence-attached",
                "n_refs": result.n_refs,
                "n_verified": result.n_verified,
                "n_affirmed": len(affirmed_via_evidence),
                "require_evidence": require_evidence,
                "trust": trust is not None,
                "lang": lang,
            }
        )

    scores = compute_scores(affirmed_ids, skipped_ids, risk_class)
    gate_results = evaluate_all_gates(affirmed_ids, skipped_ids, risk_class, effective_strict)

    gates_open = [g for g, r in gate_results.items() if r.status.value == "OPEN"]

    log_security_event(
        {
            "event": "iga-classify-assess",
            "use_case_id": select,
            "cell": cid,
            "risk_class": risk_class,
            "strict": effective_strict,
            "profile_pack": pack.framework_id,
            "pack_content_hash": pack.content_hash,
            "gates_open": gates_open,
            "lang": lang,
            "overall_score": scores.overall,
        }
    )

    if save:
        store.save_assessment(
            use_case=select,
            risk_class=risk_class,
            lang=lang,
            answers={"affirmed": sorted(affirmed_ids), "skipped": sorted(skipped_ids)},
            scores={
                **{dim: ds.score for dim, ds in scores.dimensions.items()},
                "overall": scores.overall,
            },
            gates={g: r.status.value for g, r in gate_results.items()},
        )
        log_security_event(
            {"event": "iga-assessment-saved", "risk_class": risk_class, "lang": lang}
        )
        if not quiet:
            _err_console.print(f"[green]{t('assessment_saved', lang, use_case=select)}[/green]")

    if quiet:
        payload = json.loads(
            render_json(
                select,
                risk_class,
                scores,
                gate_results,
                affirmed_ids,
                skipped_ids,
                lang,
                provenance,
                ev_coverage,
            )
        )
        # Augment with classify-specific fields.
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
            "producer": doc.producer,
        }
        print(json.dumps(payload, ensure_ascii=False))
        return

    print_assessment(
        console=_console,
        use_case=select,
        risk_class=risk_class,
        scores=scores,
        gate_results=gate_results,
        skipped_ids=skipped_ids,
        lang=lang,
    )
    _console.print(
        f"[dim]cell: {cid}  |  profile: {pack.framework_id} ({pack.content_hash[:12]})[/dim]"
    )
    if ev_coverage is not None:
        _console.print(
            f"[dim]Evidence coverage: {ev_coverage['evidence_backed']}/"
            f"{ev_coverage['affirmed_total']} affirmed items backed "
            f"({ev_coverage['verified']} verified).[/dim]"
        )
