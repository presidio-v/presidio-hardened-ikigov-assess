"""Typer-based CLI for the IKI-Gov Assessment Tool.

Entry point: iga  (registered in pyproject.toml)

Commands:
  iga assess   — run an assessment (parameter-driven or --interactive wizard)
  iga gate     — check readiness for a specific gate G0–G5
  iga report   — render an assessment to Markdown or JSON (stdout or --output file)
  iga iso-gap  — map results to ISO/IEC 42001 clause coverage
  iga euaiact-gap — map results to EU AI Act high-risk obligations (Art. 9–17)
  iga list     — list saved assessments from the local store
  iga portfolio— aggregate saved assessments (M1–M6 + blocked gates)
  iga trend    — maturity delta between two saved assessments
  iga delete   — hard-delete saved assessments for a use case
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from presidio_ikigov_assess import bundle as bundle_mod
from presidio_ikigov_assess import content as content_mod
from presidio_ikigov_assess import evidence as evidence_mod
from presidio_ikigov_assess import store
from presidio_ikigov_assess.classify import classify_app
from presidio_ikigov_assess.euaiact import evaluate_euaiact
from presidio_ikigov_assess.gates import evaluate_all_gates, evaluate_gate
from presidio_ikigov_assess.i18n import t
from presidio_ikigov_assess.iso import evaluate_iso_coverage
from presidio_ikigov_assess.renderer import (
    gate_detail_segments,
    print_assessment,
    print_euaiact,
    print_iso_coverage,
    print_portfolio,
    print_saved_list,
    print_trend,
    render_euaiact_json,
    render_gate_json,
    render_iso_json,
    render_json,
    render_markdown,
    render_portfolio_json,
    render_saved_list_json,
    render_trend_json,
)
from presidio_ikigov_assess.sanitize import (
    ValidationError,
    validate_date,
    validate_format,
    validate_gate,
    validate_item_ids,
    validate_lang,
    validate_output_path,
    validate_risk_class,
    validate_use_case,
)
from presidio_ikigov_assess.scoring import compute_scores
from presidio_ikigov_assess.security import (
    DepCheckResult,
    SessionLimitError,
    dep_check_available,
    dep_check_status,
    enforce_persistent_session_limit,
    log_security_event,
    session_limit,
)
from presidio_ikigov_assess.trend import TrendError, compute_trend, select_trend_pair

app = typer.Typer(
    name="iga",
    help="IKI-Gov Assessment Tool — assess AI use cases against the IKI-Gov Reference Model.",
    add_completion=False,
    no_args_is_help=True,
)
app.add_typer(classify_app, name="classify")

console = Console()
err_console = Console(stderr=True)

_NO_DEP_CHECK: bool = False

# CI exit codes for --assert-gate (v0.3.0): distinct from the general error
# code 1, so pipelines can branch on gate status without parsing output.
GATE_EXIT_CODES: dict[str, int] = {"OPEN": 0, "PARTIAL": 2, "BLOCKED": 3}


@app.callback()
def main_callback(
    no_dep_check: bool = typer.Option(
        False,
        "--no-dep-check",
        help="Skip the on-startup CVE/dependency check (for offline/CI use).",
        is_eager=True,
    ),
) -> None:
    """IKI-Gov Assessment Tool (iga) — v0.20.0."""
    global _NO_DEP_CHECK
    _NO_DEP_CHECK = no_dep_check

    if not no_dep_check:
        _run_dep_check_quietly()


def _run_dep_check_quietly() -> None:
    if not dep_check_available():
        err_console.print(f"[dim]{t('dep_check_unavailable', 'en')}[/dim]")
        return
    err_console.print(f"[dim]{t('dep_check_start', 'en')}[/dim]")
    status = dep_check_status(verbose=False)
    if status is DepCheckResult.CLEAN:
        err_console.print(f"[dim]{t('dep_check_ok', 'en')}[/dim]")
    elif status is DepCheckResult.VULNERABLE:
        err_console.print(f"[yellow]{t('dep_check_warn', 'en')}[/yellow]")
    elif status is DepCheckResult.UNAVAILABLE:
        err_console.print(f"[dim]{t('dep_check_unavailable', 'en')}[/dim]")
    else:
        # Inconclusive (timeout / tool error): do not imply the scan was clean.
        err_console.print(f"[yellow]{t('dep_check_inconclusive', 'en')}[/yellow]")


def _parse_answers(
    affirm_raw: Optional[str],
    skip_raw: Optional[str],
    lang: str,
) -> tuple[frozenset[str], frozenset[str]]:
    """Parse and validate --affirm and --skip option strings."""
    try:
        affirmed = frozenset(validate_item_ids(affirm_raw or ""))
        skipped = frozenset(validate_item_ids(skip_raw or ""))
    except ValidationError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc

    overlap = affirmed & skipped
    if overlap:
        err_console.print(
            f"[red]Error:[/red] Item IDs appear in both --affirm and --skip: "
            f"{', '.join(sorted(overlap))}"
        )
        raise typer.Exit(1)

    return affirmed, skipped


def _validated(value: str, validator, lang: str) -> str:
    try:
        return validator(value)
    except ValidationError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc


def _read_file(path: str, lang: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        err_console.print(f"[red]Error:[/red] could not read {path}: {exc}")
        raise typer.Exit(1) from exc


def _resolve_sign_key(
    sign_key: Optional[str], sign_key_file: Optional[str], lang: str
) -> Optional[str]:
    """Resolve the manifest HMAC seal key, preferring sources that stay off argv.

    Precedence: ``--sign-key-file`` (path) > ``--sign-key`` (inline) > ``$IGA_SIGN_KEY``.
    The file and env-var paths keep the secret out of shell history and the process list;
    ``--sign-key`` is kept for convenience but is the least private option. Whitespace
    around a file's contents is stripped (so ``echo key > file`` works); an empty env var
    counts as unset.
    """
    if sign_key_file is not None:
        path = _validated(sign_key_file, validate_output_path, lang)
        return _read_file(path, lang).strip()
    if sign_key is not None:
        return sign_key
    return os.environ.get("IGA_SIGN_KEY") or None


def _apply_evidence(
    affirmed: frozenset[str],
    skipped: frozenset[str],
    evidence_path: str,
    trust_path: Optional[str],
    require_evidence: bool,
    lang: str,
    quiet: bool,
) -> tuple[frozenset[str], dict[str, str], dict[str, object]]:
    """Load signed evidence, affirm the items it substantiates, return provenance+coverage."""
    evidence_path = _validated(evidence_path, validate_output_path, lang)
    try:
        refs = evidence_mod.load_evidence(_read_file(evidence_path, lang))
        trust = None
        if trust_path is not None:
            trust_path = _validated(trust_path, validate_output_path, lang)
            trust = evidence_mod.load_trust_store(_read_file(trust_path, lang))
        result = evidence_mod.classify(refs, trust, require_verified=require_evidence)
    except evidence_mod.EvidenceError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc

    # Evidence cannot affirm an item explicitly skipped by the assessor.
    affirmed_via_evidence = result.affirmed - skipped
    merged = affirmed | affirmed_via_evidence
    provenance = evidence_mod.merge_provenance(merged, result.provenance)
    coverage = evidence_mod.evidence_coverage(provenance)

    log_security_event(
        {
            "event": "iga-evidence-attached",
            "n_refs": result.n_refs,
            "n_verified": result.n_verified,
            "n_affirmed": len(affirmed_via_evidence),
            "require_evidence": require_evidence,
            "trust": trust_path is not None,
            "lang": lang,
        }
    )
    return merged, provenance, coverage


@app.command()
def assess(
    use_case: str = typer.Option(
        "unnamed",
        "--use-case",
        "-u",
        help="AI use-case identifier (alphanumeric, hyphens, underscores; max 128 chars).",
    ),
    risk_class: str = typer.Option(
        "medium",
        "--risk-class",
        "-r",
        help="Risk class: low | medium | high.",
    ),
    lang: str = typer.Option(
        "en",
        "--lang",
        "-l",
        help="Output language: de | en.",
    ),
    affirm: Optional[str] = typer.Option(
        None,
        "--affirm",
        help="Comma-separated list of affirmed item IDs, e.g. S1,S2,D1.",
    ),
    skip: Optional[str] = typer.Option(
        None,
        "--skip",
        help="Comma-separated list of skipped item IDs, e.g. I4,I5.",
    ),
    interactive: bool = typer.Option(
        False,
        "--interactive",
        "-i",
        help="Run the step-by-step interactive wizard.",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Treat skipped gate-critical items as blocking (implied at --risk-class high).",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Emit machine-readable JSON only (no progress bars or tables).",
    ),
    save: bool = typer.Option(
        False,
        "--save",
        help="Persist this assessment to the local store (~/.iga/assessments.db).",
    ),
    evidence: Optional[str] = typer.Option(
        None,
        "--evidence",
        help="Signed EvidenceRef JSON from a presidio-hardened-* control (affirms items).",
    ),
    trust: Optional[str] = typer.Option(
        None,
        "--trust",
        help="Trust-store JSON {signer: key} used to verify evidence signatures.",
    ),
    require_evidence: bool = typer.Option(
        False,
        "--require-evidence",
        help="Fail-closed: only evidence that verifies against --trust affirms its item.",
    ),
) -> None:
    """Assess an AI use case against the IKI-Gov checklist."""
    lang = _validated(lang, validate_lang, lang)
    use_case = _validated(use_case, validate_use_case, lang)
    risk_class = _validated(risk_class, validate_risk_class, lang)

    try:
        enforce_persistent_session_limit()
    except SessionLimitError:
        err_console.print(f"[red]{t('rate_limit_exceeded', lang, limit=session_limit())}[/red]")
        raise typer.Exit(1)

    if interactive:
        from presidio_ikigov_assess.wizard import run_wizard

        try:
            affirmed, skipped_set = run_wizard(lang=lang, risk_class=risk_class, use_case=use_case)
        except (EOFError, KeyboardInterrupt):
            err_console.print("\n[yellow]Assessment cancelled.[/yellow]")
            raise typer.Exit(0)
    else:
        affirmed, skipped_set = _parse_answers(affirm, skip, lang)

    provenance: dict[str, str] | None = None
    coverage: dict[str, object] | None = None
    if evidence is not None:
        affirmed, provenance, coverage = _apply_evidence(
            affirmed, skipped_set, evidence, trust, require_evidence, lang, quiet
        )

    scores = compute_scores(affirmed, skipped_set, risk_class)
    gate_results = evaluate_all_gates(affirmed, skipped_set, risk_class, strict)

    gates_open = [g for g, r in gate_results.items() if r.status.value == "OPEN"]

    log_security_event(
        {
            "event": "iga-assessment-complete",
            "risk_class": risk_class,
            "gates_open": gates_open,
            "lang": lang,
            "overall_score": scores.overall,
        }
    )

    if save:
        store.save_assessment(
            use_case=use_case,
            risk_class=risk_class,
            lang=lang,
            answers={"affirmed": sorted(affirmed), "skipped": sorted(skipped_set)},
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
            err_console.print(f"[green]{t('assessment_saved', lang, use_case=use_case)}[/green]")

    if quiet:
        print(
            render_json(
                use_case,
                risk_class,
                scores,
                gate_results,
                affirmed,
                skipped_set,
                lang,
                provenance,
                coverage,
            )
        )
        return

    print_assessment(
        console=console,
        use_case=use_case,
        risk_class=risk_class,
        scores=scores,
        gate_results=gate_results,
        skipped_ids=skipped_set,
        lang=lang,
    )
    if coverage is not None:
        console.print(
            f"[dim]Evidence coverage: {coverage['evidence_backed']}/{coverage['affirmed_total']} "
            f"affirmed items backed ({coverage['verified']} verified).[/dim]"
        )


@app.command(name="verify-evidence")
def verify_evidence(
    evidence: str = typer.Option(..., "--evidence", help="Signed EvidenceRef JSON to verify."),
    trust: str = typer.Option(..., "--trust", help="Trust-store JSON {signer: key}."),
    lang: str = typer.Option("en", "--lang", "-l", help="Output language: de | en."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Emit machine-readable JSON only."),
) -> None:
    """Verify the signatures on an evidence document against a trust store (fail-closed).

    Exits 0 only if every reference verifies; exits 1 if any reference fails or the
    documents are malformed.
    """
    lang = _validated(lang, validate_lang, lang)
    evidence = _validated(evidence, validate_output_path, lang)
    trust = _validated(trust, validate_output_path, lang)
    try:
        refs = evidence_mod.load_evidence(_read_file(evidence, lang))
        store_keys = evidence_mod.load_trust_store(_read_file(trust, lang))
    except evidence_mod.EvidenceError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc

    results = []
    all_ok = bool(refs)
    for ref in refs:
        ok = evidence_mod.verify_ref(ref, store_keys)
        all_ok = all_ok and ok
        results.append(
            {
                "item_id": ref.item_id,
                "signer": ref.signer,
                "verified": ok,
                "ledger_ref": ref.ledger_ref,
            }
        )
    log_security_event(
        {"event": "iga-evidence-verified", "n_refs": len(refs), "all_ok": all_ok, "lang": lang}
    )

    if quiet:
        print(json.dumps({"all_verified": all_ok, "refs": results}, ensure_ascii=False))
    else:
        for r in results:
            mark = "OK  " if r["verified"] else "FAIL"
            colour = "green" if r["verified"] else "red"
            console.print(f"[{colour}]{mark}[/{colour}] {r['item_id']}  signer={r['signer']}")
        if not refs:
            err_console.print("[yellow]No evidence references found.[/yellow]")
    if not all_ok:
        raise typer.Exit(1)


@app.command()
def gate(
    gate_id: str = typer.Option(
        ...,
        "--gate",
        "-g",
        help="Gate identifier: G0–G5.",
    ),
    risk_class: str = typer.Option(
        "medium",
        "--risk-class",
        "-r",
        help="Risk class: low | medium | high.",
    ),
    lang: str = typer.Option(
        "en",
        "--lang",
        "-l",
        help="Output language: de | en.",
    ),
    affirm: Optional[str] = typer.Option(
        None,
        "--affirm",
        help="Comma-separated list of affirmed item IDs.",
    ),
    skip: Optional[str] = typer.Option(
        None,
        "--skip",
        help="Comma-separated list of skipped item IDs.",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Treat skipped gate-critical items as blocking (implied at --risk-class high).",
    ),
    assert_gate: Optional[str] = typer.Option(
        None,
        "--assert-gate",
        help="Exit with the gate's CI code (0 OPEN / 2 PARTIAL / 3 BLOCKED). Must match --gate.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Emit machine-readable JSON only (no progress bars).",
    ),
) -> None:
    """Check readiness for a specific IKI-Gov lifecycle gate."""
    lang = _validated(lang, validate_lang, lang)
    gate_id = _validated(gate_id, validate_gate, lang)
    risk_class = _validated(risk_class, validate_risk_class, lang)

    affirmed, skipped_set = _parse_answers(affirm, skip, lang)

    result = evaluate_gate(gate_id, affirmed, skipped_set, risk_class, strict)
    status_str = t(result.status.value, lang)

    log_security_event(
        {
            "event": "iga-gate-check",
            "gate": gate_id,
            "status": result.status.value,
            "risk_class": risk_class,
            "strict": strict or risk_class == "high",
            "lang": lang,
        }
    )

    if quiet:
        print(render_gate_json(result, risk_class, strict, lang))
    else:
        colour_map = {"OPEN": "green", "PARTIAL": "yellow", "BLOCKED": "red"}
        colour = colour_map.get(result.status.value, "white")
        line = f"\n[bold]{gate_id}[/bold]  [{colour}]{status_str}[/{colour}]"
        details = gate_detail_segments(result, lang, text_width=50)
        if details:
            line += "  — " + " · ".join(details)
        console.print(line)

    if assert_gate is not None:
        try:
            assert_gate_id = validate_gate(assert_gate)
        except ValidationError as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from exc

        if assert_gate_id != gate_id:
            err_console.print(
                f"[red]Error:[/red] --assert-gate {assert_gate_id} does not match --gate {gate_id}."
            )
            raise typer.Exit(1)

        code = GATE_EXIT_CODES.get(result.status.value, 1)
        if code == 0:
            if not quiet:
                console.print(f"[green]{t('gate_assert_pass', lang, gate=gate_id)}[/green]")
        else:
            if not quiet:
                err_console.print(
                    f"[red]{t('gate_assert_fail', lang, gate=gate_id, status=status_str)}[/red]"
                )
            raise typer.Exit(code)


@app.command()
def report(
    use_case: str = typer.Option(
        "unnamed",
        "--use-case",
        "-u",
        help="AI use-case identifier.",
    ),
    risk_class: str = typer.Option(
        "medium",
        "--risk-class",
        "-r",
        help="Risk class: low | medium | high.",
    ),
    lang: str = typer.Option(
        "en",
        "--lang",
        "-l",
        help="Output language: de | en.",
    ),
    affirm: Optional[str] = typer.Option(
        None,
        "--affirm",
        help="Comma-separated list of affirmed item IDs.",
    ),
    skip: Optional[str] = typer.Option(
        None,
        "--skip",
        help="Comma-separated list of skipped item IDs.",
    ),
    fmt: str = typer.Option(
        "markdown",
        "--format",
        "-f",
        help="Output format: markdown | json.",
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Treat skipped gate-critical items as blocking (implied at --risk-class high).",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write the report to this file instead of stdout.",
    ),
) -> None:
    """Render an assessment report (Markdown or JSON) to stdout or a file.

    With --output the report is written to the given path; otherwise it is
    printed to stdout. The report includes use-case metadata, M1–M6 scores,
    gate readiness, and a per-item answers table.
    """
    lang = _validated(lang, validate_lang, lang)
    use_case = _validated(use_case, validate_use_case, lang)
    risk_class = _validated(risk_class, validate_risk_class, lang)
    fmt = _validated(fmt, validate_format, lang)
    out_path = _validated(output, validate_output_path, lang) if output is not None else None

    affirmed, skipped_set = _parse_answers(affirm, skip, lang)

    scores = compute_scores(affirmed, skipped_set, risk_class)
    gate_results = evaluate_all_gates(affirmed, skipped_set, risk_class, strict)

    log_security_event(
        {
            "event": "iga-report-generated",
            "risk_class": risk_class,
            "format": fmt,
            "lang": lang,
            "to_file": out_path is not None,
        }
    )

    if fmt == "json":
        report_text = render_json(
            use_case, risk_class, scores, gate_results, affirmed, skipped_set, lang
        )
    else:
        report_text = render_markdown(
            use_case, risk_class, scores, gate_results, affirmed, skipped_set, lang
        )

    if out_path is None:
        print(report_text)
        return

    # Refuse to write through a symlink: an attacker who can pre-plant a symlink
    # at the destination could otherwise redirect the write to a file outside
    # the intended target.
    if Path(out_path).is_symlink():
        err_console.print(f"[red]Error:[/red] {t('output_is_symlink', lang, path=out_path)}")
        raise typer.Exit(1)

    try:
        Path(out_path).write_text(report_text + "\n", encoding="utf-8")
    except OSError as exc:
        err_console.print(f"[red]Error:[/red] could not write report: {exc}")
        raise typer.Exit(1) from exc

    # typer.echo (not rich): avoids Rich markup interpretation of the user-supplied
    # path and line-wrapping that would split a long path across lines.
    typer.echo(t("report_written", lang, path=out_path), err=True)


@app.command()
def export(
    use_case: str = typer.Option("unnamed", "--use-case", "-u", help="AI use-case identifier."),
    risk_class: str = typer.Option(
        "medium", "--risk-class", "-r", help="Risk class: low|medium|high."
    ),
    lang: str = typer.Option("en", "--lang", "-l", help="Output language: de | en."),
    affirm: Optional[str] = typer.Option(
        None, "--affirm", help="Comma-separated affirmed item IDs."
    ),
    skip: Optional[str] = typer.Option(None, "--skip", help="Comma-separated skipped item IDs."),
    strict: bool = typer.Option(
        False, "--strict", help="Treat skipped gate-critical items as blocking."
    ),
    bundle: str = typer.Option(..., "--bundle", help="Output directory (or .zip with --zip)."),
    as_zip: bool = typer.Option(
        False, "--zip", help="Write a .zip archive instead of a directory."
    ),
    sign_key: Optional[str] = typer.Option(
        None,
        "--sign-key",
        help="HMAC seal key, inline. Least private — prefer --sign-key-file or $IGA_SIGN_KEY.",
    ),
    sign_key_file: Optional[str] = typer.Option(
        None,
        "--sign-key-file",
        help="File holding the HMAC seal key, keeping it off argv (also reads $IGA_SIGN_KEY).",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Emit machine-readable JSON only."),
) -> None:
    """Export a signed, audit-ready evidence pack (report + hash manifest) for an assessment."""
    lang = _validated(lang, validate_lang, lang)
    use_case = _validated(use_case, validate_use_case, lang)
    risk_class = _validated(risk_class, validate_risk_class, lang)
    bundle = _validated(bundle, validate_output_path, lang)
    seal_key = _resolve_sign_key(sign_key, sign_key_file, lang)
    affirmed, skipped_set = _parse_answers(affirm, skip, lang)

    scores = compute_scores(affirmed, skipped_set, risk_class)
    gate_results = evaluate_all_gates(affirmed, skipped_set, risk_class, strict)
    report_md = render_markdown(
        use_case, risk_class, scores, gate_results, affirmed, skipped_set, lang
    )
    report_json = render_json(
        use_case, risk_class, scores, gate_results, affirmed, skipped_set, lang
    )

    try:
        out = bundle_mod.write_bundle(
            bundle,
            report_md=report_md,
            report_json=report_json,
            use_case=use_case,
            risk_class=risk_class,
            as_zip=as_zip,
            sign_key=seal_key,
        )
    except (OSError, bundle_mod.BundleError) as exc:
        err_console.print(f"[red]Error:[/red] could not write evidence pack: {exc}")
        raise typer.Exit(1) from exc

    log_security_event(
        {"event": "iga-export", "as_zip": as_zip, "signed": seal_key is not None, "lang": lang}
    )
    if quiet:
        print(json.dumps({"bundle": str(out), "signed": seal_key is not None, "zip": as_zip}))
    else:
        console.print(f"[green]Evidence pack written to: {out}[/green]")


@app.command(name="verify-bundle")
def verify_bundle(
    bundle: str = typer.Option(..., "--bundle", help="Evidence-pack directory or .zip to verify."),
    sign_key: Optional[str] = typer.Option(
        None,
        "--sign-key",
        help="HMAC seal key, inline. Least private — prefer --sign-key-file or $IGA_SIGN_KEY.",
    ),
    sign_key_file: Optional[str] = typer.Option(
        None,
        "--sign-key-file",
        help="File holding the HMAC seal key, keeping it off argv (also reads $IGA_SIGN_KEY).",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Emit machine-readable JSON only."),
) -> None:
    """Verify an evidence pack: re-hash artifacts vs the manifest (and optional signature)."""
    bundle = _validated(bundle, validate_output_path, "en")
    seal_key = _resolve_sign_key(sign_key, sign_key_file, "en")
    try:
        report = bundle_mod.verify_bundle(bundle, sign_key=seal_key)
    except bundle_mod.BundleError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc

    log_security_event({"event": "iga-verify-bundle", "ok": report["ok"]})
    if quiet:
        print(json.dumps(report))
    else:
        for name, ok in report["artifacts"].items():
            colour = "green" if ok else "red"
            console.print(f"[{colour}]{'OK  ' if ok else 'FAIL'}[/{colour}] {name}")
        if report["signature"] is not None:
            sig_ok = report["signature"]
            console.print(
                f"[{'green' if sig_ok else 'red'}]manifest signature: "
                f"{'valid' if sig_ok else 'INVALID'}[/]"
            )
    if not report["ok"]:
        raise typer.Exit(1)


@app.command(name="content-list")
def content_list(
    lang: str = typer.Option("en", "--lang", "-l", help="Output language: de | en."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Emit machine-readable JSON only."),
) -> None:
    """List installed regulatory-content packs (built-in + external) with versions/hashes."""
    lang = _validated(lang, validate_lang, lang)
    try:
        packs = content_mod.load_packs()
    except content_mod.ContentError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc

    summary = [
        {
            "framework_id": p.framework_id,
            "version": p.version,
            "mapping_kind": p.mapping_kind,
            "targets": len(p.target_order),
            "source": p.source,
            "content_hash": p.content_hash,
        }
        for p in packs.values()
    ]
    log_security_event({"event": "iga-content-list", "count": len(summary), "lang": lang})
    if quiet:
        print(json.dumps(summary))
    else:
        for s in summary:
            console.print(
                f"[bold]{s['framework_id']}[/bold] v{s['version']} "
                f"({s['mapping_kind']}-mapped, {s['targets']} targets, {s['source']}) "
                f"[dim]{s['content_hash'][:12]}[/dim]"
            )


@app.command(name="framework-gap")
def framework_gap(
    framework: str = typer.Option(
        ..., "--framework", help="Content-pack framework id (see content-list)."
    ),
    use_case: str = typer.Option("unnamed", "--use-case", "-u", help="AI use-case identifier."),
    risk_class: str = typer.Option(
        "medium", "--risk-class", "-r", help="Risk class: low|medium|high."
    ),
    lang: str = typer.Option("en", "--lang", "-l", help="Output language: de | en."),
    affirm: Optional[str] = typer.Option(
        None, "--affirm", help="Comma-separated affirmed item IDs."
    ),
    skip: Optional[str] = typer.Option(None, "--skip", help="Comma-separated skipped item IDs."),
    strict: bool = typer.Option(
        False, "--strict", help="Treat skipped gate-critical items as blocking."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Emit machine-readable JSON only."),
) -> None:
    """Coverage gap against any installed content pack (generic over the pack engine)."""
    lang = _validated(lang, validate_lang, lang)
    framework = _validated(framework, validate_use_case, lang)
    use_case = _validated(use_case, validate_use_case, lang)
    risk_class = _validated(risk_class, validate_risk_class, lang)
    affirmed, skipped_set = _parse_answers(affirm, skip, lang)

    packs = content_mod.load_packs()
    pack = packs.get(framework)
    if pack is None:
        err_console.print(
            f"[red]Error:[/red] unknown framework '{framework}'. "
            f"Available: {', '.join(sorted(packs))}."
        )
        raise typer.Exit(1)

    gate_results = None
    if pack.mapping_kind == "gate":
        gate_results = evaluate_all_gates(affirmed, skipped_set, risk_class, strict)
    try:
        coverage = content_mod.evaluate_coverage(pack, affirmed, gate_results)
    except content_mod.ContentError as exc:
        err_console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(1) from exc

    log_security_event({"event": "iga-framework-gap", "framework": framework, "lang": lang})
    if quiet:
        print(
            json.dumps(
                {
                    "framework_id": pack.framework_id,
                    "version": pack.version,
                    "content_hash": pack.content_hash,
                    "coverage": {
                        t: {
                            "status": c.status.value,
                            "name": pack.name(t, lang),
                            "satisfied": c.satisfied,
                            "total": c.total,
                            "outstanding": list(c.outstanding),
                        }
                        for t, c in coverage.items()
                    },
                }
            )
        )
    else:
        colour = {"covered": "green", "partial": "yellow", "gap": "red"}
        console.print(f"\n[bold]{pack.framework_id} v{pack.version}[/bold] — {use_case}\n")
        for t, c in coverage.items():
            col = colour.get(c.status.value, "white")
            line = (
                f"  {t:<4} {pack.name(t, lang):<34} [{col}]{c.status.value.upper():<8}[/{col}] "
                f"({c.satisfied}/{c.total})"
            )
            if c.outstanding:
                line += f"  — outstanding: {', '.join(c.outstanding)}"
            console.print(line)


@app.command(name="iso-gap")
def iso_gap(
    use_case: str = typer.Option(
        "unnamed",
        "--use-case",
        "-u",
        help="AI use-case identifier.",
    ),
    risk_class: str = typer.Option(
        "medium",
        "--risk-class",
        "-r",
        help="Risk class: low | medium | high.",
    ),
    lang: str = typer.Option(
        "en",
        "--lang",
        "-l",
        help="Output language: de | en.",
    ),
    affirm: Optional[str] = typer.Option(
        None,
        "--affirm",
        help="Comma-separated list of affirmed item IDs.",
    ),
    skip: Optional[str] = typer.Option(
        None,
        "--skip",
        help="Comma-separated list of skipped item IDs.",
    ),
    quiet: bool = typer.Option(
        False,
        "--quiet",
        "-q",
        help="Emit machine-readable JSON only.",
    ),
) -> None:
    """Map assessment results to ISO/IEC 42001 clause-level coverage.

    Shows each ISO/IEC 42001 clause group (4–10 + Annex A) as covered, partial,
    or gap based on the affirmed checklist items, with the outstanding items per
    incompletely-covered clause. Skipped and denied items count as not affirmed.
    """
    lang = _validated(lang, validate_lang, lang)
    use_case = _validated(use_case, validate_use_case, lang)
    risk_class = _validated(risk_class, validate_risk_class, lang)

    affirmed, _skipped_set = _parse_answers(affirm, skip, lang)

    coverage = evaluate_iso_coverage(affirmed)
    gaps = [clause for clause, cov in coverage.items() if cov.status.value != "covered"]

    log_security_event(
        {
            "event": "iga-iso-gap",
            "risk_class": risk_class,
            "lang": lang,
            "gaps": gaps,
        }
    )

    if quiet:
        print(render_iso_json(use_case, risk_class, coverage, lang))
    else:
        print_iso_coverage(console, use_case, risk_class, coverage, lang)


@app.command(name="euaiact-gap")
def euaiact_gap(
    use_case: str = typer.Option(
        "unnamed",
        "--use-case",
        "-u",
        help="AI use-case identifier.",
    ),
    risk_class: str = typer.Option(
        "high",
        "--risk-class",
        "-r",
        help="Risk class (EU AI Act obligations apply only to high-risk systems).",
    ),
    lang: str = typer.Option("en", "--lang", "-l", help="Output language: de | en."),
    affirm: Optional[str] = typer.Option(
        None, "--affirm", help="Comma-separated list of affirmed item IDs."
    ),
    skip: Optional[str] = typer.Option(
        None, "--skip", help="Comma-separated list of skipped item IDs."
    ),
    strict: bool = typer.Option(
        False,
        "--strict",
        help="Treat skipped gate-critical items as blocking (implied at high risk).",
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Emit machine-readable JSON only."),
) -> None:
    """Map gate readiness to EU AI Act high-risk obligations (Art. 9–17).

    Each article (Art. 9–17) is shown OPEN / PARTIAL / BLOCKED based on the
    readiness of the gates that generate its evidence. Only meaningful for
    high-risk systems; exits with a warning for low/medium risk.
    """
    lang = _validated(lang, validate_lang, lang)
    use_case = _validated(use_case, validate_use_case, lang)
    risk_class = _validated(risk_class, validate_risk_class, lang)

    if risk_class != "high":
        err_console.print(f"[yellow]{t('euaiact_high_risk_only', lang)}[/yellow]")
        raise typer.Exit(1)

    affirmed, skipped_set = _parse_answers(affirm, skip, lang)
    gate_results = evaluate_all_gates(affirmed, skipped_set, risk_class, strict)
    coverage = evaluate_euaiact(gate_results)

    blocked = [a for a, cov in coverage.items() if cov.status == "BLOCKED"]
    log_security_event(
        {
            "event": "iga-euaiact-gap",
            "risk_class": risk_class,
            "lang": lang,
            "articles_blocked": blocked,
        }
    )

    if quiet:
        print(render_euaiact_json(use_case, risk_class, coverage, lang))
    else:
        print_euaiact(console, use_case, risk_class, coverage, lang)


@app.command(name="list")
def list_assessments(
    lang: str = typer.Option("en", "--lang", "-l", help="Output language: de | en."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Emit machine-readable JSON only."),
) -> None:
    """List saved assessments from the local store (~/.iga/assessments.db)."""
    lang = _validated(lang, validate_lang, lang)
    assessments = store.list_assessments()
    log_security_event({"event": "iga-list", "count": len(assessments), "lang": lang})

    if quiet:
        print(render_saved_list_json(assessments))
    else:
        print_saved_list(console, assessments, lang)


@app.command()
def portfolio(
    lang: str = typer.Option("en", "--lang", "-l", help="Output language: de | en."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Emit machine-readable JSON only."),
) -> None:
    """Aggregate saved assessments into a portfolio view (M1–M6 + blocked gates).

    Uses the most recent saved assessment per use case.
    """
    lang = _validated(lang, validate_lang, lang)
    summary = store.portfolio_summary()
    log_security_event(
        {"event": "iga-portfolio", "use_case_count": summary["use_case_count"], "lang": lang}
    )

    if quiet:
        print(render_portfolio_json(summary, lang))
    else:
        print_portfolio(console, summary, lang)


@app.command()
def delete(
    use_case: str = typer.Option(
        ...,
        "--use-case",
        "-u",
        help="Use case whose saved assessments will be hard-deleted.",
    ),
    lang: str = typer.Option("en", "--lang", "-l", help="Output language: de | en."),
) -> None:
    """Hard-delete all saved assessments for a use case (no soft-delete log)."""
    lang = _validated(lang, validate_lang, lang)
    use_case = _validated(use_case, validate_use_case, lang)

    removed = store.delete_use_case(use_case)
    log_security_event({"event": "iga-delete", "removed": removed, "lang": lang})

    if removed:
        console.print(f"[green]{t('delete_done', lang, count=removed, use_case=use_case)}[/green]")
    else:
        err_console.print(f"[yellow]{t('delete_none', lang, use_case=use_case)}[/yellow]")


@app.command()
def trend(
    use_case: str = typer.Option(
        ...,
        "--use-case",
        "-u",
        help="Use case to trend (needs >=2 saved assessments).",
    ),
    from_date: Optional[str] = typer.Option(
        None,
        "--from",
        help="Window start date YYYY-MM-DD (compare first vs last in window).",
    ),
    to_date: Optional[str] = typer.Option(
        None,
        "--to",
        help="Window end date YYYY-MM-DD.",
    ),
    lang: str = typer.Option("en", "--lang", "-l", help="Output language: de | en."),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Emit machine-readable JSON only."),
) -> None:
    """Show the maturity delta between two saved assessments of a use case.

    Without a date window, compares the two most recent runs. With --from/--to,
    compares the first and last saved assessment in the inclusive date window.
    """
    lang = _validated(lang, validate_lang, lang)
    use_case = _validated(use_case, validate_use_case, lang)
    from_date = _validated(from_date, validate_date, lang) if from_date is not None else None
    to_date = _validated(to_date, validate_date, lang) if to_date is not None else None

    assessments = store.assessments_for_use_case(use_case)
    try:
        earlier, later = select_trend_pair(assessments, from_date, to_date)
    except TrendError:
        err_console.print(f"[yellow]{t('trend_insufficient', lang, use_case=use_case)}[/yellow]")
        raise typer.Exit(1)

    result = compute_trend(earlier, later)
    log_security_event(
        {
            "event": "iga-trend",
            "overall_delta": result.overall_delta,
            "lang": lang,
        }
    )

    if quiet:
        print(render_trend_json(result, lang))
    else:
        print_trend(console, result, lang)
