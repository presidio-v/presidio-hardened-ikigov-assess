"""Typer-based CLI for the IKI-Gov Assessment Tool.

Entry point: iga  (registered in pyproject.toml)

Commands:
  iga assess   — run an assessment (parameter-driven or --interactive wizard)
  iga gate     — check readiness for a specific gate G0–G5
  iga report   — render an assessment to Markdown or JSON (stdout or --output file)
  iga iso-gap  — map results to ISO/IEC 42001 clause coverage
  iga list     — list saved assessments (stub; persistence added in v0.6.0)
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from presidio_ikigov_assess.gates import evaluate_all_gates, evaluate_gate
from presidio_ikigov_assess.i18n import t
from presidio_ikigov_assess.iso import evaluate_iso_coverage
from presidio_ikigov_assess.renderer import (
    gate_detail_segments,
    print_assessment,
    print_iso_coverage,
    render_gate_json,
    render_iso_json,
    render_json,
    render_markdown,
)
from presidio_ikigov_assess.sanitize import (
    ValidationError,
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
    dep_check_available,
    increment_and_check_session_count,
    log_security_event,
    run_dep_check,
)

app = typer.Typer(
    name="iga",
    help="IKI-Gov Assessment Tool — assess AI use cases against the IKI-Gov Reference Model.",
    add_completion=False,
    no_args_is_help=True,
)

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
    """IKI-Gov Assessment Tool (iga) — v0.5.0."""
    global _NO_DEP_CHECK
    _NO_DEP_CHECK = no_dep_check

    if not no_dep_check:
        _run_dep_check_quietly()


def _run_dep_check_quietly() -> None:
    if not dep_check_available():
        err_console.print(f"[dim]{t('dep_check_unavailable', 'en')}[/dim]")
        return
    err_console.print(f"[dim]{t('dep_check_start', 'en')}[/dim]")
    ok = run_dep_check(verbose=False)
    if ok:
        err_console.print(f"[dim]{t('dep_check_ok', 'en')}[/dim]")
    else:
        err_console.print(f"[yellow]{t('dep_check_warn', 'en')}[/yellow]")


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
) -> None:
    """Assess an AI use case against the IKI-Gov checklist."""
    lang = _validated(lang, validate_lang, lang)
    use_case = _validated(use_case, validate_use_case, lang)
    risk_class = _validated(risk_class, validate_risk_class, lang)

    increment_and_check_session_count()

    if interactive:
        from presidio_ikigov_assess.wizard import run_wizard

        try:
            affirmed, skipped_set = run_wizard(lang=lang, risk_class=risk_class, use_case=use_case)
        except (EOFError, KeyboardInterrupt):
            err_console.print("\n[yellow]Assessment cancelled.[/yellow]")
            raise typer.Exit(0)
    else:
        affirmed, skipped_set = _parse_answers(affirm, skip, lang)

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

    if quiet:
        print(render_json(use_case, risk_class, scores, gate_results, affirmed, skipped_set, lang))
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

    try:
        Path(out_path).write_text(report_text + "\n", encoding="utf-8")
    except OSError as exc:
        err_console.print(f"[red]Error:[/red] could not write report: {exc}")
        raise typer.Exit(1) from exc

    # typer.echo (not rich): avoids Rich markup interpretation of the user-supplied
    # path and line-wrapping that would split a long path across lines.
    typer.echo(t("report_written", lang, path=out_path), err=True)


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


@app.command(name="list")
def list_assessments(
    lang: str = typer.Option(
        "en",
        "--lang",
        "-l",
        help="Output language: de | en.",
    ),
) -> None:
    """List saved assessments.

    Persistence is introduced in v0.6.0; this command is a prerequisite stub.
    """
    lang = _validated(lang, validate_lang, lang)
    console.print(f"[dim]{t('list_empty', lang)}[/dim]")
