"""Typer-based CLI for the IKI-Gov Assessment Tool.

Entry point: iga  (registered in pyproject.toml)

Commands:
  iga assess   — run an assessment (parameter-driven or --interactive wizard)
  iga gate     — check readiness for a specific gate G0–G5
  iga report   — render an assessment to Markdown or JSON (stdout)
  iga list     — list saved assessments (stub; persistence added in v0.5.0)
"""

from __future__ import annotations

import typer
from rich.console import Console

from presidio_ikigov_assess.gates import evaluate_all_gates, evaluate_gate
from presidio_ikigov_assess.i18n import t
from presidio_ikigov_assess.renderer import print_assessment, render_json, render_markdown
from presidio_ikigov_assess.sanitize import (
    ValidationError,
    validate_format,
    validate_gate,
    validate_item_ids,
    validate_lang,
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


@app.callback()
def main_callback(
    no_dep_check: bool = typer.Option(
        False,
        "--no-dep-check",
        help="Skip the on-startup CVE/dependency check (for offline/CI use).",
        is_eager=True,
    ),
) -> None:
    """IKI-Gov Assessment Tool (iga) — v0.1.0."""
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
    affirm_raw: str | None,
    skip_raw: str | None,
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


def _validated(value: str, validator, lang: str, error_key: str = "") -> str:
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
    affirm: str | None = typer.Option(
        None,
        "--affirm",
        help="Comma-separated list of affirmed item IDs, e.g. S1,S2,D1.",
    ),
    skip: str | None = typer.Option(
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
    gate_results = evaluate_all_gates(affirmed, skipped_set)

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
    affirm: str | None = typer.Option(
        None,
        "--affirm",
        help="Comma-separated list of affirmed item IDs.",
    ),
    skip: str | None = typer.Option(
        None,
        "--skip",
        help="Comma-separated list of skipped item IDs.",
    ),
    assert_gate: str | None = typer.Option(
        None,
        "--assert-gate",
        help="Exit 1 if the specified gate is not OPEN (for CI pipelines).",
    ),
) -> None:
    """Check readiness for a specific IKI-Gov lifecycle gate."""
    lang = _validated(lang, validate_lang, lang)
    gate_id = _validated(gate_id, validate_gate, lang)
    risk_class = _validated(risk_class, validate_risk_class, lang)

    affirmed, skipped_set = _parse_answers(affirm, skip, lang)

    result = evaluate_gate(gate_id, affirmed, skipped_set)

    status_str = t(result.status.value, lang)

    colour_map = {"OPEN": "green", "PARTIAL": "yellow", "BLOCKED": "red"}
    colour = colour_map.get(result.status.value, "white")

    console.print(f"\n[bold]{gate_id}[/bold]  [{colour}]{status_str}[/{colour}]", end="")

    if result.blocking_items:
        blocking_label = t("blocking_label", lang)
        items_str = ", ".join(
            f"{item.id} ({item.text(lang)[:50]})" for item in result.blocking_items
        )
        console.print(f"  — {blocking_label}: {items_str}", end="")
    elif result.skipped_items:
        skip_label = t("skipped_label", lang)
        items_str = ", ".join(item.id for item in result.skipped_items)
        console.print(f"  [{skip_label}: {items_str}]", end="")

    console.print()

    log_security_event(
        {
            "event": "iga-gate-check",
            "gate": gate_id,
            "status": result.status.value,
            "risk_class": risk_class,
            "lang": lang,
        }
    )

    if assert_gate:
        try:
            assert_gate_id = validate_gate(assert_gate)
        except ValidationError as exc:
            err_console.print(f"[red]Error:[/red] {exc}")
            raise typer.Exit(1) from exc

        if assert_gate_id == gate_id:
            if result.status.value != "OPEN":
                err_console.print(
                    f"[red]{t('gate_assert_fail', lang, gate=gate_id, status=status_str)}[/red]"
                )
                raise typer.Exit(1)
            else:
                console.print(f"[green]{t('gate_assert_pass', lang, gate=gate_id)}[/green]")


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
    affirm: str | None = typer.Option(
        None,
        "--affirm",
        help="Comma-separated list of affirmed item IDs.",
    ),
    skip: str | None = typer.Option(
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
) -> None:
    """Render an assessment report to stdout (Markdown or JSON).

    In v0.1.0 output goes to stdout only; file export is added in v0.3.0.
    """
    lang = _validated(lang, validate_lang, lang)
    use_case = _validated(use_case, validate_use_case, lang)
    risk_class = _validated(risk_class, validate_risk_class, lang)
    fmt = _validated(fmt, validate_format, lang)

    affirmed, skipped_set = _parse_answers(affirm, skip, lang)

    scores = compute_scores(affirmed, skipped_set, risk_class)
    gate_results = evaluate_all_gates(affirmed, skipped_set)

    log_security_event(
        {
            "event": "iga-report-generated",
            "risk_class": risk_class,
            "format": fmt,
            "lang": lang,
        }
    )

    if fmt == "json":
        output = render_json(
            use_case, risk_class, scores, gate_results, affirmed, skipped_set, lang
        )
    else:
        output = render_markdown(
            use_case, risk_class, scores, gate_results, affirmed, skipped_set, lang
        )

    print(output)


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

    Persistence is introduced in v0.5.0; this command is a prerequisite stub.
    """
    lang = _validated(lang, validate_lang, lang)
    console.print(f"[dim]{t('list_empty', lang)}[/dim]")
