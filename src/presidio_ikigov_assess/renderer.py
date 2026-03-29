"""Console and report rendering for IKI-Gov assessment results."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from rich.console import Console

from presidio_ikigov_assess.__init__ import __version__
from presidio_ikigov_assess.checklist import VALID_DIMENSIONS
from presidio_ikigov_assess.gates import GateResult, GateStatus
from presidio_ikigov_assess.i18n import RISK_LABEL_KEY, t
from presidio_ikigov_assess.sanitize import escape_for_report
from presidio_ikigov_assess.scoring import AssessmentScores

_FILLED = "█"
_EMPTY = "░"
_BAR_WIDTH = 10

_STATUS_COLOUR = {
    GateStatus.OPEN: "green",
    GateStatus.PARTIAL: "yellow",
    GateStatus.BLOCKED: "red",
}


def _bar(score: float) -> str:
    filled = round(score / 10)
    filled = max(0, min(_BAR_WIDTH, filled))
    return _FILLED * filled + _EMPTY * (_BAR_WIDTH - filled)


def print_assessment(
    console: Console,
    use_case: str,
    risk_class: str,
    scores: AssessmentScores,
    gate_results: dict[str, GateResult],
    skipped_ids: frozenset[str],
    lang: str,
) -> None:
    """Render the full assessment result to *console*."""
    risk_label = t(RISK_LABEL_KEY[risk_class], lang)
    title = t("assessment_title", lang)
    risk_key = t("risk_label", lang)

    console.print(f"\n[bold]{title} — {use_case}[/bold]  [dim][{risk_key}: {risk_label}][/dim]\n")

    # ── Measurement Dimensions ───────────────────────────────────────────────
    console.print(f"[bold]{t('dimensions_header', lang)}[/bold]")

    for dim in sorted(VALID_DIMENSIONS):
        ds = scores.dimensions[dim]
        dim_name = t(dim, lang)
        bar = _bar(ds.score)
        pct = f"{ds.score:5.1f} %"
        console.print(f"  {dim}  {dim_name:<36} {bar}  {pct}")

    console.rule(style="dim")
    overall_label = t("overall_label", lang)
    overall_bar = _bar(scores.overall)
    console.print(f"  {'':>3}  {overall_label:<36} {overall_bar}  {scores.overall:5.1f} %\n")

    # ── Gate Readiness ───────────────────────────────────────────────────────
    console.print(f"[bold]{t('gates_header', lang)}[/bold]")

    for gate_id, result in sorted(gate_results.items()):
        colour = _STATUS_COLOUR[result.status]
        status_str = t(result.status.value, lang)
        line = f"  {gate_id}  [{colour}]{status_str}[/{colour}]"

        if result.blocking_items:
            blocking_label = t("blocking_label", lang)
            items_str = ", ".join(
                f"{item.id} ({item.text(lang)[:40]})" for item in result.blocking_items
            )
            line += f"  — {blocking_label}: {items_str}"
        elif result.skipped_items:
            skip_label = t("skipped_label", lang)
            items_str = ", ".join(item.id for item in result.skipped_items)
            line += f"  [{skip_label}: {items_str}]"

        console.print(line)

    console.print()


def render_markdown(
    use_case: str,
    risk_class: str,
    scores: AssessmentScores,
    gate_results: dict[str, GateResult],
    affirmed: frozenset[str],
    skipped: frozenset[str],
    lang: str,
) -> str:
    """Return the assessment report as a Markdown string."""
    safe_use_case = escape_for_report(use_case)
    risk_label = t(RISK_LABEL_KEY[risk_class], lang)
    title = t("assessment_title", lang)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines: list[str] = [
        f"# {title} — {safe_use_case}",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Use Case | {safe_use_case} |",
        f"| Risk Class | {risk_label} |",
        f"| Timestamp | {ts} |",
        f"| Tool Version | {__version__} |",
        "",
        f"## {t('dimensions_header', lang)}",
        "",
        "| Dimension | Name | Score | Bar |",
        "|---|---|---|---|",
    ]

    for dim in sorted(VALID_DIMENSIONS):
        ds = scores.dimensions[dim]
        bar = _bar(ds.score)
        lines.append(f"| {dim} | {t(dim, lang)} | {ds.score:.1f} % | `{bar}` |")

    lines += [
        "",
        f"**{t('overall_label', lang)}: {scores.overall:.1f} %**",
        "",
        f"## {t('gates_header', lang)}",
        "",
        "| Gate | Status | Blocking / Skipped Items |",
        "|---|---|---|",
    ]

    for gate_id, result in sorted(gate_results.items()):
        status_str = t(result.status.value, lang)
        detail = ""
        if result.blocking_items:
            detail = "; ".join(
                f"{escape_for_report(item.id)} ({escape_for_report(item.text(lang)[:60])})"
                for item in result.blocking_items
            )
        elif result.skipped_items:
            detail = f"skipped: {', '.join(item.id for item in result.skipped_items)}"
        lines.append(f"| {gate_id} | {status_str} | {detail} |")

    lines += [
        "",
        "---",
        "",
        f"*{t('report_disclaimer', lang)}*",
        "",
    ]

    return "\n".join(lines)


def render_json(
    use_case: str,
    risk_class: str,
    scores: AssessmentScores,
    gate_results: dict[str, GateResult],
    affirmed: frozenset[str],
    skipped: frozenset[str],
    lang: str,
) -> str:
    """Return the assessment report as a JSON string."""
    safe_use_case = escape_for_report(use_case)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    data: dict[str, object] = {
        "use_case": safe_use_case,
        "risk_class": risk_class,
        "lang": lang,
        "timestamp": ts,
        "tool_version": __version__,
        "scores": {
            dim: {
                "score": ds.score,
                "affirmed": ds.affirmed_count,
                "denied": ds.denied_count,
                "skipped": ds.skipped_count,
                "total": ds.total_count,
            }
            for dim, ds in scores.dimensions.items()
        },
        "overall": scores.overall,
        "gates": {
            gate_id: {
                "status": result.status.value,
                "blocking": [item.id for item in result.blocking_items],
                "skipped": [item.id for item in result.skipped_items],
            }
            for gate_id, result in sorted(gate_results.items())
        },
        "answers": {
            "affirmed": sorted(affirmed),
            "skipped": sorted(skipped),
        },
        "disclaimer": t("report_disclaimer", lang),
    }

    return json.dumps(data, indent=2, ensure_ascii=False)
