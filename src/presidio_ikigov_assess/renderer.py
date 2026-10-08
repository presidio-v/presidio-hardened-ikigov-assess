"""Console and report rendering for IKI-Gov assessment results."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from rich.console import Console

from presidio_ikigov_assess.__init__ import __version__
from presidio_ikigov_assess.checklist import CHECKLIST, VALID_DIMENSIONS
from presidio_ikigov_assess.euaiact import ArticleCoverage
from presidio_ikigov_assess.gates import GateResult, GateStatus
from presidio_ikigov_assess.i18n import RISK_LABEL_KEY, t
from presidio_ikigov_assess.iso import ClauseCoverage, Coverage
from presidio_ikigov_assess.sanitize import escape_for_report, escape_markdown
from presidio_ikigov_assess.scoring import AssessmentScores
from presidio_ikigov_assess.trend import TrendResult

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


def classify_answer(
    item_id: str,
    affirmed: frozenset[str],
    skipped: frozenset[str],
    asserted: frozenset[str] = frozenset(),
) -> str:
    """Return the answer status for an item: affirmed | asserted | skipped | denied.

    ``asserted`` (v0.26.0 S-1) is a self-attestation made under
    ``--require-evidence``: recorded and shown, never counted.
    """
    if item_id in affirmed:
        return "affirmed"
    if item_id in asserted:
        return "asserted"
    if item_id in skipped:
        return "skipped"
    return "denied"


def item_answers(
    affirmed: frozenset[str],
    skipped: frozenset[str],
    lang: str,
    provenance: dict[str, str] | None = None,
    asserted: frozenset[str] = frozenset(),
) -> list[dict[str, object]]:
    """Build the per-item answer detail for every checklist item, in order.

    Every affirmed or asserted item carries ``provenance``: how it was
    substantiated (``self`` | ``evidence`` | ``evidence-verified``). Since
    v0.26.0 the field is always present for those rows (``self`` when no
    evidence was attached), so a reader of any output can tell an assertion
    from evidence without knowing which flags were used.
    """
    rows: list[dict[str, object]] = []
    for item in CHECKLIST:
        status = classify_answer(item.id, affirmed, skipped, asserted)
        row: dict[str, object] = {
            "id": item.id,
            "status": status,
            "status_label": t(f"answer_{status}", lang),
            "dimension": item.m_dimension,
            "gates": list(item.gates),
            "iso_clauses": list(item.iso_clauses),
            "text": item.text(lang),
        }
        if status in ("affirmed", "asserted"):
            row["provenance"] = (provenance or {}).get(item.id, "self")
        rows.append(row)
    return rows


def _evidence_summary_line(coverage: dict[str, object], lang: str) -> str:
    """One-line evidence summary shown under the overall score in every report."""
    return t(
        "evidence_summary_line",
        lang,
        verified=coverage.get("verified", 0),
        backed=coverage.get("evidence_backed", 0),
        total=coverage.get("affirmed_total", 0),
        asserted=coverage.get("asserted_not_counted", 0),
    )


def _default_coverage(
    affirmed: frozenset[str],
    provenance: dict[str, str] | None,
    asserted: frozenset[str],
    require_evidence: bool,
) -> dict[str, object]:
    from presidio_ikigov_assess.evidence import evidence_coverage, merge_provenance

    coverage = evidence_coverage(merge_provenance(affirmed, provenance or {}))
    coverage["require_evidence"] = require_evidence
    coverage["asserted_not_counted"] = len(asserted)
    return coverage


# Characters stripped from the end of a shortened item text so it never ends on
# a dangling separator ("pipeline," → "pipeline…").
_SHORTEN_STRIP = " ,;:.–—-("


def shorten_text(text: str, width: int) -> str:
    """Shorten *text* to at most *width* characters at a word boundary.

    Text that fits is returned unchanged. Otherwise the cut falls on the last
    space within *width* (a single over-long word is hard-cut), trailing
    separators are dropped, and an ellipsis marks the truncation.
    """
    if len(text) <= width:
        return text
    cut = text[: width - 1]
    space = cut.rfind(" ")
    if space > 0:
        cut = cut[:space]
    return cut.rstrip(_SHORTEN_STRIP) + "…"


def gate_detail_segments(result: GateResult, lang: str, text_width: int = 0) -> list[str]:
    """Build the human-readable detail segments for a gate result.

    Lists denied items as blocking, skips that block under strict/high-risk
    policy separately (so the reason for a BLOCKED-not-PARTIAL gate is visible),
    and otherwise lists informational skips. *text_width* > 0 appends the item
    text, shortened at a word boundary, after each blocking item id.
    """
    segments: list[str] = []

    if result.blocking_items:
        if text_width > 0:
            items = ", ".join(
                f"{item.id} ({shorten_text(item.text(lang), text_width)})"
                for item in result.blocking_items
            )
        else:
            items = ", ".join(item.id for item in result.blocking_items)
        segments.append(f"{t('blocking_label', lang)}: {items}")

    if result.blocking_skips:
        items = ", ".join(item.id for item in result.blocking_skips)
        segments.append(f"{t('strict_blocking_label', lang)}: {items}")
    elif result.skipped_items:
        items = ", ".join(item.id for item in result.skipped_items)
        segments.append(f"{t('skipped_label', lang)}: {items}")

    return segments


def print_assessment(
    console: Console,
    use_case: str,
    risk_class: str,
    scores: AssessmentScores,
    gate_results: dict[str, GateResult],
    skipped_ids: frozenset[str],
    lang: str,
    *,
    coverage: dict[str, object] | None = None,
    asserted: frozenset[str] = frozenset(),
) -> None:
    """Render the full assessment result to *console*.

    ``coverage`` (always shown when given) and ``asserted`` mark what the
    numbers rest on: how many affirmed items are evidence-backed or verified,
    and which self-attestations were recorded but not counted.
    """
    risk_label = t(RISK_LABEL_KEY[risk_class], lang)
    title = t("assessment_title", lang)
    risk_key = t("risk_label", lang)

    console.print(f"\n[bold]{title} — {use_case}[/bold]  [dim]\\[{risk_key}: {risk_label}][/dim]\n")

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
    console.print(f"  {'':>3}  {overall_label:<36} {overall_bar}  {scores.overall:5.1f} %")
    if coverage is not None:
        console.print(f"  {'':>3}  [dim]{_evidence_summary_line(coverage, lang)}[/dim]")
    if asserted:
        console.print(
            f"  {'':>3}  [yellow]{t('asserted_label', lang)}: {', '.join(sorted(asserted))}[/yellow]"
        )
    console.print()

    # ── Gate Readiness ───────────────────────────────────────────────────────
    console.print(f"[bold]{t('gates_header', lang)}[/bold]")

    for gate_id, result in sorted(gate_results.items()):
        colour = _STATUS_COLOUR[result.status]
        status_str = t(result.status.value, lang)
        line = f"  {gate_id}  [{colour}]{status_str}[/{colour}]"

        details = gate_detail_segments(result, lang, text_width=40)
        if details:
            line += "  — " + " · ".join(details)

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
    provenance: dict[str, str] | None = None,
    coverage: dict[str, object] | None = None,
    asserted: frozenset[str] = frozenset(),
    require_evidence: bool = False,
) -> str:
    """Return the assessment report as a Markdown string.

    The answers table always carries a provenance column and the score is
    followed by an evidence summary line, so a report never shows a number
    without saying what it rests on (v0.26.0 S-1).
    """
    safe_use_case = escape_markdown(use_case)
    if coverage is None:
        coverage = _default_coverage(affirmed, provenance, asserted, require_evidence)
    risk_label = t(RISK_LABEL_KEY[risk_class], lang)
    title = t("assessment_title", lang)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines: list[str] = [
        f"# {title} — {safe_use_case}",
        "",
        f"| {t('col_field', lang)} | {t('col_value', lang)} |",
        "|---|---|",
        f"| {t('col_use_case', lang)} | {safe_use_case} |",
        f"| {t('col_risk_class', lang)} | {risk_label} |",
        f"| {t('col_time', lang)} | {ts} |",
        f"| {t('col_tool_version', lang)} | {__version__} |",
        "",
        f"## {t('dimensions_header', lang)}",
        "",
        f"| {t('col_dimension', lang)} | {t('col_name', lang)} |"
        f" {t('col_score', lang)} | {t('col_bar', lang)} |",
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
        f"*{_evidence_summary_line(coverage, lang)}*",
    ]
    if asserted:
        lines.append(f"*{t('asserted_label', lang)}: {', '.join(sorted(asserted))}*")
    lines += [
        "",
        f"## {t('gates_header', lang)}",
        "",
        f"| {t('col_gate', lang)} | {t('col_status', lang)} | {t('col_blocking_skipped', lang)} |",
        "|---|---|---|",
    ]

    for gate_id, result in sorted(gate_results.items()):
        status_str = t(result.status.value, lang)
        detail = escape_for_report(" · ".join(gate_detail_segments(result, lang, text_width=60)))
        lines.append(f"| {gate_id} | {status_str} | {detail} |")

    # ── Per-Item Answers ─────────────────────────────────────────────────────
    lines += [
        "",
        f"## {t('answers_header', lang)}",
        "",
        f"| ID | {t('col_dimension', lang)} | {t('col_status', lang)} |"
        f" {t('col_provenance', lang)} | {t('col_item', lang)} |",
        "|---|---|---|---|---|",
    ]
    for row in item_answers(affirmed, skipped, lang, provenance, asserted):
        # Escape item text and neutralise table-breaking pipes before embedding.
        text = escape_for_report(str(row["text"])).replace("|", "\\|")
        prov = t(f"provenance_{row['provenance']}", lang) if "provenance" in row else "—"
        lines.append(
            f"| {row['id']} | {row['dimension']} | {row['status_label']} | {prov} | {text} |"
        )

    lines += [
        "",
        "---",
        "",
        f"*{t('report_disclaimer', lang)}*",
        "",
    ]

    return "\n".join(lines)


def build_payload(
    use_case: str,
    risk_class: str,
    scores: AssessmentScores,
    gate_results: dict[str, GateResult],
    affirmed: frozenset[str],
    skipped: frozenset[str],
    lang: str,
    provenance: dict[str, str] | None = None,
    coverage: dict[str, object] | None = None,
    asserted: frozenset[str] = frozenset(),
    require_evidence: bool = False,
) -> dict[str, object]:
    """Build the structured (JSON-serialisable) assessment payload.

    Shared by the CLI JSON report and the MCP server so both front-ends emit
    an identical schema. The use-case name is output-sanitised before inclusion.

    Since v0.26.0 every payload carries per-item ``provenance`` on affirmed and
    asserted rows, ``answers.asserted`` and an ``evidence_coverage`` block
    (with ``require_evidence`` and ``asserted_not_counted``), whatever flags
    produced it. Additive over the v0.13.0 schema: no key was removed or retyped.
    """
    safe_use_case = escape_for_report(use_case)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if coverage is None:
        coverage = _default_coverage(affirmed, provenance, asserted, require_evidence)

    payload: dict[str, object] = {
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
                "blocking_skips": [item.id for item in result.blocking_skips],
            }
            for gate_id, result in sorted(gate_results.items())
        },
        "answers": {
            "affirmed": sorted(affirmed),
            "asserted": sorted(asserted),
            "skipped": sorted(skipped),
            "items": item_answers(affirmed, skipped, lang, provenance, asserted),
        },
        "evidence_coverage": coverage,
        "disclaimer": t("report_disclaimer", lang),
    }
    return payload


def render_json(
    use_case: str,
    risk_class: str,
    scores: AssessmentScores,
    gate_results: dict[str, GateResult],
    affirmed: frozenset[str],
    skipped: frozenset[str],
    lang: str,
    provenance: dict[str, str] | None = None,
    coverage: dict[str, object] | None = None,
    asserted: frozenset[str] = frozenset(),
    require_evidence: bool = False,
) -> str:
    """Return the assessment report as a JSON string."""
    data = build_payload(
        use_case,
        risk_class,
        scores,
        gate_results,
        affirmed,
        skipped,
        lang,
        provenance,
        coverage,
        asserted,
        require_evidence,
    )
    return json.dumps(data, indent=2, ensure_ascii=False)


_ISO_COVERAGE_COLOUR = {
    Coverage.COVERED: "green",
    Coverage.PARTIAL: "yellow",
    Coverage.GAP: "red",
}


def print_iso_coverage(
    console: Console,
    use_case: str,
    risk_class: str,
    coverage: dict[str, ClauseCoverage],
    lang: str,
) -> None:
    """Render the ISO/IEC 42001 clause coverage analysis to *console*."""
    risk_label = t(RISK_LABEL_KEY[risk_class], lang)
    title = t("iso_gap_title", lang)
    risk_key = t("risk_label", lang)

    console.print(f"\n[bold]{title} — {use_case}[/bold]  [dim]\\[{risk_key}: {risk_label}][/dim]\n")

    for clause, cov in coverage.items():
        colour = _ISO_COVERAGE_COLOUR[cov.status]
        status_str = t(f"iso_{cov.status.value}", lang)
        name = t(f"iso_clause_{clause}", lang)
        line = (
            f"  {clause:<3} {name:<32} "
            f"[{colour}]{status_str:<9}[/{colour}]  ({cov.affirmed}/{cov.total})"
        )
        if cov.status is not Coverage.COVERED and cov.outstanding:
            ids = ", ".join(item.id for item in cov.outstanding)
            line += f"  — {t('iso_col_outstanding', lang)}: {ids}"
        console.print(line)

    console.print()


def build_iso_payload(
    use_case: str,
    risk_class: str,
    coverage: dict[str, ClauseCoverage],
    lang: str,
    evidence: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build the structured ISO/IEC 42001 coverage payload."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload: dict[str, object] = {
        "use_case": escape_for_report(use_case),
        "risk_class": risk_class,
        "lang": lang,
        "timestamp": ts,
        "tool_version": __version__,
        "iso_coverage": {
            clause: {
                "name": t(f"iso_clause_{clause}", lang),
                "status": cov.status.value,
                "total": cov.total,
                "affirmed": cov.affirmed,
                "outstanding": [item.id for item in cov.outstanding],
            }
            for clause, cov in coverage.items()
        },
        "disclaimer": t("report_disclaimer", lang),
    }
    if evidence is not None:
        payload["evidence"] = evidence
    return payload


def render_iso_json(
    use_case: str,
    risk_class: str,
    coverage: dict[str, ClauseCoverage],
    lang: str,
    evidence: dict[str, object] | None = None,
) -> str:
    """Return the ISO/IEC 42001 coverage analysis as a JSON string."""
    return json.dumps(
        build_iso_payload(use_case, risk_class, coverage, lang, evidence),
        indent=2,
        ensure_ascii=False,
    )


def print_saved_list(console: Console, assessments: list, lang: str) -> None:
    """Render the table of saved assessments to *console*."""
    if not assessments:
        console.print(f"[dim]{t('list_empty', lang)}[/dim]")
        return

    console.print(f"\n[bold]{t('saved_title', lang)}[/bold]\n")
    header = (
        f"  {t('col_use_case', lang):<24} {t('col_risk', lang):<8} "
        f"{t('col_overall', lang):>8}  {t('col_time', lang)}"
    )
    console.print(f"[dim]{header}[/dim]")
    for a in assessments:
        risk = t(RISK_LABEL_KEY.get(a.risk_class, "risk_medium"), lang)
        overall = float(a.scores.get("overall", 0.0))
        console.print(f"  {a.use_case[:24]:<24} {risk:<8} {overall:>6.1f} %  {a.timestamp}")
    console.print()


def render_saved_list_json(assessments: list) -> str:
    """Return the saved assessments as a JSON string (for ``--quiet``)."""
    data = [
        {
            "id": a.id,
            "use_case": escape_for_report(a.use_case),
            "risk_class": a.risk_class,
            "timestamp": a.timestamp,
            "lang": a.lang,
            "overall": a.scores.get("overall", 0.0),
            "scores": a.scores,
            "gates": a.gates,
            "answers": a.answers,
        }
        for a in assessments
    ]
    return json.dumps(data, indent=2, ensure_ascii=False)


def print_portfolio(console: Console, summary: dict, lang: str) -> None:
    """Render the aggregated portfolio view to *console*."""
    if summary["use_case_count"] == 0:
        console.print(f"[dim]{t('portfolio_empty', lang)}[/dim]")
        return

    console.print(f"\n[bold]{t('portfolio_title', lang)}[/bold]\n")
    console.print(f"  {t('portfolio_use_cases', lang, count=summary['use_case_count'])}\n")

    dimensions: dict = summary["dimensions"]
    for dim in sorted(dimensions):
        score = dimensions[dim]
        console.print(f"  {dim}  {t(dim, lang):<36} {_bar(score)}  {score:5.1f} %")

    console.rule(style="dim")
    overall = summary["overall"]
    console.print(f"  {'':>3}  {t('overall_label', lang):<36} {_bar(overall)}  {overall:5.1f} %\n")

    gates_blocked: dict = summary["gates_blocked"]
    if gates_blocked:
        console.print(f"[bold]{t('portfolio_blocked_gates', lang)}[/bold]")
        for gate in sorted(gates_blocked):
            console.print(f"  {gate}  ({gates_blocked[gate]})")
        console.print()


def render_portfolio_json(summary: dict, lang: str) -> str:
    """Return the portfolio summary as a JSON string (for ``--quiet``)."""
    return json.dumps({**summary, "lang": lang}, indent=2, ensure_ascii=False)


_TREND_SYMBOL = {"up": ("▲", "green"), "down": ("▼", "red"), "same": ("=", "dim")}


def print_trend(console: Console, result: TrendResult, lang: str) -> None:
    """Render a maturity-trend comparison between two assessments to *console*."""
    console.print(f"\n[bold]{t('trend_title', lang)} — {result.use_case}[/bold]")
    console.print(f"[dim]{result.earlier_timestamp}  →  {result.later_timestamp}[/dim]\n")

    for d in result.dimensions:
        sym, colour = _TREND_SYMBOL[d.direction]
        console.print(
            f"  {d.dimension}  {t(d.dimension, lang):<32} "
            f"{d.earlier:5.1f} → {d.later:5.1f}   [{colour}]{sym} {d.delta:+.1f}[/{colour}]"
        )

    console.rule(style="dim")
    overall_dir = (
        "up" if result.overall_delta > 0 else "down" if result.overall_delta < 0 else "same"
    )
    sym, colour = _TREND_SYMBOL[overall_dir]
    console.print(
        f"  {'':>3}  {t('trend_overall_delta', lang):<32} "
        f"{result.overall_earlier:5.1f} → {result.overall_later:5.1f}   "
        f"[{colour}]{sym} {result.overall_delta:+.1f}[/{colour}]\n"
    )

    console.print(f"[bold]{t('trend_gates_header', lang)}[/bold]")
    for tr in result.gate_transitions:
        earlier = t(tr.earlier_status, lang)
        later = t(tr.later_status, lang)
        if tr.changed:
            console.print(f"  {tr.gate}  [yellow]{earlier}  →  {later}[/yellow]")
        else:
            console.print(f"  [dim]{tr.gate}  {earlier}  →  {later}[/dim]")
    console.print()


def render_trend_json(result: TrendResult, lang: str) -> str:
    """Return the trend comparison as a JSON string (for ``--quiet``)."""
    data = {
        "use_case": escape_for_report(result.use_case),
        "lang": lang,
        "earlier_timestamp": result.earlier_timestamp,
        "later_timestamp": result.later_timestamp,
        "overall": {
            "earlier": result.overall_earlier,
            "later": result.overall_later,
            "delta": result.overall_delta,
        },
        "dimensions": [
            {
                "dimension": d.dimension,
                "earlier": d.earlier,
                "later": d.later,
                "delta": d.delta,
                "direction": d.direction,
            }
            for d in result.dimensions
        ],
        "gate_transitions": [
            {
                "gate": g.gate,
                "earlier": g.earlier_status,
                "later": g.later_status,
                "changed": g.changed,
            }
            for g in result.gate_transitions
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


_ARTICLE_STATUS_COLOUR = {"OPEN": "green", "PARTIAL": "yellow", "BLOCKED": "red"}


def print_euaiact(
    console: Console,
    use_case: str,
    risk_class: str,
    coverage: dict[str, ArticleCoverage],
    lang: str,
) -> None:
    """Render the EU AI Act high-risk article coverage to *console*."""
    risk_label = t(RISK_LABEL_KEY[risk_class], lang)
    title = t("euaiact_title", lang)
    risk_key = t("risk_label", lang)

    console.print(f"\n[bold]{title} — {use_case}[/bold]  [dim]\\[{risk_key}: {risk_label}][/dim]\n")

    for article, cov in coverage.items():
        colour = _ARTICLE_STATUS_COLOUR[cov.status]
        status_str = t(cov.status, lang)
        obligation = t(f"euaiact_art_{article}", lang)
        gates = ", ".join(g for g, _ in cov.gate_statuses)
        line = f"  Art. {article:<3} {obligation:<44} {gates:<14} [{colour}]{status_str}[/{colour}]"
        if cov.blocking:
            detail = ", ".join(f"{g} {t(s, lang)}" for g, s in cov.blocking)
            line += f"  — {detail}"
        console.print(line)

    console.print()


def build_euaiact_payload(
    use_case: str,
    risk_class: str,
    coverage: dict[str, ArticleCoverage],
    lang: str,
    evidence: dict[str, object] | None = None,
) -> dict[str, object]:
    """Build the structured EU AI Act coverage payload."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload: dict[str, object] = {
        "use_case": escape_for_report(use_case),
        "risk_class": risk_class,
        "lang": lang,
        "timestamp": ts,
        "tool_version": __version__,
        "articles": {
            article: {
                "obligation": t(f"euaiact_art_{article}", lang),
                "status": cov.status,
                "gates": [g for g, _ in cov.gate_statuses],
                "gate_statuses": {g: s for g, s in cov.gate_statuses},
                "blocking": {g: s for g, s in cov.blocking},
            }
            for article, cov in coverage.items()
        },
        "disclaimer": t("report_disclaimer", lang),
    }
    if evidence is not None:
        payload["evidence"] = evidence
    return payload


def render_euaiact_json(
    use_case: str,
    risk_class: str,
    coverage: dict[str, ArticleCoverage],
    lang: str,
    evidence: dict[str, object] | None = None,
) -> str:
    """Return the EU AI Act coverage analysis as a JSON string."""
    return json.dumps(
        build_euaiact_payload(use_case, risk_class, coverage, lang, evidence),
        indent=2,
        ensure_ascii=False,
    )


def render_gate_json(
    result: GateResult,
    risk_class: str,
    strict: bool,
    lang: str,
    evidence: dict[str, object] | None = None,
) -> str:
    """Return a single gate-readiness result as a JSON string (for ``--quiet``).

    ``evidence`` (v0.26.0) is the shared marking block: which of the gate's
    items were verified, evidence-backed, self-attested, or asserted-not-counted.
    """
    data: dict[str, object] = {
        "gate": result.gate,
        "status": result.status.value,
        "risk_class": risk_class,
        "strict": strict or risk_class == "high",
        "lang": lang,
        "blocking": [item.id for item in result.blocking_items],
        "skipped": [item.id for item in result.skipped_items],
        "blocking_skips": [item.id for item in result.blocking_skips],
    }
    if evidence is not None:
        data["evidence"] = evidence
    return json.dumps(data, indent=2, ensure_ascii=False)
