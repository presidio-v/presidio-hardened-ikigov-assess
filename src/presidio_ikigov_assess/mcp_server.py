"""Model Context Protocol (MCP) server for the IKI-Gov Assessment Tool.

Exposes the assessment engine as MCP tools so that LLM agents and MCP-capable
clients can assess AI use cases against the IKI-Gov reference model, inspect the
checklist, and check lifecycle-gate readiness — the same engine the ``iga`` CLI
drives, behind a structured tool interface.

The server is a thin front-end: validation (``sanitize``), scoring (``scoring``),
gate logic (``gates``) and the structured payload (``renderer.build_payload``) are
all reused unchanged. Each tool returns a JSON-serialisable dict.

Run it over stdio::

    iga-mcp

Requires the optional ``mcp`` extra (Python 3.10+)::

    pip install "presidio-hardened-ikigov-assess[mcp]"

The pure helper functions below (``framework_info``, ``list_items``, ``assess``,
``gate_status``) carry no dependency on the ``mcp`` package and are unit-tested
directly; only ``build_server``/``main`` import FastMCP.
"""

from __future__ import annotations

from typing import Optional

from presidio_ikigov_assess import __version__
from presidio_ikigov_assess.checklist import (
    CHECKLIST,
    VALID_DIMENSIONS,
    VALID_GATES,
    VALID_RISK_CLASSES,
)
from presidio_ikigov_assess.gates import evaluate_all_gates, evaluate_gate
from presidio_ikigov_assess.i18n import (
    RISK_LABEL_KEY,
    SECTION_FOR_PREFIX,
    section_name,
    t,
)
from presidio_ikigov_assess.iso import evaluate_iso_coverage
from presidio_ikigov_assess.renderer import build_iso_payload, build_payload
from presidio_ikigov_assess.sanitize import (
    ValidationError,
    validate_gate,
    validate_item_ids,
    validate_lang,
    validate_risk_class,
    validate_use_case,
)
from presidio_ikigov_assess.scoring import compute_scores
from presidio_ikigov_assess.security import (
    increment_session_count,
    log_security_event,
    session_limit,
)

# Lifecycle phases are presentation metadata specific to the framework overview.
_LIFECYCLE_PHASES: dict[str, list[str]] = {
    "de": [
        "Kontext",
        "Konzeption",
        "Entwicklung",
        "Freigabe",
        "Betrieb",
        "Anpassung",
        "Außerbetriebnahme",
    ],
    "en": [
        "Context",
        "Conception",
        "Development",
        "Release",
        "Operation",
        "Adaptation",
        "Decommissioning",
    ],
}

_SERVER_INSTRUCTIONS = (
    "IKI-Gov Assessment tools. Use `iga_framework_info` to learn the model "
    "(dimensions M1–M6, gates G0–G5, sections, risk classes), `iga_list_checklist` "
    "to retrieve the 25 checklist items with their IDs, then `iga_assess` with the "
    "IDs the organisation affirms (and optionally skips) to obtain M1–M6 maturity "
    "scores and gate readiness. Use `iga_check_gate` to evaluate a single gate, and "
    "`iga_iso_gap` for ISO/IEC 42001 clause-level coverage. Risk class is one of "
    "low|medium|high; language is de|en. This tool does not constitute legal advice "
    "or certification."
)


class ToolInputError(ValueError):
    """Raised when an MCP tool receives invalid input.

    A ``ValueError`` subclass so FastMCP surfaces it to the client as a tool
    error rather than crashing the server.
    """


def _prepare_answers(
    affirmed: Optional[list[str]],
    skipped: Optional[list[str]],
) -> tuple[frozenset[str], frozenset[str]]:
    """Validate and normalise affirmed/skipped item-ID lists.

    Reuses the CLI validator (membership, casing, length bounds) by joining the
    lists into the comma form it expects, then rejects any ID claimed as both
    affirmed and skipped.
    """
    try:
        affirm_ids = frozenset(validate_item_ids(",".join(affirmed or [])))
        skip_ids = frozenset(validate_item_ids(",".join(skipped or [])))
    except ValidationError as exc:
        raise ToolInputError(str(exc)) from exc

    overlap = affirm_ids & skip_ids
    if overlap:
        raise ToolInputError(
            f"Item IDs appear in both affirmed and skipped: {', '.join(sorted(overlap))}"
        )
    return affirm_ids, skip_ids


def _guard_session() -> None:
    """Apply the per-session abuse guard without terminating the server."""
    if increment_session_count() > session_limit():
        raise ToolInputError(
            f"Session limit reached ({session_limit()} assessments). "
            "Restart the server to reset the counter."
        )


def _validated(value: str, validator) -> str:
    try:
        return validator(value)
    except ValidationError as exc:
        raise ToolInputError(str(exc)) from exc


# ── Pure tool logic (no MCP dependency; unit-tested directly) ────────────────


def framework_info(lang: str = "en") -> dict:
    """Return the structure of the IKI-Gov reference model in the given language."""
    lang = _validated(lang, validate_lang)
    return {
        "framework": "IKI-Gov — Integrated KI-Governance Reference Model",
        "lang": lang,
        "lifecycle_phases": _LIFECYCLE_PHASES.get(lang, _LIFECYCLE_PHASES["en"]),
        "dimensions": {dim: t(dim, lang) for dim in sorted(VALID_DIMENSIONS)},
        "gates": {g: t(f"gate_{g}", lang) for g in sorted(VALID_GATES)},
        "sections": {prefix: t(key, lang) for prefix, key in SECTION_FOR_PREFIX.items()},
        "risk_classes": {rc: t(RISK_LABEL_KEY[rc], lang) for rc in sorted(VALID_RISK_CLASSES)},
        "tool_version": __version__,
    }


def list_items(lang: str = "en") -> dict:
    """Return all 25 checklist items with IDs, text, dimension, gates and section."""
    lang = _validated(lang, validate_lang)
    items = [
        {
            "id": item.id,
            "text": item.text(lang),
            "dimension": item.m_dimension,
            "dimension_name": t(item.m_dimension, lang),
            "gates": list(item.gates),
            "section": section_name(item.id, lang),
        }
        for item in CHECKLIST
    ]
    return {"items": items, "count": len(items), "lang": lang}


def assess(
    affirmed: Optional[list[str]] = None,
    skipped: Optional[list[str]] = None,
    risk_class: str = "medium",
    lang: str = "en",
    use_case: str = "unnamed",
    strict: bool = False,
) -> dict:
    """Run a full assessment and return scores, gate readiness and metadata."""
    lang = _validated(lang, validate_lang)
    risk_class = _validated(risk_class, validate_risk_class)
    use_case = _validated(use_case, validate_use_case)
    affirm_ids, skip_ids = _prepare_answers(affirmed, skipped)
    _guard_session()

    scores = compute_scores(affirm_ids, skip_ids, risk_class)
    gate_results = evaluate_all_gates(affirm_ids, skip_ids, risk_class, strict)
    payload = build_payload(use_case, risk_class, scores, gate_results, affirm_ids, skip_ids, lang)

    gates_open = [g for g, r in gate_results.items() if r.status.value == "OPEN"]
    log_security_event(
        {
            "event": "iga-mcp-assessment-complete",
            "risk_class": risk_class,
            "gates_open": gates_open,
            "lang": lang,
            "overall_score": scores.overall,
        }
    )
    return payload


def gate_status(
    gate: str,
    affirmed: Optional[list[str]] = None,
    skipped: Optional[list[str]] = None,
    risk_class: str = "medium",
    lang: str = "en",
    strict: bool = False,
) -> dict:
    """Evaluate readiness for a single IKI-Gov lifecycle gate (G0–G5)."""
    lang = _validated(lang, validate_lang)
    gate = _validated(gate, validate_gate)
    risk_class = _validated(risk_class, validate_risk_class)
    affirm_ids, skip_ids = _prepare_answers(affirmed, skipped)

    result = evaluate_gate(gate, affirm_ids, skip_ids, risk_class, strict)
    log_security_event(
        {
            "event": "iga-mcp-gate-check",
            "gate": gate,
            "status": result.status.value,
            "risk_class": risk_class,
            "strict": strict or risk_class == "high",
            "lang": lang,
        }
    )
    return {
        "gate": gate,
        "transition": t(f"gate_{gate}", lang),
        "status": result.status.value,
        "status_label": t(result.status.value, lang),
        "blocking": [{"id": item.id, "text": item.text(lang)} for item in result.blocking_items],
        "skipped": [{"id": item.id, "text": item.text(lang)} for item in result.skipped_items],
        "blocking_skips": [
            {"id": item.id, "text": item.text(lang)} for item in result.blocking_skips
        ],
        "risk_class": risk_class,
        "strict": strict or risk_class == "high",
        "lang": lang,
    }


def iso_gap(
    affirmed: Optional[list[str]] = None,
    skipped: Optional[list[str]] = None,
    risk_class: str = "medium",
    lang: str = "en",
    use_case: str = "unnamed",
) -> dict:
    """Map affirmed items to ISO/IEC 42001 clause-level coverage."""
    lang = _validated(lang, validate_lang)
    risk_class = _validated(risk_class, validate_risk_class)
    use_case = _validated(use_case, validate_use_case)
    affirm_ids, _skip_ids = _prepare_answers(affirmed, skipped)

    coverage = evaluate_iso_coverage(affirm_ids)
    gaps = [clause for clause, cov in coverage.items() if cov.status.value != "covered"]
    log_security_event(
        {
            "event": "iga-mcp-iso-gap",
            "risk_class": risk_class,
            "lang": lang,
            "gaps": gaps,
        }
    )
    return build_iso_payload(use_case, risk_class, coverage, lang)


# ── FastMCP server wiring ────────────────────────────────────────────────────


def build_server():
    """Construct and return the FastMCP server with all IKI-Gov tools registered.

    Imports FastMCP lazily so the pure logic above (and its tests) do not require
    the optional ``mcp`` dependency.
    """
    from mcp.server.fastmcp import FastMCP

    server = FastMCP("iki-gov-assess", instructions=_SERVER_INSTRUCTIONS)

    @server.tool()
    def iga_framework_info(lang: str = "en") -> dict:
        """Describe the IKI-Gov reference model.

        Returns the lifecycle phases, measurement dimensions (M1–M6), lifecycle
        gates (G0–G5) with their transitions, checklist sections, and risk
        classes — all localised to ``lang`` (de|en). Call this first to learn
        the vocabulary used by the other tools.
        """
        return framework_info(lang)

    @server.tool()
    def iga_list_checklist(lang: str = "en") -> dict:
        """List the 25 IKI-Gov checklist items.

        Each item carries its ID (e.g. ``S1``, ``D3``, ``T4``), the question
        text in ``lang`` (de|en), its primary M-dimension, the gates it gates,
        and its section. Use the returned IDs as the ``affirmed``/``skipped``
        arguments to ``iga_assess`` and ``iga_check_gate``.
        """
        return list_items(lang)

    @server.tool()
    def iga_assess(
        affirmed: Optional[list[str]] = None,
        skipped: Optional[list[str]] = None,
        risk_class: str = "medium",
        lang: str = "en",
        use_case: str = "unnamed",
        strict: bool = False,
    ) -> dict:
        """Assess an AI use case against the IKI-Gov checklist.

        ``affirmed`` is the list of checklist item IDs the organisation can
        evidence (e.g. ``["S1", "S2", "D1"]``); ``skipped`` lists IDs marked
        not-applicable (excluded from scoring). Any item neither affirmed nor
        skipped counts as denied. ``risk_class`` is low|medium|high and scales
        item weights; ``lang`` is de|en. ``strict`` (implied at high risk) makes
        skipped gate-critical items block their gate. Returns per-dimension
        M1–M6 scores, overall maturity, and gate readiness, where a gate is
        OPEN/PARTIAL/BLOCKED under the active risk policy.
        """
        return assess(affirmed, skipped, risk_class, lang, use_case, strict)

    @server.tool()
    def iga_check_gate(
        gate: str,
        affirmed: Optional[list[str]] = None,
        skipped: Optional[list[str]] = None,
        risk_class: str = "medium",
        lang: str = "en",
        strict: bool = False,
    ) -> dict:
        """Check readiness for one IKI-Gov lifecycle gate (``gate``: G0–G5).

        Returns the gate's transition label and status under the active risk
        policy: OPEN (every mapped item affirmed; at low risk, skips are
        forgiven), PARTIAL (only gaps are skips, at medium risk), or BLOCKED
        (any mapped item denied, or — under ``strict``/high risk — skipped).
        ``blocking_skips`` lists skips that block the gate under strict policy.
        """
        return gate_status(gate, affirmed, skipped, risk_class, lang, strict)

    @server.tool()
    def iga_iso_gap(
        affirmed: Optional[list[str]] = None,
        skipped: Optional[list[str]] = None,
        risk_class: str = "medium",
        lang: str = "en",
        use_case: str = "unnamed",
    ) -> dict:
        """Map an assessment to ISO/IEC 42001 clause-level coverage.

        Returns each ISO/IEC 42001 clause group (4–10 + Annex A) as covered /
        partial / gap based on the affirmed checklist items, with the count of
        affirmed-vs-total mapped items and the outstanding item IDs per clause.
        Skipped and denied items count as not affirmed (no coverage credit).
        """
        return iso_gap(affirmed, skipped, risk_class, lang, use_case)

    return server


def main() -> None:
    """Entry point for the ``iga-mcp`` console script: run the server over stdio."""
    build_server().run()


if __name__ == "__main__":
    main()
