"""Bilingual (de/en) UI strings for the IKI-Gov Assessment Tool."""

from __future__ import annotations

STRINGS: dict[str, dict[str, str]] = {
    # ── Dimensions ───────────────────────────────────────────────────────────
    "M1": {
        "de": "Strategie & Ownership",
        "en": "Strategie & Ownership",
    },
    "M2": {
        "de": "Datenqualität & Lineage",
        "en": "Data Quality & Lineage",
    },
    "M3": {
        "de": "Validierung & Fairness",
        "en": "Validation & Fairness",
    },
    "M4": {
        "de": "Sicherheit & Robustheit",
        "en": "Security & Robustness",
    },
    "M5": {
        "de": "Compliance-Nachweise",
        "en": "Compliance Evidence",
    },
    "M6": {
        "de": "Betrieb, Drift & Vorfälle",
        "en": "Operations, Drift & Incidents",
    },
    # ── Sections ─────────────────────────────────────────────────────────────
    "section_S": {
        "de": "Strategie & Geschäftsfall",
        "en": "Strategy & Business Case",
    },
    "section_D": {
        "de": "Daten, Recht & Ethik",
        "en": "Data, Law & Ethics",
    },
    "section_T": {
        "de": "Modell, Sicherheit & Technik",
        "en": "Model, Security & Technology",
    },
    "section_O": {
        "de": "Betrieb, Monitoring & Aufsicht",
        "en": "Operations, Monitoring & Oversight",
    },
    "section_I": {
        "de": "ISO/IEC 42001 Abgleich",
        "en": "ISO/IEC 42001 Alignment",
    },
    # ── Gate status ──────────────────────────────────────────────────────────
    "OPEN": {"de": "OFFEN", "en": "OPEN"},
    "PARTIAL": {"de": "TEILWEISE", "en": "PARTIAL"},
    "BLOCKED": {"de": "BLOCKIERT", "en": "BLOCKED"},
    # ── Gate lifecycle transitions ───────────────────────────────────────────
    "gate_G0": {"de": "Kontext → Konzeption", "en": "Context → Conception"},
    "gate_G1": {"de": "Konzeption → Entwicklung", "en": "Conception → Development"},
    "gate_G2": {"de": "Entwicklung → Freigabe", "en": "Development → Release"},
    "gate_G3": {"de": "Freigabe → Betrieb", "en": "Release → Operation"},
    "gate_G4": {"de": "Betrieb → Anpassung", "en": "Operation → Adaptation"},
    "gate_G5": {
        "de": "Anpassung → Außerbetriebnahme",
        "en": "Adaptation → Decommissioning",
    },
    # ── Risk classes ─────────────────────────────────────────────────────────
    "risk_low": {"de": "NIEDRIG", "en": "LOW"},
    "risk_medium": {"de": "MITTEL", "en": "MEDIUM"},
    "risk_high": {"de": "HOCH", "en": "HIGH"},
    # ── Assessment output labels ─────────────────────────────────────────────
    "assessment_title": {
        "de": "IKI-Gov Bewertung",
        "en": "IKI-Gov Assessment",
    },
    "risk_label": {"de": "Risiko", "en": "risk"},
    "dimensions_header": {
        "de": "Messdimensionen",
        "en": "Measurement Dimensions",
    },
    "overall_label": {
        "de": "Gesamtreife",
        "en": "Overall maturity",
    },
    "gates_header": {
        "de": "Gate-Bereitschaft",
        "en": "Gate Readiness",
    },
    "blocking_label": {
        "de": "blockierend",
        "en": "blocking",
    },
    "skipped_label": {
        "de": "übersprungen",
        "en": "skipped",
    },
    "strict_blocking_label": {
        "de": "blockierend (Skips nicht erlaubt)",
        "en": "blocking (skips not permitted)",
    },
    "no_items_affirmed": {
        "de": "Keine Elemente bestätigt.",
        "en": "No items affirmed.",
    },
    # ── Interactive wizard ───────────────────────────────────────────────────
    "wizard_welcome": {
        "de": (
            "IKI-Gov Bewertungs-Assistent\n"
            "Beantworten Sie jede Frage mit J (Ja) / N (Nein) / Ü (Überspringen) / ? (Hilfe)."
        ),
        "en": (
            "IKI-Gov Assessment Wizard\n"
            "Answer each question with Y (Yes) / N (No) / S (Skip) / ? (Help)."
        ),
    },
    "wizard_prompt": {
        "de": "  → J / N / Ü / ? : ",
        "en": "  → Y / N / S / ? : ",
    },
    "wizard_help_prefix": {
        "de": "  Hilfe: ",
        "en": "  Help : ",
    },
    "wizard_invalid": {
        "de": "  Ungültige Eingabe. Bitte J, N, Ü oder ? eingeben.",
        "en": "  Invalid input. Please enter Y, N, S, or ?.",
    },
    "wizard_progress": {
        "de": "Element {current}/{total} — Abschnitt: {section}",
        "en": "Item {current}/{total} — Section: {section}",
    },
    "wizard_summary": {
        "de": "Bewertung abgeschlossen. {affirmed} bestätigt · {denied} abgelehnt · {skipped} übersprungen",
        "en": "Assessment complete. {affirmed} affirmed · {denied} denied · {skipped} skipped",
    },
    # ── CLI messages ─────────────────────────────────────────────────────────
    "dep_check_start": {
        "de": "Abhängigkeitsprüfung läuft…",
        "en": "Running dependency check…",
    },
    "dep_check_ok": {
        "de": "Keine bekannten Schwachstellen gefunden.",
        "en": "No known vulnerabilities found.",
    },
    "dep_check_warn": {
        "de": "Warnung: Abhängigkeitsprüfung ergab Befunde. Bitte pip-audit-Ausgabe prüfen.",
        "en": "Warning: dependency check reported findings. Review pip-audit output.",
    },
    "dep_check_unavailable": {
        "de": "Hinweis: pip-audit nicht installiert. Abhängigkeitsprüfung übersprungen.",
        "en": "Note: pip-audit not installed. Dependency check skipped.",
    },
    "dep_check_timeout": {
        "de": "Hinweis: Abhängigkeitsprüfung hat das Zeitlimit überschritten.",
        "en": "Note: Dependency check timed out.",
    },
    "rate_limit_exceeded": {
        "de": "Sitzungslimit erreicht. Maximal {limit} Bewertungen pro Sitzung erlaubt.",
        "en": "Session limit reached. Maximum {limit} assessments per session allowed.",
    },
    "list_empty": {
        "de": (
            "Keine gespeicherten Bewertungen vorhanden.\n"
            "(Persistenz wird in Version 0.6.0 hinzugefügt.)"
        ),
        "en": ("No saved assessments found.\n(Persistence is added in version 0.6.0.)"),
    },
    "report_disclaimer": {
        "de": (
            "Erstellt mit dem IKI-Gov Assessment Tool. "
            "Stellt keine Rechtsberatung oder Zertifizierung dar."
        ),
        "en": (
            "Generated by the IKI-Gov Assessment Tool. "
            "Does not constitute legal advice or certification."
        ),
    },
    "gate_assert_fail": {
        "de": "Gate {gate} ist nicht OFFEN (Status: {status}). Build schlägt fehl.",
        "en": "Gate {gate} is not OPEN (status: {status}). Build fails.",
    },
    "gate_assert_pass": {
        "de": "Gate {gate} ist OFFEN.",
        "en": "Gate {gate} is OPEN.",
    },
    "err_invalid_use_case": {
        "de": "Ungültiger Anwendungsfall-Name: '{value}'. Nur alphanumerische Zeichen, Bindestriche und Unterstriche erlaubt (max. 128 Zeichen).",
        "en": "Invalid use-case name: '{value}'. Only alphanumeric characters, hyphens, and underscores are allowed (max 128 chars).",
    },
    "err_invalid_risk_class": {
        "de": "Ungültige Risikoklasse: '{value}'. Erlaubt: low, medium, high.",
        "en": "Invalid risk class: '{value}'. Allowed: low, medium, high.",
    },
    "err_invalid_gate": {
        "de": "Ungültiges Gate: '{value}'. Erlaubt: G0–G5.",
        "en": "Invalid gate: '{value}'. Allowed: G0–G5.",
    },
    "err_invalid_item_id": {
        "de": "Unbekannte Checklisten-ID: '{value}'.",
        "en": "Unknown checklist item ID: '{value}'.",
    },
    "err_invalid_lang": {
        "de": "Ungültige Sprache: '{value}'. Erlaubt: de, en.",
        "en": "Invalid language: '{value}'. Allowed: de, en.",
    },
}

SECTION_FOR_PREFIX: dict[str, str] = {
    "S": "section_S",
    "D": "section_D",
    "T": "section_T",
    "O": "section_O",
    "I": "section_I",
}

RISK_LABEL_KEY: dict[str, str] = {
    "low": "risk_low",
    "medium": "risk_medium",
    "high": "risk_high",
}


def t(key: str, lang: str, **kwargs: object) -> str:
    """Return the translated string for *key* in *lang*, formatted with **kwargs."""
    entry = STRINGS.get(key, {})
    text = entry.get(lang) or entry.get("en") or key
    if kwargs:
        return text.format(**kwargs)
    return text


def section_name(item_id: str, lang: str) -> str:
    prefix = item_id[0]
    key = SECTION_FOR_PREFIX.get(prefix, "")
    return t(key, lang)
