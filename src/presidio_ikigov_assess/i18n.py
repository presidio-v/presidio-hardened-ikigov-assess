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
    # ── Per-item answers (report export, v0.4.0) ─────────────────────────────
    "answers_header": {
        "de": "Antworten je Element",
        "en": "Per-Item Answers",
    },
    "answer_affirmed": {"de": "bestätigt", "en": "affirmed"},
    "answer_denied": {"de": "nicht bestätigt", "en": "not affirmed"},
    "answer_skipped": {"de": "übersprungen", "en": "skipped"},
    "col_item": {"de": "Element", "en": "Item"},
    "col_status": {"de": "Status", "en": "Status"},
    "col_dimension": {"de": "Dimension", "en": "Dimension"},
    "report_written": {
        "de": "Bericht geschrieben nach: {path}",
        "en": "Report written to: {path}",
    },
    # ── ISO/IEC 42001 gap mapping (v0.5.0) ───────────────────────────────────
    "iso_gap_title": {
        "de": "ISO/IEC 42001 Abdeckungsanalyse",
        "en": "ISO/IEC 42001 Coverage Gap Analysis",
    },
    "iso_covered": {"de": "ABGEDECKT", "en": "COVERED"},
    "iso_partial": {"de": "TEILWEISE", "en": "PARTIAL"},
    "iso_gap": {"de": "LÜCKE", "en": "GAP"},
    "iso_col_clause": {"de": "Abschnitt", "en": "Clause"},
    "iso_col_coverage": {"de": "Abdeckung", "en": "Coverage"},
    "iso_col_outstanding": {"de": "Offene Elemente", "en": "Outstanding items"},
    "iso_suggestion": {
        "de": "Empfehlung: folgende Elemente bestätigen",
        "en": "Suggestion: affirm the following items",
    },
    "iso_clause_4": {
        "de": "Kontext der Organisation",
        "en": "Context of the organization",
    },
    "iso_clause_5": {"de": "Führung", "en": "Leadership"},
    "iso_clause_6": {"de": "Planung", "en": "Planning"},
    "iso_clause_7": {"de": "Unterstützung", "en": "Support"},
    "iso_clause_8": {"de": "Betrieb", "en": "Operation"},
    "iso_clause_9": {"de": "Bewertung der Leistung", "en": "Performance evaluation"},
    "iso_clause_10": {"de": "Verbesserung", "en": "Improvement"},
    "iso_clause_A": {"de": "Anhang A (Kontrollen)", "en": "Annex A (Controls)"},
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
    "dep_check_inconclusive": {
        "de": "Warnung: Abhängigkeitsprüfung ergebnislos (Zeitlimit/Fehler). "
        "Kein sauberes Ergebnis — bitte pip-audit manuell ausführen.",
        "en": "Warning: dependency check inconclusive (timeout/error). "
        "Not a clean result — run pip-audit manually to confirm.",
    },
    "output_is_symlink": {
        "de": "Ausgabepfad ist ein symbolischer Link; Schreiben abgelehnt: '{path}'.",
        "en": "Output path is a symbolic link; refusing to write: '{path}'.",
    },
    "rate_limit_exceeded": {
        "de": "Sitzungslimit erreicht. Maximal {limit} Bewertungen pro Sitzung erlaubt.",
        "en": "Session limit reached. Maximum {limit} assessments per session allowed.",
    },
    "list_empty": {
        "de": "Keine gespeicherten Bewertungen vorhanden. Mit 'iga assess --save' speichern.",
        "en": "No saved assessments yet. Save one with 'iga assess --save'.",
    },
    # ── Persistence / portfolio (v0.6.0) ─────────────────────────────────────
    "saved_title": {"de": "Gespeicherte Bewertungen", "en": "Saved Assessments"},
    "col_use_case": {"de": "Anwendungsfall", "en": "Use Case"},
    "col_risk": {"de": "Risiko", "en": "Risk"},
    "col_overall": {"de": "Gesamt", "en": "Overall"},
    "col_time": {"de": "Zeitstempel", "en": "Timestamp"},
    "assessment_saved": {
        "de": "Bewertung für '{use_case}' gespeichert.",
        "en": "Assessment saved for '{use_case}'.",
    },
    "delete_done": {
        "de": "{count} Bewertung(en) für '{use_case}' gelöscht.",
        "en": "Deleted {count} assessment(s) for '{use_case}'.",
    },
    "delete_none": {
        "de": "Keine Bewertungen für '{use_case}' gefunden.",
        "en": "No assessments found for '{use_case}'.",
    },
    "portfolio_title": {"de": "Portfolio-Übersicht", "en": "Portfolio Overview"},
    "portfolio_use_cases": {
        "de": "Bewertete Anwendungsfälle: {count}",
        "en": "Use cases assessed: {count}",
    },
    "portfolio_blocked_gates": {
        "de": "Blockierte Gates im Portfolio",
        "en": "Blocked gates across portfolio",
    },
    "portfolio_empty": {
        "de": "Keine gespeicherten Bewertungen — nichts zu aggregieren.",
        "en": "No saved assessments — nothing to aggregate.",
    },
    # ── Maturity trend (v0.7.0) ──────────────────────────────────────────────
    "trend_title": {"de": "Reifegrad-Trend", "en": "Maturity Trend"},
    "trend_insufficient": {
        "de": "Mindestens zwei gespeicherte Bewertungen für '{use_case}' erforderlich.",
        "en": "At least two saved assessments are required for '{use_case}'.",
    },
    "trend_gates_header": {"de": "Gate-Übergänge", "en": "Gate Transitions"},
    "trend_overall_delta": {"de": "Veränderung Gesamtreife", "en": "Overall maturity change"},
    # ── EU AI Act gate-to-article mapping (v0.8.0) ───────────────────────────
    "euaiact_title": {
        "de": "EU-KI-VO Hochrisiko-Compliance-Lücke",
        "en": "EU AI Act High-Risk Compliance Gap",
    },
    "euaiact_high_risk_only": {
        "de": (
            "EU-KI-VO-Pflichten gelten nur für Hochrisiko-Systeme. "
            "Bitte mit '--risk-class high' aufrufen."
        ),
        "en": (
            "EU AI Act obligations apply only to high-risk systems. "
            "Re-run with '--risk-class high'."
        ),
    },
    "euaiact_col_article": {"de": "Artikel", "en": "Article"},
    "euaiact_col_obligation": {"de": "Pflicht", "en": "Obligation"},
    "euaiact_col_gates": {"de": "Gates", "en": "Gates"},
    "euaiact_col_status": {"de": "Status", "en": "Status"},
    "euaiact_art_9": {"de": "Risikomanagementsystem", "en": "Risk management system"},
    "euaiact_art_10": {"de": "Daten und Daten-Governance", "en": "Data and data governance"},
    "euaiact_art_11": {"de": "Technische Dokumentation", "en": "Technical documentation"},
    "euaiact_art_12": {
        "de": "Aufzeichnungspflichten (Protokollierung)",
        "en": "Record-keeping (logging)",
    },
    "euaiact_art_13": {
        "de": "Transparenz und Bereitstellung von Informationen",
        "en": "Transparency and information to deployers",
    },
    "euaiact_art_14": {"de": "Menschliche Aufsicht", "en": "Human oversight"},
    "euaiact_art_15": {
        "de": "Genauigkeit, Robustheit und Cybersicherheit",
        "en": "Accuracy, robustness and cybersecurity",
    },
    "euaiact_art_17": {"de": "Qualitätsmanagementsystem", "en": "Quality management system"},
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
    # ── Classificator bridge (v0.20.0) ────────────────────────────────────────
    "classify_ingest_title": {
        "de": "EAI-Klassifikation — Ergebnisse",
        "en": "EAI Classification — Ingest Results",
    },
    "classify_col_id": {"de": "Anwendungsfall-ID", "en": "Use-Case ID"},
    "classify_col_cell": {"de": "Zelle", "en": "Cell"},
    "classify_col_risk": {"de": "Risikovermutung", "en": "Risk Presumption"},
    "classify_col_strict": {"de": "Strikt", "en": "Strict"},
    "classify_col_obligations": {"de": "Pflichten", "en": "Obligations"},
    "classify_col_note": {"de": "Hinweis", "en": "Note"},
    "classify_err_file": {
        "de": "Klassifikationsdatei konnte nicht gelesen werden: {path}",
        "en": "Cannot read classification file: {path}",
    },
    "classify_err_parse": {
        "de": "Klassifikationsdokument ungültig: {detail}",
        "en": "Invalid classification document: {detail}",
    },
    "classify_err_use_case_not_found": {
        "de": "Anwendungsfall-ID '{id}' nicht im Klassifikationsdokument gefunden.",
        "en": "Use-case id '{id}' not found in the classification document.",
    },
    "classify_err_no_profile": {
        "de": "Kein Profil-Pack verfügbar (Framework: '{fid}').",
        "en": "No profile pack available (framework: '{fid}').",
    },
    "classify_assess_event": {
        "de": "iga-classify-assess",
        "en": "iga-classify-assess",
    },
    "classify_profile_strict_locked": {
        "de": "Profilpflicht: 'strict=true' — kann nicht durch Flags aufgehoben werden.",
        "en": "Profile mandates strict=true — cannot be overridden by flags.",
    },
    "classify_risk_low": {"de": "niedrig", "en": "low"},
    "classify_risk_medium": {"de": "mittel", "en": "medium"},
    "classify_risk_high": {"de": "hoch", "en": "high"},
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
