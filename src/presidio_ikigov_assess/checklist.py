"""25-item IKI-Gov checklist drawn from the five appendix sections of the framework.

Sections and primary M-dimension mapping:
  S1–S5  Strategie & Geschäftsfall          → M1 (Strategie & Ownership)
  D1–D5  Daten, Recht & Ethik               → M2 (Datenqualität & Lineage)
  T1–T3  Modell, Sicherheit & Technik       → M3 (Validierung & Fairness)
  T4–T5  Modell, Sicherheit & Technik       → M4 (Sicherheit & Robustheit)
  O1–O5  Betrieb, Monitoring & Aufsicht     → M6 (Betrieb, Drift & Vorfälle)
  I1–I5  ISO/IEC 42001 Abgleich             → M5 (Compliance-Nachweise)

Gate mapping follows the IKI-Gov lifecycle:
  G0  Kontext → Konzeption
  G1  Konzeption → Entwicklung
  G2  Entwicklung → Freigabe
  G3  Freigabe → Betrieb
  G4  Betrieb → Anpassung
  G5  Anpassung → Außerbetriebnahme
"""

from __future__ import annotations

from dataclasses import dataclass, field

VALID_ITEM_IDS = {
    "S1",
    "S2",
    "S3",
    "S4",
    "S5",
    "D1",
    "D2",
    "D3",
    "D4",
    "D5",
    "T1",
    "T2",
    "T3",
    "T4",
    "T5",
    "O1",
    "O2",
    "O3",
    "O4",
    "O5",
    "I1",
    "I2",
    "I3",
    "I4",
    "I5",
}

VALID_DIMENSIONS = {"M1", "M2", "M3", "M4", "M5", "M6"}
VALID_GATES = {"G0", "G1", "G2", "G3", "G4", "G5"}
VALID_RISK_CLASSES = {"low", "medium", "high"}

# ISO/IEC 42001 clause groups (clauses 4–10 + Annex A controls), in report order.
ISO_CLAUSE_ORDER: tuple[str, ...] = ("4", "5", "6", "7", "8", "9", "10", "A")
VALID_ISO_CLAUSES = set(ISO_CLAUSE_ORDER)

RISK_WEIGHTS: dict[str, float] = {"low": 1.0, "medium": 1.5, "high": 2.0}


@dataclass(frozen=True)
class ChecklistItem:
    id: str
    text_de: str
    text_en: str
    m_dimension: str  # M1–M6
    gates: tuple[str, ...]  # subset of G0–G5
    risk_weight: dict[str, float] = field(default_factory=lambda: dict(RISK_WEIGHTS))

    def text(self, lang: str) -> str:
        return self.text_de if lang == "de" else self.text_en

    def weight(self, risk_class: str) -> float:
        return self.risk_weight.get(risk_class, 1.0)

    @property
    def iso_clauses(self) -> tuple[str, ...]:
        """ISO/IEC 42001 clause groups this item provides evidence for.

        Sourced from the central ISO_CLAUSES_BY_ITEM orientation matrix so the
        mapping can be reconciled with the IKI-Gov book in one place.
        """
        return ISO_CLAUSES_BY_ITEM.get(self.id, ())


CHECKLIST: tuple[ChecklistItem, ...] = (
    # ── Strategie & Geschäftsfall (S1–S5) → M1 ─────────────────────────────
    ChecklistItem(
        id="S1",
        text_de=(
            "Für diesen KI-Anwendungsfall existieren ein dokumentiertes Geschäftsziel "
            "und messbare Erfolgskriterien."
        ),
        text_en=(
            "A documented business objective and measurable success criteria exist "
            "for this AI use case."
        ),
        m_dimension="M1",
        gates=("G0", "G1"),
    ),
    ChecklistItem(
        id="S2",
        text_de=(
            "Ein verantwortlicher Geschäftsinhaber (Business Owner) ist benannt und hat "
            "sich verbindlich zu diesem Anwendungsfall bekannt."
        ),
        text_en=(
            "An accountable business owner is identified and has formally committed "
            "to this use case."
        ),
        m_dimension="M1",
        gates=("G0", "G1"),
    ),
    ChecklistItem(
        id="S3",
        text_de=(
            "Die KI-Governance-Strategie der Organisation umfasst diesen Anwendungsfall "
            "ausdrücklich und benennt den zuständigen Governance-Träger."
        ),
        text_en=(
            "The organisation's AI governance strategy explicitly covers this use case "
            "and names the responsible governance body."
        ),
        m_dimension="M1",
        gates=("G0", "G1"),
    ),
    ChecklistItem(
        id="S4",
        text_de=(
            "Eine Stakeholder-Übersicht mit allen betroffenen Parteien — einschließlich "
            "betroffener Personen, Aufsichtsbehörden und interner Entscheider — wurde "
            "dokumentiert und abgestimmt."
        ),
        text_en=(
            "A stakeholder map identifying all affected parties — including impacted "
            "individuals, regulators, and internal decision-makers — has been documented "
            "and reviewed."
        ),
        m_dimension="M1",
        gates=("G1",),
    ),
    ChecklistItem(
        id="S5",
        text_de=(
            "Der erwartete Nutzen sowie der Risiko-Nutzen-Abgleich des KI-Systems sind "
            "dokumentiert und durch den verantwortlichen Governance-Träger freigegeben."
        ),
        text_en=(
            "The expected value and the risk-benefit trade-off of deploying this AI system "
            "are documented and approved by the responsible governance body."
        ),
        m_dimension="M1",
        gates=("G1",),
    ),
    # ── Daten, Recht & Ethik (D1–D5) → M2 ──────────────────────────────────
    ChecklistItem(
        id="D1",
        text_de=(
            "Alle Datenquellen sind in einem Dateninventar erfasst und die Datenherkunft "
            "(Data Lineage) ist lückenlos bis zur Quelle nachvollziehbar dokumentiert."
        ),
        text_en=(
            "All data sources are inventoried and data lineage is documented end-to-end "
            "back to the origin."
        ),
        m_dimension="M2",
        gates=("G1", "G2"),
    ),
    ChecklistItem(
        id="D2",
        text_de=(
            "Eine Datenqualitätsprüfung bezüglich Vollständigkeit, Genauigkeit und "
            "Aktualität wurde durchgeführt, dokumentiert und etwaige Mängel adressiert."
        ),
        text_en=(
            "A data quality assessment covering completeness, accuracy, and timeliness "
            "has been conducted, documented, and identified deficiencies addressed."
        ),
        m_dimension="M2",
        gates=("G2",),
    ),
    ChecklistItem(
        id="D3",
        text_de=(
            "Nutzungsrechte und Lizenzen für alle Datenquellen wurden rechtlich geprüft, "
            "sind vollständig dokumentiert und decken den geplanten Einsatzzweck ab."
        ),
        text_en=(
            "Usage rights and licences for all data sources have been legally verified, "
            "are fully documented, and cover the intended use purpose."
        ),
        m_dimension="M2",
        gates=("G2",),
    ),
    ChecklistItem(
        id="D4",
        text_de=(
            "Eine Datenschutz-Folgenabschätzung (DSGVO Art. 35) wurde durchgeführt, "
            "durch den Datenschutzbeauftragten geprüft und etwaige Risiken mitigiert."
        ),
        text_en=(
            "A Data Protection Impact Assessment (GDPR Art. 35 / DSGVO) has been completed, "
            "reviewed by the data protection officer, and identified risks mitigated."
        ),
        m_dimension="M2",
        gates=("G2",),
    ),
    ChecklistItem(
        id="D5",
        text_de=(
            "Eine ethische Risikoabschätzung — einschließlich Bewertung von Diskriminierungs- "
            "und Fairness-Risiken — wurde dokumentiert und durch das zuständige Governance-Gremium "
            "geprüft."
        ),
        text_en=(
            "An ethical risk assessment — including evaluation of discrimination and fairness risks "
            "— has been documented and reviewed by the responsible governance body."
        ),
        m_dimension="M2",
        gates=("G1", "G2"),
    ),
    # ── Modell, Sicherheit & Technik — Validierung/Fairness (T1–T3) → M3 ───
    ChecklistItem(
        id="T1",
        text_de=(
            "Die Modellvalidierung auf einem zurückgehaltenen Testdatensatz ist inkl. "
            "Leistungsmetriken (Accuracy, Precision, Recall, AUC o. Ä.) dokumentiert "
            "und erfüllt die vereinbarten Schwellenwerte."
        ),
        text_en=(
            "Model validation against a held-out test set is documented including performance "
            "metrics (accuracy, precision, recall, AUC, or equivalent) and meets the agreed "
            "thresholds."
        ),
        m_dimension="M3",
        gates=("G2", "G3"),
    ),
    ChecklistItem(
        id="T2",
        text_de=(
            "Fairness-Prüfungen über relevante geschützte Merkmalsgruppen (z. B. Geschlecht, "
            "Alter, Herkunft) wurden durchgeführt und die Ergebnisse sind dokumentiert sowie "
            "etwaige Ungleichbehandlungen adressiert."
        ),
        text_en=(
            "Fairness checks across relevant protected groups (e.g. gender, age, origin) "
            "have been performed, results are documented, and identified disparities addressed."
        ),
        m_dimension="M3",
        gates=("G2",),
    ),
    ChecklistItem(
        id="T3",
        text_de=(
            "Ein Erklärbarkeitsmechanismus (z. B. SHAP, LIME, Regelextraktion) ist "
            "implementiert, getestet und seine Ausgaben sind für die zuständigen "
            "Stakeholder interpretierbar dokumentiert."
        ),
        text_en=(
            "An explainability mechanism (e.g. SHAP, LIME, rule extraction) is implemented, "
            "tested, and its outputs are documented in a form interpretable by the relevant "
            "stakeholders."
        ),
        m_dimension="M3",
        gates=("G2", "G3"),
    ),
    # ── Modell, Sicherheit & Technik — Sicherheit/Robustheit (T4–T5) → M4 ──
    ChecklistItem(
        id="T4",
        text_de=(
            "Adversarielle Robustheitstests sowie strenge Eingabevalidierung und "
            "Ausgabe-Sanitisierung sind implementiert, getestet und die Ergebnisse "
            "sind dokumentiert."
        ),
        text_en=(
            "Adversarial robustness tests and strict input validation together with "
            "output sanitisation are implemented, tested, and results documented."
        ),
        m_dimension="M4",
        gates=("G3",),
    ),
    ChecklistItem(
        id="T5",
        text_de=(
            "Eine Sicherheitsüberprüfung der Modell-Pipeline, der Infrastruktur und "
            "aller Abhängigkeiten (inkl. Drittanbieter-Komponenten) wurde durchgeführt "
            "und Befunde adressiert."
        ),
        text_en=(
            "A security review of the model pipeline, infrastructure, and all dependencies "
            "(including third-party components) has been conducted and findings addressed."
        ),
        m_dimension="M4",
        gates=("G3",),
    ),
    # ── Betrieb, Monitoring & Aufsicht (O1–O5) → M6 ─────────────────────────
    ChecklistItem(
        id="O1",
        text_de=(
            "Ein Produktions-Monitoring-Dashboard mit KI-relevanten KPIs (Modellleistung, "
            "Datendrift, Systemverfügbarkeit) ist in Betrieb und wird aktiv überwacht."
        ),
        text_en=(
            "A production monitoring dashboard covering AI-relevant KPIs (model performance, "
            "data drift, system availability) is operational and actively monitored."
        ),
        m_dimension="M6",
        gates=("G3", "G4"),
    ),
    ChecklistItem(
        id="O2",
        text_de=(
            "Daten- und Modell-Drift-Erkennung mit automatischer Alarmierung ist "
            "konfiguriert, getestet und die Zuständigkeiten bei Auslösung eines "
            "Alarms sind definiert."
        ),
        text_en=(
            "Data and model drift detection with automated alerting is configured, tested, "
            "and responsibilities upon alert triggering are defined."
        ),
        m_dimension="M6",
        gates=("G4",),
    ),
    ChecklistItem(
        id="O3",
        text_de=(
            "Ein menschlicher Aufsichtsprozess für KI-Systementscheidungen — inkl. "
            "Eskalationspfaden und Übersteuerungsmöglichkeiten — ist definiert, "
            "dokumentiert und erprobt."
        ),
        text_en=(
            "A human oversight process for AI system decisions — including escalation paths "
            "and override capabilities — is defined, documented, and tested."
        ),
        m_dimension="M6",
        gates=("G3", "G4"),
    ),
    ChecklistItem(
        id="O4",
        text_de=(
            "Ein Incident-Response- und Änderungsmanagementverfahren für das KI-System "
            "ist etabliert, dokumentiert und durch eine Übung oder einen realen Vorfall "
            "erprobt."
        ),
        text_en=(
            "An incident response and change management procedure for the AI system is "
            "established, documented, and validated through a drill or real incident."
        ),
        m_dimension="M6",
        gates=("G4",),
    ),
    ChecklistItem(
        id="O5",
        text_de=(
            "Ein Auditprotokoll — das Modellentscheidungen, wesentliche Ereignisse und "
            "Parameteränderungen erfasst — wird geführt, ist unveränderlich gespeichert "
            "und für autorisierte Prüfer zugänglich."
        ),
        text_en=(
            "An audit log — capturing model decisions, significant events, and parameter "
            "changes — is maintained, stored immutably, and accessible to authorised auditors."
        ),
        m_dimension="M6",
        gates=("G4", "G5"),
    ),
    # ── ISO/IEC 42001 Abgleich (I1–I5) → M5 ─────────────────────────────────
    ChecklistItem(
        id="I1",
        text_de=(
            "Eine KI-Managementsystemrichtlinie gemäß ISO/IEC 42001 Abschnitt 5.2 ist "
            "dokumentiert, von der Leitungsebene genehmigt und organisationsweit "
            "kommuniziert."
        ),
        text_en=(
            "An AI management system policy aligned with ISO/IEC 42001 clause 5.2 is "
            "documented, approved by top management, and communicated organisation-wide."
        ),
        m_dimension="M5",
        gates=("G4", "G5"),
    ),
    ChecklistItem(
        id="I2",
        text_de=(
            "Rollen und Verantwortlichkeiten für die KI-Governance gemäß ISO/IEC 42001 "
            "Abschnitt 5.3 sind formal definiert, zugewiesen und organisationsweit "
            "kommuniziert."
        ),
        text_en=(
            "Roles and responsibilities for AI governance per ISO/IEC 42001 clause 5.3 "
            "are formally defined, assigned, and communicated organisation-wide."
        ),
        m_dimension="M5",
        gates=("G4", "G5"),
    ),
    ChecklistItem(
        id="I3",
        text_de=(
            "Ein KI-Risikoregister gemäß ISO/IEC 42001 Abschnitt 6.1 wird geführt, "
            "in definierten Intervallen überprüft und ist mit dem übergeordneten "
            "Governance-Prozess verknüpft."
        ),
        text_en=(
            "An AI risk register per ISO/IEC 42001 clause 6.1 is maintained, reviewed "
            "at defined intervals, and linked to the overarching governance process."
        ),
        m_dimension="M5",
        gates=("G5",),
    ),
    ChecklistItem(
        id="I4",
        text_de=(
            "Der KI-System-Lebenszyklus ist gemäß den Anforderungen der ISO/IEC 42001 "
            "Abschnitte 8.3–8.6 dokumentiert, einschließlich Entwicklungs-, Betriebs- "
            "und Außerbetriebnahmephasen."
        ),
        text_en=(
            "The AI system lifecycle is documented in line with ISO/IEC 42001 clauses 8.3–8.6, "
            "covering development, operational, and decommissioning phases."
        ),
        m_dimension="M5",
        gates=("G5",),
    ),
    ChecklistItem(
        id="I5",
        text_de=(
            "Eine interne Prüfung der KI-Governance-Aktivitäten gemäß ISO/IEC 42001 "
            "Abschnitt 9.2 wurde durchgeführt, die Befunde sind dokumentiert und "
            "Korrekturmaßnahmen eingeleitet."
        ),
        text_en=(
            "An internal audit of AI governance activities per ISO/IEC 42001 clause 9.2 "
            "has been conducted, findings documented, and corrective actions initiated."
        ),
        m_dimension="M5",
        gates=("G5",),
    ),
)

# Lookup by ID
ITEM_BY_ID: dict[str, ChecklistItem] = {item.id: item for item in CHECKLIST}

# Items grouped by M-dimension
ITEMS_BY_DIMENSION: dict[str, list[ChecklistItem]] = {dim: [] for dim in VALID_DIMENSIONS}
for _item in CHECKLIST:
    ITEMS_BY_DIMENSION[_item.m_dimension].append(_item)

# Items grouped by gate
ITEMS_BY_GATE: dict[str, list[ChecklistItem]] = {gate: [] for gate in VALID_GATES}
for _item in CHECKLIST:
    for _gate in _item.gates:
        ITEMS_BY_GATE[_gate].append(_item)

# ── ISO/IEC 42001 orientation matrix ────────────────────────────────────────
# Maps each checklist item to the ISO/IEC 42001 clause groups (clauses 4–10 and
# Annex A controls) it provides evidence for. Reconciled (v0.5.1) against the
# IKI-Gov book's orientation matrix (Table tab:framework-iso42001-matrix): the
# union of each M-dimension's item clauses covers that dimension's high-relevance
# (•) cells in the book. The book matrix is qualitative and dimension-level; this
# item-level table refines it. Edit here to adjust — the engine is generic over it.
ISO_CLAUSES_BY_ITEM: dict[str, tuple[str, ...]] = {
    # Strategy & business case (M1)
    "S1": ("4", "6", "9"),
    "S2": ("5",),
    "S3": ("5",),
    "S4": ("4",),
    "S5": ("6",),
    # Data, law & ethics (M2)
    "D1": ("7", "8", "A"),
    "D2": ("8", "A"),
    "D3": ("8", "A"),
    "D4": ("6", "8"),
    "D5": ("6", "8", "A"),
    # Model, validation & fairness (M3: T1–T3)
    "T1": ("6", "8", "9", "A"),
    "T2": ("8", "A"),
    "T3": ("8", "A"),
    # Model, security & robustness (M4: T4–T5)
    "T4": ("6", "8", "A"),
    "T5": ("4", "7", "8", "A"),
    # Operations, monitoring & oversight (M6)
    "O1": ("9", "A"),
    "O2": ("9", "10"),
    "O3": ("8", "A"),
    "O4": ("8", "10"),
    "O5": ("9", "A"),
    # ISO/IEC 42001 alignment (M5; clauses cited in the item text)
    "I1": ("4", "5", "7"),
    "I2": ("5",),
    "I3": ("6",),
    "I4": ("8", "A"),
    "I5": ("9",),
}

# Items grouped by ISO clause group (in report order)
ITEMS_BY_ISO_CLAUSE: dict[str, list[ChecklistItem]] = {clause: [] for clause in ISO_CLAUSE_ORDER}
for _item in CHECKLIST:
    for _clause in _item.iso_clauses:
        ITEMS_BY_ISO_CLAUSE[_clause].append(_item)
