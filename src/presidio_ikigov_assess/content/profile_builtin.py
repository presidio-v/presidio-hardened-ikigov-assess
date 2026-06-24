"""Built-in classification-profile pack — DRAFT mapping semantics.

DRAFT mapping semantics — founder review required before merge.

Risk-presumption rules (as data, not code):
  Base by autonomy level:
    L1–L2: low
    L3–L4: medium
    L5: high
    L6: high + strict=true  (ecosystem/multi-system coordination regime)

  Type modifiers (floors — can only raise presumption):
    T6 Physical: floors at medium from L2, floors at high from L4
      (embodied actuation — any autonomous physical actuation carries elevated risk)
    T1 Decision: floors at medium from L3
      (decisions about persons — GDPR/EU AI Act high-risk alignment)

  All cells carry obligations: ["iso42001", "euaiact"]

Notes (de/en) per level band, explaining the presumption (clearly labelled
draft — the rationale is explicit so the founder can refine it).
"""

from __future__ import annotations

from presidio_ikigov_assess.content.profile import CellProfile, ProfilePack

_BUILTIN_VERSION = "builtin-draft-1"

_NOTES_L1 = {
    "de": (
        "ENTWURF: L1 – Automatisierte Hilfsfunktion mit menschlicher Kontrolle. "
        "Geringes Risikopotenzial; Standardkontrollen nach ISO 42001 genügen."
    ),
    "en": (
        "DRAFT: L1 – Automated assistance with full human control. "
        "Low risk potential; standard ISO 42001 controls suffice."
    ),
}
_NOTES_L2 = {
    "de": (
        "ENTWURF: L2 – Eingeschränkte Autonomie mit strukturierter menschlicher Überwachung. "
        "Geringes Risikopotenzial; Standardkontrollen nach ISO 42001 genügen."
    ),
    "en": (
        "DRAFT: L2 – Limited autonomy with structured human oversight. "
        "Low risk potential; standard ISO 42001 controls suffice."
    ),
}
_NOTES_L3 = {
    "de": (
        "ENTWURF: L3 – Konditionelle Autonomie mit erweiterten Aufsichtsanforderungen. "
        "Mittleres Risikopotenzial; erhöhte Dokumentations- und Überwachungspflichten."
    ),
    "en": (
        "DRAFT: L3 – Conditional autonomy with extended oversight requirements. "
        "Medium risk potential; elevated documentation and monitoring obligations."
    ),
}
_NOTES_L4 = {
    "de": (
        "ENTWURF: L4 – Hohe Autonomie mit eingeschränkter menschlicher Eingriffsmöglichkeit. "
        "Mittleres bis hohes Risikopotenzial; umfassende Risikokontrollen erforderlich."
    ),
    "en": (
        "DRAFT: L4 – High autonomy with limited human intervention capability. "
        "Medium-to-high risk potential; comprehensive risk controls required."
    ),
}
_NOTES_L5 = {
    "de": (
        "ENTWURF: L5 – Vollautonome Handlungsfähigkeit ohne menschliche Aufsicht im Betrieb. "
        "Hohes Risikopotenzial; strengste Kontrollen und lückenlose Nachweispflicht."
    ),
    "en": (
        "DRAFT: L5 – Fully autonomous operation without human supervision. "
        "High risk potential; strictest controls and complete evidence trail required."
    ),
}
_NOTES_L6 = {
    "de": (
        "ENTWURF: L6 – Ökosystem-/Mehrsystemkoordination (nicht-ordinales Overlay-Regime). "
        "Höchstes Risikopotenzial durch systemübergreifende Koordination; "
        "strengste Kontrollen, vollständige Striktheit erzwungen."
    ),
    "en": (
        "DRAFT: L6 – Ecosystem/multi-system coordination (non-ordinal overlay regime). "
        "Highest risk potential due to cross-system coordination; "
        "strictest controls, strict mode enforced."
    ),
}

# Per-level note lookup
_LEVEL_NOTES = {
    "L1": _NOTES_L1,
    "L2": _NOTES_L2,
    "L3": _NOTES_L3,
    "L4": _NOTES_L4,
    "L5": _NOTES_L5,
    "L6": _NOTES_L6,
}

_OBLIGATIONS = ("iso42001", "euaiact")


def _base_presumption(level: str) -> str:
    """Base risk presumption by autonomy level."""
    if level in ("L1", "L2"):
        return "low"
    if level in ("L3", "L4"):
        return "medium"
    # L5, L6
    return "high"


def _apply_type_modifier(type_id: str, level: str, base: str) -> str:
    """Apply type-specific floor modifiers, returning the effective presumption."""
    level_num = int(level[1])
    if type_id == "T6":
        # T6 Physical: floor at medium from L2, floor at high from L4
        if level_num >= 4 and base in ("low", "medium"):
            return "high"
        if level_num >= 2 and base == "low":
            return "medium"
    elif type_id == "T1":
        # T1 Decision: floor at medium from L3
        if level_num >= 3 and base == "low":
            return "medium"
    return base


def _build_profile(type_id: str, level: str) -> CellProfile:
    base = _base_presumption(level)
    presumption = _apply_type_modifier(type_id, level, base)
    strict = level == "L6"
    notes = dict(_LEVEL_NOTES[level])
    return CellProfile(
        risk_presumption=presumption,
        strict=strict,
        obligations=_OBLIGATIONS,
        notes=notes,
    )


def builtin_classification_profile_pack() -> ProfilePack:
    """Return the built-in draft classification-profile pack."""
    profiles = {
        f"T{t}.L{lv}": _build_profile(f"T{t}", f"L{lv}") for t in range(1, 7) for lv in range(1, 7)
    }
    return ProfilePack(
        pack_kind="classification-profile",
        framework_id="eai-classification-default",
        version=_BUILTIN_VERSION,
        profiles=profiles,
        source="builtin",
    )
