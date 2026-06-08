"""Built-in content packs — the ISO/IEC 42001 and EU AI Act mappings as data.

Derived from the existing ``checklist``/``euaiact`` constants so they reproduce the
hard-coded behaviour exactly (asserted by cross-check tests), while making the mappings
addressable as versioned packs the generic engine can consume.
"""

from __future__ import annotations

from presidio_ikigov_assess.checklist import ISO_CLAUSE_ORDER, ITEMS_BY_ISO_CLAUSE
from presidio_ikigov_assess.content.pack import ContentPack
from presidio_ikigov_assess.euaiact import ARTICLE_ORDER, EU_AI_ACT_ARTICLE_GATES
from presidio_ikigov_assess.i18n import t

BUILTIN_VERSION = "builtin-1"


def iso42001_pack() -> ContentPack:
    return ContentPack(
        framework_id="iso42001",
        version=BUILTIN_VERSION,
        mapping_kind="item",
        target_order=tuple(ISO_CLAUSE_ORDER),
        target_names={
            c: {"de": t(f"iso_clause_{c}", "de"), "en": t(f"iso_clause_{c}", "en")}
            for c in ISO_CLAUSE_ORDER
        },
        mapping={
            c: tuple(item.id for item in ITEMS_BY_ISO_CLAUSE.get(c, [])) for c in ISO_CLAUSE_ORDER
        },
        source="builtin",
    )


def euaiact_pack() -> ContentPack:
    return ContentPack(
        framework_id="euaiact",
        version=BUILTIN_VERSION,
        mapping_kind="gate",
        target_order=tuple(ARTICLE_ORDER),
        target_names={
            a: {"de": t(f"euaiact_art_{a}", "de"), "en": t(f"euaiact_art_{a}", "en")}
            for a in ARTICLE_ORDER
        },
        mapping={a: tuple(EU_AI_ACT_ARTICLE_GATES[a]) for a in ARTICLE_ORDER},
        source="builtin",
    )


# NIST AI RMF 1.0 core functions. Initial qualitative item→function mapping (mirrors the
# ISO matrix's relevance grading); every checklist item is assigned to exactly one
# function. Intended to be refined by the framework author — versioned so changes are
# tracked via the pack content_hash.
_NIST_FUNCTIONS = ("GOVERN", "MAP", "MEASURE", "MANAGE")
_NIST_NAMES = {
    "GOVERN": "Govern — culture, policies, accountability, oversight",
    "MAP": "Map — context, categorisation, impact identification",
    "MEASURE": "Measure — analyse, assess, benchmark, track",
    "MANAGE": "Manage — prioritise, respond, recover, document",
}
_NIST_MAPPING = {
    "GOVERN": ("S1", "S2", "S3", "D3", "I1", "I2", "I3", "I5"),
    "MAP": ("S4", "S5", "D1", "D4", "D5"),
    "MEASURE": ("T1", "T2", "T3", "D2", "O1", "O2"),
    "MANAGE": ("T4", "T5", "O3", "O4", "O5", "I4"),
}


def nist_ai_rmf_pack() -> ContentPack:
    return ContentPack(
        framework_id="nist-ai-rmf",
        version="builtin-1",
        mapping_kind="item",
        target_order=_NIST_FUNCTIONS,
        target_names={f: {"en": _NIST_NAMES[f]} for f in _NIST_FUNCTIONS},
        mapping=dict(_NIST_MAPPING),
        source="builtin",
    )


def builtin_packs() -> dict[str, ContentPack]:
    return {p.framework_id: p for p in (iso42001_pack(), euaiact_pack(), nist_ai_rmf_pack())}
