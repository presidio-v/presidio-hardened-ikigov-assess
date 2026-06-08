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


def builtin_packs() -> dict[str, ContentPack]:
    return {p.framework_id: p for p in (iso42001_pack(), euaiact_pack())}
