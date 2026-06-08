"""Regulatory-content pack model (v0.16.0).

A content pack decouples a framework's *mapping content* (which checklist items or
lifecycle gates evidence each clause/article/control) from the coverage engine, so a
new framework is added as data — not code. Built-in packs reproduce the hard-coded
ISO/IEC 42001 and EU AI Act mappings exactly; external packs load from a configured
directory.

A pack maps each **target** (clause / article / control id) to the **sources** that
evidence it: checklist item ids (``mapping_kind='item'``) or lifecycle gate ids
(``mapping_kind='gate'``). The ``content_hash`` pins the pack's content for the
evidence-pack manifest.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

VALID_KINDS = ("item", "gate")


class ContentError(ValueError):
    """Raised when a content pack is malformed."""


@dataclass(frozen=True)
class ContentPack:
    framework_id: str
    version: str
    mapping_kind: str  # "item" | "gate"
    target_order: tuple[str, ...]
    target_names: dict[str, dict[str, str]]  # target -> {lang: name}
    mapping: dict[str, tuple[str, ...]]  # target -> source ids
    source: str = field(default="builtin")  # builtin | external (not hashed)

    def name(self, target: str, lang: str) -> str:
        names = self.target_names.get(target, {})
        return names.get(lang) or names.get("en") or target

    @property
    def content_hash(self) -> str:
        payload = {
            "framework_id": self.framework_id,
            "version": self.version,
            "mapping_kind": self.mapping_kind,
            "target_order": list(self.target_order),
            "target_names": {
                t: dict(sorted(n.items())) for t, n in sorted(self.target_names.items())
            },
            "mapping": {t: list(s) for t, s in sorted(self.mapping.items())},
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_pack(pack: ContentPack) -> ContentPack:
    """Validate structural invariants; returns the pack or raises ContentError."""
    if not pack.framework_id or not isinstance(pack.framework_id, str):
        raise ContentError("pack framework_id must be a non-empty string")
    if pack.mapping_kind not in VALID_KINDS:
        raise ContentError(f"pack mapping_kind must be one of {VALID_KINDS}")
    if not pack.target_order:
        raise ContentError(f"pack '{pack.framework_id}' has no targets")
    for target in pack.target_order:
        if target not in pack.mapping:
            raise ContentError(
                f"pack '{pack.framework_id}': target {target!r} missing from mapping"
            )
        if not all(isinstance(s, str) and s for s in pack.mapping[target]):
            raise ContentError(f"pack '{pack.framework_id}': target {target!r} has invalid sources")
    return pack


def pack_from_dict(data: object, *, source: str = "external") -> ContentPack:
    """Build and validate a ContentPack from a parsed JSON object."""
    if not isinstance(data, dict):
        raise ContentError("content pack must be a JSON object")
    try:
        pack = ContentPack(
            framework_id=data["framework_id"],
            version=str(data.get("version", "0")),
            mapping_kind=data["mapping_kind"],
            target_order=tuple(data["target_order"]),
            target_names={t: dict(n) for t, n in data.get("target_names", {}).items()},
            mapping={t: tuple(s) for t, s in data["mapping"].items()},
            source=source,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ContentError(f"malformed content pack: {exc}") from exc
    return validate_pack(pack)


def pack_to_dict(pack: ContentPack) -> dict[str, object]:
    """Serialise a pack to a JSON-ready dict (for `iga content list --quiet`)."""
    return {
        "framework_id": pack.framework_id,
        "version": pack.version,
        "mapping_kind": pack.mapping_kind,
        "target_order": list(pack.target_order),
        "target_names": pack.target_names,
        "mapping": {t: list(s) for t, s in pack.mapping.items()},
        "source": pack.source,
        "content_hash": pack.content_hash,
    }
