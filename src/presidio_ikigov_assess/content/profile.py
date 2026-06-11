"""Classification-profile pack (v0.20.0).

A ProfilePack maps every cell in the 6×6 eai-classification matrix
(T1–T6 × L1–L6, 36 cells) to a risk profile: risk presumption, strict flag,
obligations list, and optional bilingual notes.

Cell ids follow the pattern ``T{1-6}.L{1-6}``. All 36 cells are required;
validate_profile_pack enforces completeness.

The ``content_hash`` over a canonical JSON representation pins the pack for the
security event log and for --quiet JSON output. External override: packs with
``pack_kind="classification-profile"`` in IGA_CONTENT_PATH load alongside
ContentPacks (see content/loader.py); same framework_id overrides builtin.

Modeled on content/pack.py (v0.16.0 pattern).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

PACK_KIND = "classification-profile"

VALID_RISK_PRESUMPTIONS = frozenset({"low", "medium", "high"})
VALID_OBLIGATION_ID_RE = r"^[a-zA-Z0-9_\-]{1,64}$"

# All 36 valid cell ids
_VALID_CELLS = frozenset(f"T{t}.L{lv}" for t in range(1, 7) for lv in range(1, 7))


class ProfileError(ValueError):
    """Raised when a profile pack is malformed."""


@dataclass(frozen=True)
class CellProfile:
    """Risk profile for a single 6×6 matrix cell."""

    risk_presumption: str  # "low" | "medium" | "high"
    strict: bool = False
    obligations: tuple[str, ...] = field(default_factory=tuple)
    notes: dict[str, str] = field(default_factory=dict)  # {lang: str}


@dataclass(frozen=True)
class ProfilePack:
    """A 36-cell classification-profile pack.

    All 36 cells T1.L1 … T6.L6 are required.
    """

    pack_kind: str  # always "classification-profile"
    framework_id: str
    version: str
    profiles: dict[str, CellProfile]  # keyed by "T{t}.L{l}"
    source: str = "builtin"

    @property
    def content_hash(self) -> str:
        """SHA-256 over a canonical, deterministic JSON representation."""
        profiles_serial = {}
        for cell in sorted(self.profiles):
            p = self.profiles[cell]
            profiles_serial[cell] = {
                "risk_presumption": p.risk_presumption,
                "strict": p.strict,
                "obligations": list(p.obligations),
                "notes": {k: p.notes[k] for k in sorted(p.notes)},
            }
        payload = {
            "pack_kind": self.pack_kind,
            "framework_id": self.framework_id,
            "version": self.version,
            "profiles": profiles_serial,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def get(self, cell: str) -> CellProfile:
        """Return the profile for a cell id; raises ProfileError if not found."""
        if cell not in self.profiles:
            raise ProfileError(f"cell {cell!r} not found in profile pack {self.framework_id!r}")
        return self.profiles[cell]


import re  # noqa: E402

_OBLIGATION_PATTERN = re.compile(VALID_OBLIGATION_ID_RE)


def validate_profile_pack(pack: ProfilePack) -> ProfilePack:
    """Validate structural invariants; returns the pack or raises ProfileError."""
    if pack.pack_kind != PACK_KIND:
        raise ProfileError(f"pack_kind must be {PACK_KIND!r}, got {pack.pack_kind!r}")
    if not pack.framework_id or not isinstance(pack.framework_id, str):
        raise ProfileError("profile pack framework_id must be a non-empty string")
    if not pack.version:
        raise ProfileError("profile pack version must be a non-empty string")
    if set(pack.profiles.keys()) != _VALID_CELLS:
        missing = _VALID_CELLS - set(pack.profiles.keys())
        extra = set(pack.profiles.keys()) - _VALID_CELLS
        parts = []
        if missing:
            parts.append(f"missing cells: {sorted(missing)}")
        if extra:
            parts.append(f"unexpected cells: {sorted(extra)}")
        raise ProfileError(
            f"profile pack '{pack.framework_id}' does not cover all 36 cells: " + "; ".join(parts)
        )
    for cell, prof in pack.profiles.items():
        if prof.risk_presumption not in VALID_RISK_PRESUMPTIONS:
            raise ProfileError(
                f"cell {cell!r}: risk_presumption must be low|medium|high, "
                f"got {prof.risk_presumption!r}"
            )
        for ob in prof.obligations:
            if not isinstance(ob, str) or not _OBLIGATION_PATTERN.match(ob):
                raise ProfileError(
                    f"cell {cell!r}: obligation id {ob!r} must match [a-zA-Z0-9_-]{{1,64}}"
                )
    return pack


def profile_pack_from_dict(data: object, *, source: str = "external") -> ProfilePack:
    """Build and validate a ProfilePack from a parsed JSON object."""
    if not isinstance(data, dict):
        raise ProfileError("profile pack must be a JSON object")
    if data.get("pack_kind") != PACK_KIND:
        raise ProfileError(f"pack_kind must be {PACK_KIND!r} to load as a ProfilePack")
    try:
        raw_profiles = data["profiles"]
        if not isinstance(raw_profiles, dict):
            raise ProfileError("profiles must be an object")
        profiles: dict[str, CellProfile] = {}
        for cell, pdata in raw_profiles.items():
            if not isinstance(pdata, dict):
                raise ProfileError(f"profile for cell {cell!r} must be an object")
            rp = pdata.get("risk_presumption", "low")
            st = bool(pdata.get("strict", False))
            obs_raw = pdata.get("obligations", [])
            if not isinstance(obs_raw, list):
                raise ProfileError(f"cell {cell!r}: obligations must be a list")
            obs = tuple(str(o) for o in obs_raw)
            notes_raw = pdata.get("notes", {})
            if not isinstance(notes_raw, dict):
                raise ProfileError(f"cell {cell!r}: notes must be an object")
            notes = {str(k): str(v) for k, v in notes_raw.items()}
            profiles[cell] = CellProfile(
                risk_presumption=rp,
                strict=st,
                obligations=obs,
                notes=notes,
            )
        pack = ProfilePack(
            pack_kind=str(data.get("pack_kind", PACK_KIND)),
            framework_id=str(data["framework_id"]),
            version=str(data.get("version", "0")),
            profiles=profiles,
            source=source,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ProfileError(f"malformed profile pack: {exc}") from exc
    return validate_profile_pack(pack)


def profile_pack_to_dict(pack: ProfilePack) -> dict[str, object]:
    """Serialise a ProfilePack to a JSON-ready dict."""
    return {
        "pack_kind": pack.pack_kind,
        "framework_id": pack.framework_id,
        "version": pack.version,
        "profiles": {
            cell: {
                "risk_presumption": p.risk_presumption,
                "strict": p.strict,
                "obligations": list(p.obligations),
                "notes": dict(p.notes),
            }
            for cell, p in pack.profiles.items()
        },
        "source": pack.source,
        "content_hash": pack.content_hash,
    }
