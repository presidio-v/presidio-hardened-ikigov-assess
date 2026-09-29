"""Load built-in plus external content packs and classification-profile packs.

External packs are ``*.json`` files in ``IGA_CONTENT_PATH`` (or ``~/.iga/content/``).
Files with ``pack_kind="classification-profile"`` are loaded as
:class:`~presidio_ikigov_assess.content.profile.ProfilePack`; all other files are
treated as :class:`ContentPack`. A pack with the same ``framework_id`` as a built-in
one overrides it, so an organisation can ship updated content without a code release.

Because ``framework_id`` is the identity a user trusts and anyone can write it, an
override is refused unless explicitly allowed (``IGA_ALLOW_BUILTIN_OVERRIDE=1`` or
``iga --allow-builtin-override``), and an allowed override is announced on stderr
every time packs load. Pack files are capped in size and parse errors, including
excessive nesting, surface as :class:`ContentError`.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from presidio_ikigov_assess.content.builtin import builtin_packs
from presidio_ikigov_assess.content.pack import ContentError, ContentPack, pack_from_dict
from presidio_ikigov_assess.content.profile import ProfilePack, profile_pack_from_dict
from presidio_ikigov_assess.content.profile_builtin import builtin_classification_profile_pack

_CONTENT_ENV = "IGA_CONTENT_PATH"
ALLOW_OVERRIDE_ENV = "IGA_ALLOW_BUILTIN_OVERRIDE"
#: Same bound as a classification document: packs are small JSON tables.
MAX_PACK_BYTES = 1_000_000


def _read_pack_json(path: Path, kind: str) -> object:
    """Read one pack file, bounded in size, with every parse failure as ContentError."""
    try:
        with path.open("rb") as fh:
            raw = fh.read(MAX_PACK_BYTES + 1)
        if len(raw) > MAX_PACK_BYTES:
            raise ContentError(f"{kind} {path.name} exceeds {MAX_PACK_BYTES} bytes")
        return json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ContentError(f"cannot read {kind} {path.name}: {type(exc).__name__}") from exc


def _overlay(builtin: dict, external: dict, kind: str) -> dict:
    """Overlay *external* packs on *builtin*, guarding built-in framework_ids."""
    overridden = sorted(set(builtin) & set(external))
    if overridden:
        if os.environ.get(ALLOW_OVERRIDE_ENV, "").strip() != "1":
            raise ContentError(
                f"external {kind} would override built-in framework_id "
                f"{', '.join(overridden)}; refusing. Rename its framework_id, or allow "
                f"with {ALLOW_OVERRIDE_ENV}=1 / iga --allow-builtin-override."
            )
        for fid in overridden:
            print(
                f"warning: built-in {kind} '{fid}' overridden by external pack "
                f"{external[fid].version} ({external[fid].content_hash[:12]})",
                file=sys.stderr,
            )
    merged = dict(builtin)
    merged.update(external)
    return merged


def content_dir() -> Path:
    return Path(os.environ.get(_CONTENT_ENV, str(Path.home() / ".iga" / "content")))


def load_external_packs(directory: Path | None = None) -> dict[str, ContentPack]:
    """Load external ContentPacks (non-profile) from the content directory."""
    directory = directory or content_dir()
    packs: dict[str, ContentPack] = {}
    if not directory.is_dir():
        return packs
    for path in sorted(directory.glob("*.json")):
        data = _read_pack_json(path, "content pack")
        # Skip classification-profile packs — handled by load_external_profile_packs.
        if isinstance(data, dict) and data.get("pack_kind") == "classification-profile":
            continue
        pack = pack_from_dict(data, source="external")
        packs[pack.framework_id] = pack
    return packs


def load_external_profile_packs(directory: Path | None = None) -> dict[str, ProfilePack]:
    """Load external ProfilePacks (pack_kind='classification-profile') from the content dir."""
    from presidio_ikigov_assess.content.profile import PACK_KIND

    directory = directory or content_dir()
    packs: dict[str, ProfilePack] = {}
    if not directory.is_dir():
        return packs
    for path in sorted(directory.glob("*.json")):
        data = _read_pack_json(path, "profile pack")
        if not (isinstance(data, dict) and data.get("pack_kind") == PACK_KIND):
            continue
        try:
            pack = profile_pack_from_dict(data, source="external")
        except Exception as exc:
            raise ContentError(f"malformed profile pack {path.name}: {exc}") from exc
        packs[pack.framework_id] = pack
    return packs


def load_packs(directory: Path | None = None) -> dict[str, ContentPack]:
    """Built-in ContentPacks overlaid by any external ContentPacks of the same framework_id."""
    return _overlay(builtin_packs(), load_external_packs(directory), "content pack")


def load_profile_packs(directory: Path | None = None) -> dict[str, ProfilePack]:
    """Built-in ProfilePack overlaid by any external ProfilePacks of the same framework_id."""
    builtin = builtin_classification_profile_pack()
    return _overlay(
        {builtin.framework_id: builtin}, load_external_profile_packs(directory), "profile pack"
    )
