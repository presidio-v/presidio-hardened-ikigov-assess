"""Load built-in plus external content packs and classification-profile packs.

External packs are ``*.json`` files in ``IGA_CONTENT_PATH`` (or ``~/.iga/content/``).
Files with ``pack_kind="classification-profile"`` are loaded as
:class:`~presidio_ikigov_assess.content.profile.ProfilePack`; all other files are
treated as :class:`ContentPack`. A pack with the same ``framework_id`` as a built-in
one overrides it, so an organisation can ship updated content without a code release.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from presidio_ikigov_assess.content.builtin import builtin_packs
from presidio_ikigov_assess.content.pack import ContentError, ContentPack, pack_from_dict
from presidio_ikigov_assess.content.profile import ProfilePack, profile_pack_from_dict
from presidio_ikigov_assess.content.profile_builtin import builtin_classification_profile_pack

_CONTENT_ENV = "IGA_CONTENT_PATH"


def content_dir() -> Path:
    return Path(os.environ.get(_CONTENT_ENV, str(Path.home() / ".iga" / "content")))


def load_external_packs(directory: Path | None = None) -> dict[str, ContentPack]:
    """Load external ContentPacks (non-profile) from the content directory."""
    directory = directory or content_dir()
    packs: dict[str, ContentPack] = {}
    if not directory.is_dir():
        return packs
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ContentError(f"cannot read content pack {path.name}: {exc}") from exc
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
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ContentError(f"cannot read profile pack {path.name}: {exc}") from exc
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
    packs = builtin_packs()
    packs.update(load_external_packs(directory))
    return packs


def load_profile_packs(directory: Path | None = None) -> dict[str, ProfilePack]:
    """Built-in ProfilePack overlaid by any external ProfilePacks of the same framework_id."""
    packs: dict[str, ProfilePack] = {
        builtin_classification_profile_pack().framework_id: builtin_classification_profile_pack()
    }
    packs.update(load_external_profile_packs(directory))
    return packs
