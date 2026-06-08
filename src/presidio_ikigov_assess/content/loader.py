"""Load built-in plus external content packs.

External packs are ``*.json`` files in ``IGA_CONTENT_PATH`` (or ``~/.iga/content/``),
each a serialised :class:`ContentPack`. An external pack with the same ``framework_id``
as a built-in one overrides it, so an organisation can ship updated regulatory content
without a code release.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from presidio_ikigov_assess.content.builtin import builtin_packs
from presidio_ikigov_assess.content.pack import ContentError, ContentPack, pack_from_dict

_CONTENT_ENV = "IGA_CONTENT_PATH"


def content_dir() -> Path:
    return Path(os.environ.get(_CONTENT_ENV, str(Path.home() / ".iga" / "content")))


def load_external_packs(directory: Path | None = None) -> dict[str, ContentPack]:
    directory = directory or content_dir()
    packs: dict[str, ContentPack] = {}
    if not directory.is_dir():
        return packs
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ContentError(f"cannot read content pack {path.name}: {exc}") from exc
        pack = pack_from_dict(data, source="external")
        packs[pack.framework_id] = pack
    return packs


def load_packs(directory: Path | None = None) -> dict[str, ContentPack]:
    """Built-in packs overlaid by any external packs of the same framework_id."""
    packs = builtin_packs()
    packs.update(load_external_packs(directory))
    return packs
