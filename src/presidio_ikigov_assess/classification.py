"""Interchange schema ``eai-classification/v1`` — parse and validate EAI classification documents.

A classification document is a producer-agnostic JSON object:
  {
    "schema": "eai-classification/v1",
    "producer": {optional, free-form},
    "use_cases": [...]
  }

Each use case carries: id, type (T1–T6), level (L1–L6), and optional fields
name, ecosystem, confidence, rationale, tags.

The ``ecosystem`` flag implements the non-ordinal L6 overlay regime: when
``ecosystem=true`` the effective cell level is L6 regardless of the declared
base level (L1–L5). ``level=L6`` with ``ecosystem=false`` is a contradiction
and is rejected. Unknown fields at any level are silently ignored (forward
compatibility). Unknown schema versions fail closed.

Security posture: hard input limits mirroring sanitize.py style.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_SUPPORTED_SCHEMA = "eai-classification/v1"

# Hard limits matching the repo's security posture.
_MAX_USE_CASES = 200
_MAX_DOC_BYTES = 1_000_000  # 1 MB
_MAX_RATIONALE_LEN = 2000
_MAX_NAME_LEN = 256
_MAX_TAG_LEN = 64
_MAX_TAGS = 20

_VALID_TYPES = frozenset(f"T{i}" for i in range(1, 7))
_VALID_LEVELS = frozenset(f"L{i}" for i in range(1, 7))

# Use-case id: same rules as validate_use_case in sanitize.py
_USE_CASE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")


class ClassificationError(ValueError):
    """Raised when a classification document is malformed or invalid."""


@dataclass(frozen=True)
class ClassifiedUseCase:
    """A single parsed and validated use-case record from an eai-classification document.

    ``level`` is the *effective* cell level (L6 when ecosystem=True was present).
    ``base_level`` is the declared level before ecosystem normalisation.
    """

    id: str
    type: str  # T1–T6
    level: str  # effective cell level L1–L6
    base_level: str  # declared level (before ecosystem normalisation)
    name: str | dict[str, str] | None = None
    ecosystem: bool = False
    confidence: float | None = None
    rationale: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ClassificationDocument:
    """A parsed and validated eai-classification/v1 document."""

    schema: str
    producer: Any  # free-form, not validated beyond presence
    use_cases: tuple[ClassifiedUseCase, ...]

    @property
    def cell_id(self) -> str | None:
        """Return the first use case's cell id, or None if document is empty."""
        if self.use_cases:
            uc = self.use_cases[0]
            return f"{uc.type}.{uc.level}"
        return None


def _parse_use_case(raw: object, idx: int) -> ClassifiedUseCase:
    """Parse and validate a single use-case entry.

    Unknown fields are silently ignored (forward-compat).
    """
    if not isinstance(raw, dict):
        raise ClassificationError(f"use_cases[{idx}]: expected object, got {type(raw).__name__}")

    # --- id ---
    raw_id = raw.get("id")
    if not isinstance(raw_id, str) or not _USE_CASE_ID_PATTERN.match(raw_id):
        raise ClassificationError(
            f"use_cases[{idx}]: id must match [a-zA-Z0-9_-]{{1,128}}, got {raw_id!r:.40}"
        )

    # --- type ---
    raw_type = raw.get("type")
    if raw_type not in _VALID_TYPES:
        raise ClassificationError(
            f"use_cases[{idx}] (id={raw_id!r}): type must be T1–T6, got {raw_type!r:.20}"
        )

    # --- level ---
    raw_level = raw.get("level")
    if raw_level not in _VALID_LEVELS:
        raise ClassificationError(
            f"use_cases[{idx}] (id={raw_id!r}): level must be L1–L6, got {raw_level!r:.20}"
        )

    # --- ecosystem ---
    raw_ecosystem = raw.get("ecosystem")
    if raw_ecosystem is None:
        ecosystem = False
    elif isinstance(raw_ecosystem, bool):
        ecosystem = raw_ecosystem
    else:
        raise ClassificationError(f"use_cases[{idx}] (id={raw_id!r}): ecosystem must be a boolean")

    # Contradiction: level=L6 + ecosystem=false is explicitly rejected.
    if raw_level == "L6" and ecosystem is False and "ecosystem" in raw:
        raise ClassificationError(
            f"use_cases[{idx}] (id={raw_id!r}): level=L6 with ecosystem=false is a "
            "contradiction — L6 is the ecosystem/coordination regime; omit ecosystem "
            "or set ecosystem=true"
        )

    # Normalise: ecosystem=true → effective level = L6; retain base_level.
    base_level = raw_level
    effective_level = "L6" if ecosystem else raw_level

    # --- name (optional) ---
    raw_name = raw.get("name")
    name: str | dict[str, str] | None = None
    if raw_name is not None:
        if isinstance(raw_name, str):
            if len(raw_name) > _MAX_NAME_LEN:
                raise ClassificationError(
                    f"use_cases[{idx}] (id={raw_id!r}): name string too long "
                    f"(max {_MAX_NAME_LEN} chars)"
                )
            name = raw_name
        elif isinstance(raw_name, dict):
            for k, v in raw_name.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    raise ClassificationError(
                        f"use_cases[{idx}] (id={raw_id!r}): name dict must be {{str: str}}"
                    )
                if len(v) > _MAX_NAME_LEN:
                    raise ClassificationError(
                        f"use_cases[{idx}] (id={raw_id!r}): name[{k!r}] too long "
                        f"(max {_MAX_NAME_LEN} chars)"
                    )
            name = dict(raw_name)
        else:
            raise ClassificationError(
                f"use_cases[{idx}] (id={raw_id!r}): name must be a string or {{lang: str}} dict"
            )

    # --- confidence (optional) ---
    raw_conf = raw.get("confidence")
    confidence: float | None = None
    if raw_conf is not None:
        if not isinstance(raw_conf, (int, float)):
            raise ClassificationError(
                f"use_cases[{idx}] (id={raw_id!r}): confidence must be a number 0..1"
            )
        conf_f = float(raw_conf)
        if not (0.0 <= conf_f <= 1.0):
            raise ClassificationError(
                f"use_cases[{idx}] (id={raw_id!r}): confidence must be in [0, 1], got {conf_f}"
            )
        confidence = conf_f

    # --- rationale (optional) ---
    raw_rationale = raw.get("rationale")
    rationale: str | None = None
    if raw_rationale is not None:
        if not isinstance(raw_rationale, str):
            raise ClassificationError(
                f"use_cases[{idx}] (id={raw_id!r}): rationale must be a string"
            )
        if len(raw_rationale) > _MAX_RATIONALE_LEN:
            raise ClassificationError(
                f"use_cases[{idx}] (id={raw_id!r}): rationale too long "
                f"(max {_MAX_RATIONALE_LEN} chars)"
            )
        rationale = raw_rationale

    # --- tags (optional) ---
    raw_tags = raw.get("tags")
    tags: tuple[str, ...] = ()
    if raw_tags is not None:
        if not isinstance(raw_tags, list):
            raise ClassificationError(f"use_cases[{idx}] (id={raw_id!r}): tags must be a list")
        if len(raw_tags) > _MAX_TAGS:
            raise ClassificationError(
                f"use_cases[{idx}] (id={raw_id!r}): too many tags (max {_MAX_TAGS})"
            )
        validated_tags = []
        for ti, tag in enumerate(raw_tags):
            if not isinstance(tag, str):
                raise ClassificationError(
                    f"use_cases[{idx}] (id={raw_id!r}): tags[{ti}] must be a string"
                )
            if len(tag) > _MAX_TAG_LEN:
                raise ClassificationError(
                    f"use_cases[{idx}] (id={raw_id!r}): tags[{ti}] too long "
                    f"(max {_MAX_TAG_LEN} chars)"
                )
            validated_tags.append(tag)
        tags = tuple(validated_tags)

    return ClassifiedUseCase(
        id=raw_id,
        type=raw_type,
        level=effective_level,
        base_level=base_level,
        name=name,
        ecosystem=ecosystem,
        confidence=confidence,
        rationale=rationale,
        tags=tags,
    )


def parse_classification(data: object) -> ClassificationDocument:
    """Parse and validate a deserialized eai-classification/v1 document.

    Unknown top-level fields are ignored (forward-compat).
    Unknown schema versions fail closed with a clear error.
    """
    if not isinstance(data, dict):
        raise ClassificationError("classification document must be a JSON object")

    # --- schema version (required) ---
    raw_schema = data.get("schema")
    if not isinstance(raw_schema, str):
        raise ClassificationError(
            f"classification document missing required 'schema' field "
            f'(expected "{_SUPPORTED_SCHEMA}")'
        )
    if raw_schema != _SUPPORTED_SCHEMA:
        raise ClassificationError(
            f"unsupported schema version: {raw_schema!r}. "
            f'This implementation supports "{_SUPPORTED_SCHEMA}" only.'
        )

    # --- producer (optional, free-form) ---
    producer = data.get("producer")  # not validated beyond presence

    # --- use_cases ---
    raw_ucs = data.get("use_cases")
    if raw_ucs is None:
        raise ClassificationError("classification document missing required 'use_cases' field")
    if not isinstance(raw_ucs, list):
        raise ClassificationError("use_cases must be a JSON array")
    if len(raw_ucs) > _MAX_USE_CASES:
        raise ClassificationError(
            f"too many use cases ({len(raw_ucs)}); maximum is {_MAX_USE_CASES}"
        )

    use_cases = tuple(_parse_use_case(uc, idx) for idx, uc in enumerate(raw_ucs))

    return ClassificationDocument(
        schema=raw_schema,
        producer=producer,
        use_cases=use_cases,
    )


def parse_classification_bytes(raw: bytes | str) -> ClassificationDocument:
    """Parse and validate raw JSON bytes/str as an eai-classification/v1 document.

    Enforces the maximum document size limit before decoding.
    """
    import json

    if isinstance(raw, bytes):
        if len(raw) > _MAX_DOC_BYTES:
            raise ClassificationError(
                f"classification document too large ({len(raw)} bytes); maximum is {_MAX_DOC_BYTES}"
            )
        text = raw.decode("utf-8")
    else:
        if len(raw.encode("utf-8")) > _MAX_DOC_BYTES:
            raise ClassificationError(
                f"classification document too large; maximum is {_MAX_DOC_BYTES} bytes"
            )
        text = raw

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ClassificationError(f"invalid JSON: {exc}") from exc

    return parse_classification(data)


def cell_id(use_case: ClassifiedUseCase) -> str:
    """Return the canonical cell id string, e.g. 'T2.L4'."""
    return f"{use_case.type}.{use_case.level}"
