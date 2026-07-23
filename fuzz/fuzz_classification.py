"""Atheris property fuzzer for :func:`presidio_ikigov_assess.classification.parse_classification_bytes`.

``parse_classification_bytes`` is the untrusted-input boundary for producer
``eai-classification/v1`` documents: it decodes bytes/str, size-checks, parses
JSON, then validates and normalises every use case. Because producers are
arbitrary third-party tools, the whole decode -> json -> validate -> normalise
path must be fail-closed — the only thing that may ever escape is
:class:`~presidio_ikigov_assess.classification.ClassificationError` (a valid
document parses; anything else raises it). This harness drives that boundary
from ``FuzzedDataProvider`` in two modes and asserts:

* fail-closed    — arbitrary bytes fed straight in raise ``ClassificationError``
                   or succeed; no ``UnicodeError``/``RecursionError``/other
                   exception may leak;
* normalisation  — on a successfully parsed document, each use case satisfies
                   ``level == "L6" if ecosystem else base_level`` (the L6
                   ecosystem overlay), ``base_level`` equals the declared level,
                   and ``cell_id(uc) == f"{uc.type}.{uc.level}"``;
* determinism    — parsing the same bytes twice yields equal documents;
* contradiction  — ``level=L6`` with an explicit ``ecosystem=false`` is always
                   rejected (the non-ordinal L6 regime admits no exceptions).
"""

from __future__ import annotations

import json
import sys

import atheris

from presidio_ikigov_assess.classification import (
    ClassificationError,
    cell_id,
    parse_classification_bytes,
)

_SCHEMA = "eai-classification/v1"
_TYPES = tuple(f"T{i}" for i in range(1, 7))
_LEVELS = tuple(f"L{i}" for i in range(1, 7))


def _maybe(fdp: atheris.FuzzedDataProvider, valid: tuple[str, ...]) -> object:
    """Return either a valid token (bias toward acceptance) or arbitrary garbage."""
    if fdp.ConsumeBool():
        return valid[fdp.ConsumeIntInRange(0, len(valid) - 1)]
    return fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 12))


def _build_use_case(fdp: atheris.FuzzedDataProvider) -> dict[str, object]:
    """Build one semi-valid use-case dict with independently mutated fields."""
    uc: dict[str, object] = {
        "id": _maybe(fdp, (f"uc-{fdp.ConsumeIntInRange(0, 99)}",)),
        "type": _maybe(fdp, _TYPES),
        "level": _maybe(fdp, _LEVELS),
    }
    if fdp.ConsumeBool():
        uc["ecosystem"] = fdp.ConsumeBool()
    if fdp.ConsumeBool():
        uc["confidence"] = fdp.ConsumeProbability()
    if fdp.ConsumeBool():
        uc["name"] = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 20))
    if fdp.ConsumeBool():
        uc["tags"] = [
            fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 8))
            for _ in range(fdp.ConsumeIntInRange(0, 4))
        ]
    return uc


def _assert_document_invariants(text: str) -> None:
    """Parse ``text`` and, on success, assert the normalisation invariants."""
    try:
        doc = parse_classification_bytes(text)
    except ClassificationError:
        return  # fail-closed rejection is the expected outcome for bad input

    if doc != parse_classification_bytes(text):
        raise AssertionError(f"non-deterministic parse for {text!r}")

    for uc in doc.use_cases:
        expected_level = "L6" if uc.ecosystem else uc.base_level
        if uc.level != expected_level:
            raise AssertionError(f"level normalisation broken: {uc!r}")
        if uc.base_level not in _LEVELS:
            raise AssertionError(f"base_level not a declared level: {uc!r}")
        if cell_id(uc) != f"{uc.type}.{uc.level}":
            raise AssertionError(f"cell_id disagrees with fields: {uc!r}")


def _assert_l6_contradiction_rejected() -> None:
    """``level=L6`` + explicit ``ecosystem=false`` must always fail closed."""
    contradiction = json.dumps(
        {
            "schema": _SCHEMA,
            "use_cases": [{"id": "x", "type": "T1", "level": "L6", "ecosystem": False}],
        }
    )
    try:
        parse_classification_bytes(contradiction)
    except ClassificationError:
        return
    raise AssertionError("L6 + ecosystem=false was not rejected as a contradiction")


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris entrypoint contract)
    fdp = atheris.FuzzedDataProvider(data)

    if fdp.ConsumeBool():
        # Mode (a): arbitrary bytes straight in — only ClassificationError may escape.
        raw = fdp.ConsumeBytes(fdp.remaining_bytes())
        try:
            parse_classification_bytes(raw)
        except ClassificationError:
            pass
    else:
        # Mode (b): structure-aware document, validated for its invariants on success.
        doc: dict[str, object] = {
            "schema": _SCHEMA if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(8),
            "use_cases": [_build_use_case(fdp) for _ in range(fdp.ConsumeIntInRange(0, 5))],
        }
        _assert_document_invariants(json.dumps(doc))

    _assert_l6_contradiction_rejected()


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
