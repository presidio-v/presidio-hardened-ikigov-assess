"""Atheris property fuzzer for :mod:`presidio_ikigov_assess.evidence` document loaders.

``load_evidence`` and ``load_trust_store`` are the untrusted-input boundary for
peer-produced evidence documents and locally-configured trust stores. Both are
contractually fail-closed: a malformed, oversized, or hostile document must raise
:class:`~presidio_ikigov_assess.evidence.EvidenceError` and never any other
exception (no ``JSONDecodeError``/``RecursionError`` leak). This harness drives
both loaders from ``FuzzedDataProvider`` — with arbitrary text and with
structure-aware JSON — and asserts:

* fail-closed    — only ``EvidenceError`` may escape either loader;
* ref invariants — every parsed :class:`EvidenceRef` has non-empty string fields
                   of at most 512 chars, with ``content_hash`` and ``signature``
                   lowercase hex;
* determinism    — ``expected_signature(h, s, k)`` is a pure function (two calls
                   are byte-identical);
* round-trip     — a ref carrying ``expected_signature`` for its own
                   ``(content_hash, signer)`` verifies against a matching
                   single-key HMAC trust store entry (fail-closed never means
                   fail-wrong: a correct signature must verify).
"""

from __future__ import annotations

import json
import sys

import atheris

from presidio_ikigov_assess.evidence import (
    _CONTRACT_FIELDS,
    _HEX_RE,
    _MAX_STR,
    EvidenceError,
    EvidenceRef,
    expected_signature,
    load_evidence,
    load_trust_store,
    verify_ref,
)

_HEX_ALPHABET = "0123456789abcdef"


def _hex_string(fdp: atheris.FuzzedDataProvider, length: int) -> str:
    return "".join(_HEX_ALPHABET[fdp.ConsumeIntInRange(0, 15)] for _ in range(length))


def _build_ref_dict(fdp: atheris.FuzzedDataProvider) -> dict[str, object]:
    """Build one semi-valid evidence-ref dict with independently mutated fields."""
    ref: dict[str, object] = {}
    for name in _CONTRACT_FIELDS:
        if not fdp.ConsumeBool():
            continue  # sometimes omit the field entirely (missing-field path)
        if name in ("content_hash", "signature") and fdp.ConsumeBool():
            ref[name] = _hex_string(fdp, fdp.ConsumeIntInRange(8, 64))
        else:
            ref[name] = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 16))
    return ref


def _assert_ref_invariants(text: str) -> None:
    """Parse an evidence document and, on success, assert per-ref invariants."""
    try:
        refs = load_evidence(text)
    except EvidenceError:
        return

    for ref in refs:
        for name in _CONTRACT_FIELDS:
            value = getattr(ref, name)
            if not isinstance(value, str) or not value or len(value) > _MAX_STR:
                raise AssertionError(f"ref field {name!r} violates the string contract: {ref!r}")
        if not _HEX_RE.match(ref.content_hash):
            raise AssertionError(f"content_hash is not lowercase hex: {ref!r}")
        if not _HEX_RE.match(ref.signature):
            raise AssertionError(f"signature is not lowercase hex: {ref!r}")


def _assert_signature_properties(fdp: atheris.FuzzedDataProvider) -> None:
    """``expected_signature`` is deterministic and round-trips through ``verify_ref``."""
    content_hash = _hex_string(fdp, fdp.ConsumeIntInRange(8, 64))
    signer = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 16)) or "signer"
    key = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 24)) or "key"

    sig = expected_signature(content_hash, signer, key)
    if sig != expected_signature(content_hash, signer, key):
        raise AssertionError("expected_signature is non-deterministic")

    ref = EvidenceRef(
        item_id="D1",
        source="fuzz",
        source_version="0",
        ledger_ref="fuzz:0",
        content_hash=content_hash,
        signer=signer,
        signature=sig,
        claimed_at="2026-01-01T00:00:00+00:00",
    )
    if verify_ref(ref, {signer: key}) is not True:
        raise AssertionError(f"correctly-signed ref failed to verify: {ref!r}")


def TestOneInput(data: bytes) -> None:  # noqa: N802 (Atheris entrypoint contract)
    fdp = atheris.FuzzedDataProvider(data)

    mode = fdp.ConsumeIntInRange(0, 2)
    if mode == 0:
        # Arbitrary text into both loaders — only EvidenceError may escape.
        text = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 256))
        try:
            load_evidence(text)
        except EvidenceError:
            pass
        try:
            load_trust_store(text)
        except EvidenceError:
            pass
    elif mode == 1:
        # Structure-aware evidence document; ref invariants asserted on success.
        doc = {
            "schema": "presidio-hardened/evidence-ref@1",
            "evidence": [_build_ref_dict(fdp) for _ in range(fdp.ConsumeIntInRange(0, 4))],
        }
        _assert_ref_invariants(json.dumps(doc))
    else:
        # Structure-aware trust store — only EvidenceError may escape.
        store: dict[str, object] = {}
        for _ in range(fdp.ConsumeIntInRange(0, 4)):
            signer = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(1, 12)) or "s"
            if fdp.ConsumeBool():
                store[signer] = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 16))
            else:
                store[signer] = {
                    "alg": "hmac-sha256" if fdp.ConsumeBool() else "ed25519",
                    "key": _hex_string(fdp, fdp.ConsumeIntInRange(0, 64)),
                }
        try:
            load_trust_store(json.dumps(store))
        except EvidenceError:
            pass

    _assert_signature_properties(fdp)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
