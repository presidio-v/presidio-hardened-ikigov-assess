"""External evidence-backed affirmation (v0.13.0) — consumer side.

Lets the IKI-Gov assessment ingest **signed evidence references** emitted by peer
``presidio-hardened-*`` controls (first producer: ``presidio-hardened-ai``) and
upgrade affirmations from *self-attested* ("someone ticked it") to *affirmed-by-
evidence* — present, or cryptographically **verified** against a local trust store.

The ``EvidenceRef`` schema matches ``presidio-hardened-ikigov-assess`` PRESIDIO-REQ.md
v0.13.0 **verbatim** and is the cross-repo contract with the producer. Verification is
**fail-closed**: a missing, malformed, or wrong signature never counts as verified.

Wire format (must byte-match the producer): the detached signature is
``HMAC-SHA256(key, canonical_json({"content_hash": ..., "signer": ...}))`` where
``canonical_json`` is ``json.dumps(sort_keys=True, separators=(",", ":"),
ensure_ascii=False)``. Keys are resolved from a local trust store only — no network.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass

from presidio_ikigov_assess.checklist import VALID_ITEM_IDS

SCHEMA_ID = "presidio-hardened/evidence-ref@1"
_CONTRACT_FIELDS = (
    "item_id",
    "source",
    "source_version",
    "ledger_ref",
    "content_hash",
    "signer",
    "signature",
    "claimed_at",
)
_HEX_RE = re.compile(r"^[0-9a-f]{8,128}$")
_MAX_STR = 512

# Provenance states, weakest to strongest.
SELF = "self"
EVIDENCE = "evidence"
EVIDENCE_VERIFIED = "evidence-verified"


class EvidenceError(ValueError):
    """Raised when an evidence document or reference is malformed."""


@dataclass(frozen=True)
class EvidenceRef:
    item_id: str
    source: str
    source_version: str
    ledger_ref: str
    content_hash: str
    signer: str
    signature: str
    claimed_at: str


def _canonical(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        dict(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _hmac_hex(key: str, payload: Mapping[str, object]) -> str:
    return hmac.new(key.encode("utf-8"), _canonical(payload), hashlib.sha256).hexdigest()


def expected_signature(content_hash: str, signer: str, key: str) -> str:
    """The detached signature the producer would have written (wire-format)."""
    return _hmac_hex(key, {"content_hash": content_hash, "signer": signer})


def _str_field(raw: Mapping[str, object], name: str) -> str:
    value = raw.get(name)
    if not isinstance(value, str) or not value or len(value) > _MAX_STR:
        raise EvidenceError(f"evidence ref field '{name}' must be a non-empty string ≤{_MAX_STR}")
    if "\x00" in value:
        raise EvidenceError(f"evidence ref field '{name}' contains a null byte")
    return value


def _parse_ref(raw: object) -> EvidenceRef:
    if not isinstance(raw, Mapping):
        raise EvidenceError("each evidence entry must be an object")
    missing = [f for f in _CONTRACT_FIELDS if f not in raw]
    if missing:
        raise EvidenceError(f"evidence ref missing field(s): {', '.join(missing)}")
    fields = {name: _str_field(raw, name) for name in _CONTRACT_FIELDS}
    if fields["item_id"] not in VALID_ITEM_IDS:
        raise EvidenceError(
            f"evidence ref item_id is not a known checklist item: {fields['item_id']}"
        )
    if not _HEX_RE.match(fields["content_hash"]):
        raise EvidenceError("evidence ref content_hash must be lowercase hex")
    if not _HEX_RE.match(fields["signature"]):
        raise EvidenceError("evidence ref signature must be lowercase hex")
    return EvidenceRef(**fields)


def parse_document(doc: object) -> list[EvidenceRef]:
    """Parse a producer evidence document (the ``export_evidence`` JSON shape)."""
    if not isinstance(doc, Mapping) or "evidence" not in doc:
        raise EvidenceError("evidence document must be an object with an 'evidence' array")
    schema = doc.get("schema")
    if schema is not None and schema != SCHEMA_ID:
        raise EvidenceError(f"unsupported evidence schema: {schema!r} (expected {SCHEMA_ID!r})")
    entries = doc.get("evidence")
    if not isinstance(entries, list):
        raise EvidenceError("'evidence' must be an array")
    return [_parse_ref(entry) for entry in entries]


def load_evidence(text: str) -> list[EvidenceRef]:
    """Parse evidence document JSON text into validated refs."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"invalid evidence JSON: {exc.msg}") from exc
    return parse_document(doc)


SIGNING_ALGORITHMS = ("hmac-sha256", "ed25519")


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise EvidenceError(
            "Ed25519 evidence verification needs the optional extra: pip install "
            "'presidio-hardened-ikigov-assess[crypto]'"
        ) from exc
    return ed25519


def _normalise_entry(signer: str, value: object) -> dict[str, str]:
    """Normalise a trust entry to ``{'alg', 'material'}``.

    A bare string is an HMAC secret (back-compat). An object declares the signer's
    algorithm and key material:
    ``{'alg': 'hmac-sha256'|'ed25519', 'key'|'public_key': '<hex/secret>'}``.
    """
    if isinstance(value, str):
        return {"alg": "hmac-sha256", "material": value}
    if isinstance(value, Mapping):
        alg = value.get("alg", "hmac-sha256")
        if alg not in SIGNING_ALGORITHMS:
            raise EvidenceError(f"trust entry '{signer}': unknown alg {alg!r}")
        material = value.get("public_key") if alg == "ed25519" else value.get("key")
        material = material if material is not None else value.get("key") or value.get("public_key")
        if not isinstance(material, str) or not material:
            raise EvidenceError(f"trust entry '{signer}': missing key material")
        return {"alg": alg, "material": material}
    raise EvidenceError(f"trust entry '{signer}': must be a string or an object")


def load_trust_store(text: str) -> dict[str, dict[str, str]]:
    """Parse a trust-store JSON document into normalised ``{'alg', 'material'}`` entries.

    Each signer maps to either a bare HMAC-secret string (back-compat) or an object
    ``{'alg': 'hmac-sha256'|'ed25519', 'key'|'public_key': '<hex>'}``. Fails fast if an
    Ed25519 entry is present but the ``[crypto]`` extra is missing.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"invalid trust-store JSON: {exc.msg}") from exc
    if not isinstance(data, dict):
        raise EvidenceError("trust store must be a JSON object keyed by signer id")
    normalised = {signer: _normalise_entry(signer, value) for signer, value in data.items()}
    if any(entry["alg"] == "ed25519" for entry in normalised.values()):
        _require_crypto()  # fail fast with a clear message before verification
    return normalised


def _verify_hmac(content_hash: str, signer: str, signature: str, secret: str) -> bool:
    expected = expected_signature(content_hash, signer, secret)
    return hmac.compare_digest(expected, signature)


def _verify_ed25519(content_hash: str, signer: str, signature: str, public_key_hex: str) -> bool:
    from cryptography.exceptions import InvalidSignature

    ed25519 = _require_crypto()
    try:
        pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pk.verify(
            bytes.fromhex(signature),
            _canonical({"content_hash": content_hash, "signer": signer}),
        )
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_ref(ref: EvidenceRef, trust: Mapping[str, object]) -> bool:
    """Verify a ref's signature against the trust store (timing-safe, fail-closed).

    A trust value may be a bare HMAC-secret string (back-compat) or a normalised
    ``{'alg', 'material'}`` entry from :func:`load_trust_store` (HMAC or Ed25519).
    """
    entry = trust.get(ref.signer)
    if entry is None:
        return False
    norm = (
        entry
        if isinstance(entry, Mapping) and "material" in entry
        else _normalise_entry(ref.signer, entry)
    )
    if norm["alg"] == "ed25519":
        return _verify_ed25519(ref.content_hash, ref.signer, ref.signature, norm["material"])
    return _verify_hmac(ref.content_hash, ref.signer, ref.signature, norm["material"])


@dataclass(frozen=True)
class EvidenceResult:
    affirmed: frozenset[str]  # items affirmed by (counting) evidence
    provenance: dict[str, str]  # item_id -> EVIDENCE | EVIDENCE_VERIFIED
    refs_by_item: dict[str, EvidenceRef]  # the strongest ref per item
    n_refs: int
    n_verified: int


def classify(
    refs: list[EvidenceRef],
    trust: Mapping[str, str] | None,
    *,
    require_verified: bool = False,
) -> EvidenceResult:
    """Classify evidence refs into per-item provenance and the affirmed set.

    Each item's provenance is ``evidence-verified`` if any of its refs verifies
    against ``trust``, else ``evidence``. With ``require_verified`` (fail-closed),
    only items with a verified ref are counted as affirmed.
    """
    trust = trust or {}
    provenance: dict[str, str] = {}
    refs_by_item: dict[str, EvidenceRef] = {}
    n_verified = 0
    for ref in refs:
        verified = verify_ref(ref, trust)
        n_verified += int(verified)
        prov = EVIDENCE_VERIFIED if verified else EVIDENCE
        # Keep the strongest provenance (verified beats present) per item.
        if provenance.get(ref.item_id) != EVIDENCE_VERIFIED:
            provenance[ref.item_id] = prov
            refs_by_item[ref.item_id] = ref
    if require_verified:
        affirmed = {item for item, prov in provenance.items() if prov == EVIDENCE_VERIFIED}
    else:
        affirmed = set(provenance)
    return EvidenceResult(
        affirmed=frozenset(affirmed),
        provenance={i: p for i, p in provenance.items() if i in affirmed},
        refs_by_item={i: r for i, r in refs_by_item.items() if i in affirmed},
        n_refs=len(refs),
        n_verified=n_verified,
    )


def merge_provenance(
    affirmed: frozenset[str], evidence_provenance: Mapping[str, str]
) -> dict[str, str]:
    """Provenance for every affirmed item: evidence(-verified) where present, else self."""
    return {item: evidence_provenance.get(item, SELF) for item in sorted(affirmed)}


def evidence_coverage(provenance: Mapping[str, str]) -> dict[str, object]:
    """Coverage signal over affirmed items — orthogonal to maturity (how verifiable)."""
    total = len(provenance)
    backed = sum(1 for p in provenance.values() if p in (EVIDENCE, EVIDENCE_VERIFIED))
    verified = sum(1 for p in provenance.values() if p == EVIDENCE_VERIFIED)
    pct = (backed / total * 100.0) if total else 0.0
    vpct = (verified / total * 100.0) if total else 0.0
    return {
        "affirmed_total": total,
        "evidence_backed": backed,
        "verified": verified,
        "evidence_coverage_pct": round(pct, 1),
        "verified_coverage_pct": round(vpct, 1),
    }
