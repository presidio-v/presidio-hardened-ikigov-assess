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

Assurance tiers (``evidence-ref@2``, presidio-evidence ADR-0003)
-----------------------------------------------------------------
An ``@2`` document is the ``@1`` shape with the envelope ``schema`` REQUIRED and
one additive optional per-ref field, ``assurance_tier`` ∈ {``attested``,
``optimistic``, ``zk``} (default ``attested`` when absent). The signed message is
unchanged, so ``@1`` and ``@2`` refs verify identically. Declared tiers are
honoured **only under ``@2``**: an ``@1`` record carrying ``assurance_tier`` is an
inert extra that resolves to ``attested`` (the @1 schema has no
``additionalProperties: false``; the family golden vector
``evidence-ref-v2/valid-v1-with-extra-tier`` pins this). A tier is a producer's
*declaration* of the regime the referenced evidence lives under; this consumer
verifies signatures only, so it never upgrades a declared tier into a verified one.
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
SCHEMA_ID_V2 = "presidio-hardened/evidence-ref@2"
#: Accepted envelope schemas (fail-closed on anything else).
SCHEMA_IDS = (SCHEMA_ID, SCHEMA_ID_V2)

#: Assurance tiers, weakest to strongest (ADR-0003 / CJ Pillar II).
ASSURANCE_TIERS = ("attested", "optimistic", "zk")
DEFAULT_ASSURANCE_TIER = "attested"
TIER_RANK = {tier: rank for rank, tier in enumerate(ASSURANCE_TIERS)}

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
_HEX_RE = re.compile(r"^[0-9a-f]{8,128}\Z")
_MAX_STR = 512

# Provenance states, weakest to strongest.
SELF = "self"
EVIDENCE = "evidence"
EVIDENCE_VERIFIED = "evidence-verified"

#: Answer status of a self-attested item under ``--require-evidence``: recorded,
#: shown in every output, and **not counted** as affirmed (v0.26.0 S-1).
ASSERTED = "asserted"


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
    #: Declared assurance regime (ADR-0003). Not part of the signed message.
    assurance_tier: str = DEFAULT_ASSURANCE_TIER


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


def parse_assurance_tier(raw: object) -> str:
    """Validate a declared ``assurance_tier`` value (fail-closed on anything unknown)."""
    if not isinstance(raw, str) or raw not in ASSURANCE_TIERS:
        raise EvidenceError(
            f"evidence ref assurance_tier must be one of {', '.join(ASSURANCE_TIERS)}"
        )
    return raw


def _parse_ref(raw: object, *, honour_tiers: bool = False) -> EvidenceRef:
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
    # ADR-0003: a declared tier is honoured only under @2; under @1 it is inert.
    tier = DEFAULT_ASSURANCE_TIER
    if honour_tiers and "assurance_tier" in raw:
        tier = parse_assurance_tier(raw["assurance_tier"])
    return EvidenceRef(**fields, assurance_tier=tier)


def parse_document(doc: object) -> list[EvidenceRef]:
    """Parse a producer evidence document (the ``export_evidence`` JSON shape).

    Accepts ``evidence-ref@1`` (``schema`` optional, back-compat) and
    ``evidence-ref@2`` (``schema`` required by construction: only a document that
    *names* @2 is read as @2). Declared ``assurance_tier`` values are honoured
    only under @2 and must be a known tier; anything else fails closed.
    """
    if not isinstance(doc, Mapping) or "evidence" not in doc:
        raise EvidenceError("evidence document must be an object with an 'evidence' array")
    schema = doc.get("schema")
    if schema is not None and schema not in SCHEMA_IDS:
        raise EvidenceError(
            f"unsupported evidence schema: {schema!r} (expected one of {', '.join(SCHEMA_IDS)})"
        )
    entries = doc.get("evidence")
    if not isinstance(entries, list):
        raise EvidenceError("'evidence' must be an array")
    honour_tiers = schema == SCHEMA_ID_V2
    return [_parse_ref(entry, honour_tiers=honour_tiers) for entry in entries]


def load_evidence(text: str) -> list[EvidenceRef]:
    """Parse evidence document JSON text into validated refs."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"invalid evidence JSON: {exc.msg}") from exc
    except RecursionError as exc:
        raise EvidenceError("evidence document nesting too deep") from exc
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


def _normalise_entry(signer: str, value: object) -> dict[str, object]:
    """Normalise a trust entry to ``{'alg', 'keys'}`` (``keys`` is always a list).

    A bare string is an HMAC secret (back-compat). An object declares the signer's
    algorithm and key material, which may be a single value **or a list** so a signer
    can have several active keys during rotation:
    ``{'alg': 'hmac-sha256'|'ed25519', 'key'|'public_key': '<hex>' | ['<hex>', ...]}``.
    """
    if isinstance(value, str):
        return {"alg": "hmac-sha256", "keys": [value]}
    if isinstance(value, Mapping):
        alg = value.get("alg", "hmac-sha256")
        if alg not in SIGNING_ALGORITHMS:
            raise EvidenceError(f"trust entry '{signer}': unknown alg {alg!r}")
        raw = value.get("public_key") if alg == "ed25519" else value.get("key")
        raw = raw if raw is not None else (value.get("key") or value.get("public_key"))
        keys = [raw] if isinstance(raw, str) else raw
        if (
            not isinstance(keys, list)
            or not keys
            or not all(isinstance(k, str) and k for k in keys)
        ):
            raise EvidenceError(f"trust entry '{signer}': missing or invalid key material")
        return {"alg": alg, "keys": list(keys)}
    raise EvidenceError(f"trust entry '{signer}': must be a string or an object")


def load_trust_store(text: str) -> dict[str, dict[str, object]]:
    """Parse a trust-store JSON document into normalised ``{'alg', 'keys'}`` entries.

    Each signer maps to either a bare HMAC-secret string (back-compat) or an object
    ``{'alg': 'hmac-sha256'|'ed25519', 'key'|'public_key': '<hex>' | ['<hex>', ...]}``.
    A list of keys supports rotation (any listed key may verify). Fails fast if an
    Ed25519 entry is present but the ``[crypto]`` extra is missing.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"invalid trust-store JSON: {exc.msg}") from exc
    except RecursionError as exc:
        raise EvidenceError("trust-store document nesting too deep") from exc
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
    ``{'alg', 'keys'}`` entry from :func:`load_trust_store`. Verification succeeds if
    the signature matches **any** listed key, which is what allows key rotation.
    """
    entry = trust.get(ref.signer)
    if entry is None:
        return False
    norm = (
        entry
        if isinstance(entry, Mapping) and "keys" in entry
        else _normalise_entry(ref.signer, entry)
    )
    verify = _verify_ed25519 if norm["alg"] == "ed25519" else _verify_hmac
    return any(verify(ref.content_hash, ref.signer, ref.signature, key) for key in norm["keys"])


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


@dataclass(frozen=True)
class Affirmations:
    """The resolved answer set every command scores, gates and renders from.

    ``affirmed`` is what counts. ``asserted`` is what the assessor claimed
    without verified evidence while ``require_evidence`` was in force: it is
    carried so every output can show it, and it is never scored. ``provenance``
    covers ``affirmed`` and ``asserted``; ``coverage`` is computed over
    ``affirmed`` only and records the policy that produced it.
    """

    affirmed: frozenset[str]
    skipped: frozenset[str]
    asserted: frozenset[str]
    provenance: dict[str, str]
    coverage: dict[str, object]
    require_evidence: bool
    n_refs: int = 0
    n_verified: int = 0


def resolve_affirmations(
    self_affirmed: frozenset[str],
    skipped: frozenset[str],
    refs: list[EvidenceRef] | None,
    trust: Mapping[str, object] | None,
    *,
    require_evidence: bool = False,
) -> Affirmations:
    """Merge self-attested answers with signed evidence under one policy.

    This is the single merge point for ``--affirm`` / the wizard, ``--evidence``
    and ``--require-evidence`` (v0.26.0 S-1). Without ``require_evidence`` the
    behaviour is the v0.13.0 one: self-attested items count, evidence adds
    items, and an item explicitly skipped is never affirmed by evidence.

    With ``require_evidence`` the flag means what it says: **only an item whose
    evidence-ref verifies against ``trust`` is affirmed**. A self-attested item
    without such a ref is *asserted*: kept, shown, not counted. With no
    ``refs`` or no ``trust`` nothing can verify, so nothing is affirmed. This
    is fail-closed by construction: the counted set is a subset of the verified
    set, whatever else was supplied.
    """
    result = classify(list(refs or []), trust, require_verified=require_evidence)
    self_affirmed = frozenset(self_affirmed) - skipped
    via_evidence = result.affirmed - skipped
    if require_evidence:
        affirmed = via_evidence
        asserted = self_affirmed - via_evidence
    else:
        affirmed = self_affirmed | via_evidence
        asserted = frozenset()
    provenance = merge_provenance(affirmed, result.provenance)
    for item in sorted(asserted):
        provenance[item] = SELF
    coverage = evidence_coverage({i: p for i, p in provenance.items() if i in affirmed})
    coverage["require_evidence"] = require_evidence
    coverage["asserted_not_counted"] = len(asserted)
    return Affirmations(
        affirmed=affirmed,
        skipped=frozenset(skipped),
        asserted=asserted,
        provenance=provenance,
        coverage=coverage,
        require_evidence=require_evidence,
        n_refs=result.n_refs,
        n_verified=result.n_verified,
    )


def evidence_block(aff: Affirmations) -> dict[str, object]:
    """The per-item evidence marking block shared by every JSON output."""
    prov = aff.provenance
    return {
        "require_evidence": aff.require_evidence,
        "verified": sorted(i for i in aff.affirmed if prov.get(i) == EVIDENCE_VERIFIED),
        "evidence_backed": sorted(i for i in aff.affirmed if prov.get(i) == EVIDENCE),
        "self_attested": sorted(i for i in aff.affirmed if prov.get(i, SELF) == SELF),
        "asserted_not_counted": sorted(aff.asserted),
    }


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
