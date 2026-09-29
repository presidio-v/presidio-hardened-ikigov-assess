"""Gate certificates (v0.23.0) — *the certificate is the proof*.

Today a gate decision (OPEN / PARTIAL / BLOCKED) is computed by ``iga`` and
trusted because the tool ran. A **gate certificate** inverts that: it is a
compact, signed artifact that any third party verifies *locally* against a
trust store, **without running ikigov-assess and without the assessments DB**.
It carries its own grounding — the sufficient affirmation set, every embedded
evidence-ref, and the *decision predicate inputs* — so a verifier recomputes
the gate decision from the certificate alone and compares it to the claim.

This is the product-form of the owner's Computational Jurisprudence program
(Stantchev, arXiv 2026): local verification, no engine in the trust path,
fail-closed. It is the contrast to centralized policy-decision points
(Cedar / Zanzibar class), where the verdict is trusted because a service
returned it.

Scope of the claim (no overclaiming)
------------------------------------
A gate certificate proves that, **under the declared predicate and the embedded
affirmation set / evidence**, the gate decision recomputes to the claimed
value. It does **not** prove that the underlying controls are effective, nor
that the evidence's real-world claim is true — only that the signed evidence
verifies and the recorded partition yields the recorded decision.

Canonicalization & signing (shared with the family)
---------------------------------------------------
The certificate reuses the family canonical-JSON + SHA-256 + detached-signature
conventions already in this repo (``evidence.py``, ``sovereignty.py``,
``workshop.py``, ``content/pack.py``):

* canonical bytes = ``json.dumps(obj, sort_keys=True, separators=(",", ":"),
  ensure_ascii=False).encode("utf-8")``;
* ``content_hash`` = ``sha256_hex(canonical_bytes(...))``;
* the **issuer signature** is a detached signature over the canonical bytes of
  the certificate **with the ``signature`` field removed** (documented below),
  verified against a trust store exactly like an evidence-ref — HMAC-SHA256 or
  Ed25519, resolved through :func:`evidence.load_trust_store` /
  :func:`evidence.verify_ref` semantics. Fail-closed: a missing, malformed, or
  wrong signature never verifies.

``framework_content_hash`` pins the **decision predicate content** — the
per-gate item mapping and per-risk weights of the checklist that was assessed —
so a verifier can confirm it is recomputing under the same rule the issuer used
(see :func:`gate_predicate_content_hash`). This is what makes the certificate
the *proof* of the decision rather than an assertion about it.

Assurance tier, grounding, lineage, validity (additive within @1)
---------------------------------------------------------------------
Four optional fields were added after v0.23.0. All sit inside the signed
content; none is required, so pre-existing certificates verify unchanged
(ADR-0001 D5: additive optional fields stay within the major version).

* ``assurance_tier`` — the tier at which **this certificate** is verifiable.
  It is ``attested`` (the issuer signature) and nothing else: this verifier
  checks signatures and recomputes a predicate, so it can never verify an
  ``optimistic`` or ``zk`` certificate and rejects one fail-closed
  (``unsupported-assurance-tier``). A zk gate certificate is a research item,
  not a value of this field.
* Per embedded evidence-ref, ``assurance_tier`` round-trips the producer's
  *declared* tier (evidence-ref@2, ADR-0003; ``attested`` when absent). It is a
  declaration: the verifier re-checks the ref's signature, never its fraud
  proof or zk proof, and reports the weakest declared tier so a caller can
  demand a minimum (``evidence-tier-below-minimum``).
* ``grounding`` — the weakest provenance in the affirmation set: ``self`` if
  any affirmed gate item has no embedded evidence-ref, else
  ``evidence-verified``. Recorded because a self-attestation by a named
  signer is *not* the attested tier: it is an unbonded assertion, which in
  Computational Jurisprudence terms is the optimistic tier minus its bond.
  The verifier recomputes it (``grounding-mismatch``) and can demand
  ``evidence-verified`` (``grounding-below-minimum``).
* ``parents`` — ADR-0002 provenance-parents: content hashes of the upstream
  evidence this decision rests on (the eai-classification document, the
  workshop manifest). Inside the signed content, so lineage cannot be
  rewired after signing; acyclic by construction; omitted when empty.
  Resolving a parent is the consumer's walk (P4), not this verifier's.
* ``not_after`` — validity bound (RFC 3339, UTC ``Z``). Expiry is the
  creed-compatible revocation: no list, no accumulator, no coordination. A
  verifier fails closed past it (``expired``); an absent bound means the
  pre-v0.26 behaviour, no expiry.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from presidio_ikigov_assess.checklist import (
    ITEMS_BY_GATE,
    RISK_WEIGHTS,
    VALID_GATES,
    VALID_RISK_CLASSES,
)
from presidio_ikigov_assess.evidence import (
    ASSURANCE_TIERS,
    DEFAULT_ASSURANCE_TIER,
    TIER_RANK,
    EvidenceRef,
    verify_ref,
)
from presidio_ikigov_assess.gates import GateResult, GateStatus, evaluate_gate

CERTIFICATE_SCHEMA = "presidio-hardened/gate-certificate@1"

#: The only tier this certificate format can be verified at (see module doc).
CERTIFICATE_ASSURANCE_TIER = DEFAULT_ASSURANCE_TIER

#: Grounding of the affirmation set, weakest to strongest.
GROUNDING_SELF = "self"
GROUNDING_EVIDENCE_VERIFIED = "evidence-verified"
GROUNDINGS = (GROUNDING_SELF, GROUNDING_EVIDENCE_VERIFIED)
GROUNDING_RANK = {g: rank for rank, g in enumerate(GROUNDINGS)}

#: Family hex rule for content hashes (ADR-0002 P2, mirrors evidence.py).
_HEX_RE = re.compile(r"^[0-9a-f]{8,128}$")
#: Strict RFC 3339 UTC form this module emits and accepts.
_TIMESTAMP_FMT = "%Y-%m-%dT%H:%M:%SZ"
_MAX_PARENTS = 64

#: Per-item provenance markers carried in the affirmation set (mirrors evidence.py).
STATUS_AFFIRMED = "affirmed"
STATUS_SKIPPED = "skipped"
STATUS_DENIED = "denied"

_MAX_STR = 512


class CertificateError(ValueError):
    """Raised when a certificate is malformed (fail-closed, nothing trusted)."""


# ── Canonical layer (family profile: sorted keys, compact, UTF-8) ────────────


def canonical_bytes(payload: object) -> bytes:
    """Family canonical JSON: sorted keys, compact separators, UTF-8."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_hex(payload: object) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


# ── Decision predicate content hash ──────────────────────────────────────────


def gate_predicate_content_hash() -> str:
    """SHA-256 over the gate-decision predicate content of the built-in checklist.

    Pins exactly the inputs the gate rule reads: the per-gate item mapping and
    the per-item, per-risk-class weights. A verifier recomputing the decision
    checks this hash against the certificate's ``framework_content_hash`` so it
    knows it evaluates under the same rule content the issuer used. Independent
    of item text / language (which the decision does not depend on).
    """
    payload = {
        "gates": {
            gate: sorted(item.id for item in ITEMS_BY_GATE[gate]) for gate in sorted(VALID_GATES)
        },
        "weights": {
            item.id: {k: item.weight(k) for k in sorted(RISK_WEIGHTS)}
            for gate in sorted(VALID_GATES)
            for item in ITEMS_BY_GATE[gate]
        },
    }
    return sha256_hex(payload)


# ── Certificate assembly ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class GateCertificate:
    """In-memory view of a gate certificate (before/after signing)."""

    document: dict[str, object]

    @property
    def decision(self) -> str:
        return str(self.document.get("decision", ""))

    @property
    def gate(self) -> str:
        return str(self.document.get("gate", ""))


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime(_TIMESTAMP_FMT)


def now_iso() -> str:
    """Current UTC instant in the strict form this module emits."""
    return _iso_now()


def add_days(timestamp: str, days: int) -> str:
    """``timestamp`` plus ``days`` (strict UTC form in, strict UTC form out)."""
    parsed = parse_timestamp(timestamp)
    if parsed is None or days < 0:
        raise CertificateError("add_days needs a strict UTC timestamp and days >= 0")
    return (parsed + timedelta(days=days)).strftime(_TIMESTAMP_FMT)


def parse_timestamp(value: object) -> Optional[datetime]:
    """Parse the strict UTC form ``YYYY-MM-DDTHH:MM:SSZ``; ``None`` if malformed."""
    if not isinstance(value, str) or len(value) != 20:
        return None
    try:
        return datetime.strptime(value, _TIMESTAMP_FMT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _validate_parents(parents: Sequence[str]) -> list[str]:
    """ADR-0002 P2/P3: lowercase-hex hashes, non-empty, order-preserving, no duplicates."""
    if not isinstance(parents, (list, tuple)):
        raise CertificateError("parents must be a list of content hashes")
    if len(parents) > _MAX_PARENTS:
        raise CertificateError(f"too many parents (max {_MAX_PARENTS})")
    out: list[str] = []
    for entry in parents:
        if not isinstance(entry, str) or not _HEX_RE.match(entry):
            raise CertificateError("each parent must be a lowercase-hex content hash")
        if entry in out:
            raise CertificateError(f"duplicate parent {entry}")
        out.append(entry)
    return out


def _grounding_of(items: Sequence[Mapping[str, object]]) -> str:
    """Weakest provenance over the *affirmed* items of an affirmation set."""
    for entry in items:
        if entry.get("status") == STATUS_AFFIRMED and entry.get("evidence_ref") is None:
            return GROUNDING_SELF
    return GROUNDING_EVIDENCE_VERIFIED


def _sufficient_affirmation_set(
    result: GateResult,
    affirmed: frozenset[str],
    evidence_refs: Mapping[str, EvidenceRef],
) -> list[dict[str, object]]:
    """The per-item status list for every item mapped to the gate.

    For each gate-mapped item: ``affirmed`` / ``skipped`` / ``denied`` from the
    same partition the gate engine uses (:func:`gates.evaluate_gate`). Where an
    item was affirmed via a signed evidence-ref, the ref is embedded verbatim so
    the certificate carries its own grounding. Deterministically ordered.
    """
    skipped_ids = {i.id for i in result.skipped_items}
    denied_ids = {i.id for i in result.blocking_items}
    items: list[dict[str, object]] = []
    for item in sorted(ITEMS_BY_GATE[result.gate], key=lambda i: i.id):
        if item.id in skipped_ids:
            status = STATUS_SKIPPED
        elif item.id in denied_ids:
            status = STATUS_DENIED
        elif item.id in affirmed:
            status = STATUS_AFFIRMED
        else:
            # Defensive: a gate-mapped item not in any partition bucket cannot
            # occur (the engine covers all three), but fail-closed to denied.
            status = STATUS_DENIED
        entry: dict[str, object] = {"id": item.id, "status": status}
        ref = evidence_refs.get(item.id)
        if ref is not None and status == STATUS_AFFIRMED:
            entry["evidence_ref"] = {
                "content_hash": ref.content_hash,
                "signer": ref.signer,
                "signature": ref.signature,
                "claimed_at": ref.claimed_at,
                # item_id/source/source_version/ledger_ref round-trip the full
                # ref so verify_ref can re-check it against the trust store.
                "item_id": ref.item_id,
                "source": ref.source,
                "source_version": ref.source_version,
                "ledger_ref": ref.ledger_ref,
                # Declared regime of the referenced evidence (ADR-0003); a
                # declaration the issuer verified the *signature* of, no more.
                "assurance_tier": ref.assurance_tier,
            }
        items.append(entry)
    return items


def build_certificate(
    *,
    use_case: str,
    gate: str,
    risk_class: str,
    affirmed: frozenset[str],
    skipped: frozenset[str],
    strict: bool = False,
    evidence_refs: Optional[Mapping[str, EvidenceRef]] = None,
    issuer: str,
    framework_content_hash: Optional[str] = None,
    assessed_at: Optional[str] = None,
    parents: Optional[Sequence[str]] = None,
    not_after: Optional[str] = None,
    require_evidence: bool = False,
) -> dict[str, object]:
    """Build (unsigned) the gate certificate document for a single gate.

    ``require_evidence`` records that the issuer counted only evidence-verified
    affirmations (the caller has already dropped the rest); it is written into
    the signed content only when true, so older certificates are byte-stable.

    Recomputes the gate decision via :func:`gates.evaluate_gate` (the one
    authority), records the sufficient affirmation set with embedded
    evidence-refs, and embeds the **decision predicate inputs** — the gate's
    item ids, the risk class, the effective strict flag, and the predicate
    content hash — so a verifier can recompute the decision from the
    certificate alone. The ``signature`` field is added later by :func:`sign`.

    ``parents`` (ADR-0002) and ``not_after`` are optional and validated
    fail-closed; ``not_after`` must be the strict UTC form and must not
    precede ``assessed_at``.
    """
    if gate not in VALID_GATES:
        raise CertificateError(f"unknown gate {gate!r}")
    if risk_class not in VALID_RISK_CLASSES:
        raise CertificateError(f"unknown risk_class {risk_class!r}")
    evidence_refs = dict(evidence_refs or {})
    result = evaluate_gate(gate, affirmed, skipped, risk_class, strict)

    predicate_hash = framework_content_hash or gate_predicate_content_hash()
    strict_effective = strict or risk_class == "high"
    assessed_at = assessed_at or _iso_now()

    if not_after is not None:
        bound = parse_timestamp(not_after)
        if bound is None:
            raise CertificateError("not_after must be UTC 'YYYY-MM-DDTHH:MM:SSZ'")
        issued = parse_timestamp(assessed_at)
        if issued is None:
            raise CertificateError(
                "assessed_at must be UTC 'YYYY-MM-DDTHH:MM:SSZ' when not_after is set"
            )
        if bound < issued:
            raise CertificateError("not_after precedes assessed_at")
    parent_list = _validate_parents(parents) if parents else []

    affirmation_set = _sufficient_affirmation_set(result, affirmed, evidence_refs)
    document: dict[str, object] = {
        "schema": CERTIFICATE_SCHEMA,
        "use_case": use_case,
        "framework_content_hash": predicate_hash,
        "gate": gate,
        "risk_class": risk_class,
        "decision": result.status.value,
        "assurance_tier": CERTIFICATE_ASSURANCE_TIER,
        "grounding": _grounding_of(affirmation_set),
        "affirmation_set": affirmation_set,
        # ── Decision predicate inputs (recompute the gate rule) ──────────────
        # A verifier feeds affirmation_set + these into the same partition/policy
        # the engine uses and must arrive at `decision`. gate_items pins which
        # items the rule ranges over; strict/risk_class pin the policy branch.
        "predicate": {
            "gate_items": sorted(item.id for item in ITEMS_BY_GATE[gate]),
            "risk_class": risk_class,
            "strict": bool(strict),
            "strict_effective": bool(strict_effective),
            "predicate_content_hash": predicate_hash,
        },
        "assessed_at": assessed_at,
        "issuer": issuer,
    }
    # ADR-0002 P3: omitted when empty. Absent not_after = no expiry (pre-v0.26).
    if parent_list:
        document["parents"] = parent_list
    if not_after is not None:
        document["not_after"] = not_after
    if require_evidence:
        document["require_evidence"] = True
    return document


# ── Signing (detached over canonical bytes minus the signature field) ────────


def signing_bytes(document: Mapping[str, object]) -> bytes:
    """Canonical bytes signed by the issuer: the document minus ``signature``.

    Exact rule: drop the top-level ``signature`` key (if present), then
    canonical-JSON the remainder (sorted keys, compact, UTF-8). This is the same
    "sign the canonical content, keep the signature outside the signed bytes"
    discipline used by the workshop manifest owner-signing.
    """
    stripped = {k: v for k, v in document.items() if k != "signature"}
    return canonical_bytes(stripped)


def _hmac_hex(key: str, message: bytes) -> str:
    return hmac.new(key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def sign(
    document: dict[str, object],
    *,
    alg: str,
    key_hex_or_secret: str,
    signer: str,
) -> dict[str, object]:
    """Attach an issuer ``signature`` block to *document* and return it.

    ``alg`` is ``ed25519`` (raw 32-byte private seed, 64 hex chars) or
    ``hmac-sha256`` (shared secret). The signature covers :func:`signing_bytes`.
    The ``signature`` block records ``{alg, signer, sig}`` and is itself excluded
    from the signed bytes.
    """
    message = signing_bytes(document)
    if alg == "ed25519":
        from presidio_ikigov_assess.evidence import _require_crypto

        ed25519 = _require_crypto()
        try:
            priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key_hex_or_secret))
        except ValueError as exc:
            raise CertificateError(
                "ed25519 private key must be a raw 32-byte seed (64 hex chars)"
            ) from exc
        sig = priv.sign(message).hex()
    elif alg == "hmac-sha256":
        sig = _hmac_hex(key_hex_or_secret, message)
    else:
        raise CertificateError(f"unknown signing alg {alg!r}")
    document["signature"] = {"alg": alg, "signer": signer, "sig": sig}
    return document


# ── Verification (certificate + trust store only; no DB, no engine) ──────────

# Distinct, stable fail reasons (fail-closed; unknown reason never == "ok").
REASON_OK = "ok"
REASON_UNKNOWN_SCHEMA = "unknown-schema"
REASON_MALFORMED = "malformed-certificate"
REASON_BAD_SIGNATURE = "bad-signature"
REASON_UNKNOWN_ISSUER = "unknown-issuer"
REASON_EVIDENCE_REF_FAILURE = "evidence-ref-failure"
REASON_DECISION_MISMATCH = "decision-mismatch"
REASON_PREDICATE_MISMATCH = "predicate-content-mismatch"
REASON_EXPIRED = "expired"
REASON_UNSUPPORTED_TIER = "unsupported-assurance-tier"
REASON_GROUNDING_MISMATCH = "grounding-mismatch"
REASON_GROUNDING_BELOW_MINIMUM = "grounding-below-minimum"
REASON_EVIDENCE_TIER_BELOW_MINIMUM = "evidence-tier-below-minimum"


@dataclass(frozen=True)
class VerificationResult:
    ok: bool
    reason: str
    decision_claimed: str = ""
    decision_recomputed: str = ""
    signer: str = ""
    evidence_checked: int = 0
    evidence_ok: int = 0
    #: Recomputed grounding of the affirmation set ("" until recomputed).
    grounding: str = ""
    #: Weakest *declared* tier over embedded refs ("" when none embedded).
    evidence_tier_min: str = ""
    #: The certificate's validity bound, if it carries one.
    not_after: str = ""
    parents: tuple[str, ...] = ()


def _verify_issuer_signature(
    document: Mapping[str, object], trust: Mapping[str, object]
) -> tuple[bool, str, str]:
    """Verify the issuer signature against the trust store. Returns (ok, reason, signer)."""
    sig_block = document.get("signature")
    if not isinstance(sig_block, Mapping):
        return False, REASON_MALFORMED, ""
    alg = sig_block.get("alg")
    signer = sig_block.get("signer")
    sig = sig_block.get("sig")
    if not (isinstance(alg, str) and isinstance(signer, str) and isinstance(sig, str)):
        return False, REASON_MALFORMED, ""
    entry = trust.get(signer)
    if entry is None:
        return False, REASON_UNKNOWN_ISSUER, signer
    norm = entry if isinstance(entry, Mapping) and "keys" in entry else None
    if norm is None:
        # Fall back to evidence.load_trust_store normalisation shape.
        from presidio_ikigov_assess.evidence import _normalise_entry

        norm = _normalise_entry(signer, entry)
    if norm["alg"] != alg:
        # Trust store declares a different algorithm for this signer: fail-closed.
        return False, REASON_BAD_SIGNATURE, signer
    message = signing_bytes(document)
    ok = any(_verify_one(alg, message, sig, key) for key in norm["keys"])
    return (True, REASON_OK, signer) if ok else (False, REASON_BAD_SIGNATURE, signer)


def _verify_one(alg: str, message: bytes, sig: str, key: str) -> bool:
    if alg == "hmac-sha256":
        return hmac.compare_digest(_hmac_hex(key, message), sig)
    if alg == "ed25519":
        from cryptography.exceptions import InvalidSignature

        from presidio_ikigov_assess.evidence import _require_crypto

        ed25519 = _require_crypto()
        try:
            pk = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(key))
            pk.verify(bytes.fromhex(sig), message)
            return True
        except (InvalidSignature, ValueError):
            return False
    return False


def _recompute_decision(document: Mapping[str, object]) -> Optional[str]:
    """Recompute the gate decision from the certificate's affirmation set + predicate.

    Reads *only* the certificate: the per-item statuses in ``affirmation_set``
    and the ``predicate`` inputs. Rebuilds the affirmed/skipped partition and
    runs the exact same :func:`gates.evaluate_gate` rule the issuer ran, over
    the predicate's ``gate_items``. Returns the recomputed decision string, or
    ``None`` if the certificate is structurally malformed.
    """
    gate = document.get("gate")
    predicate = document.get("predicate")
    aff_set = document.get("affirmation_set")
    if not (isinstance(gate, str) and isinstance(predicate, Mapping) and isinstance(aff_set, list)):
        return None
    gate_items = predicate.get("gate_items")
    risk_class = predicate.get("risk_class")
    strict = predicate.get("strict")
    if not (
        isinstance(gate_items, list)
        and all(isinstance(i, str) for i in gate_items)
        and isinstance(risk_class, str)
        and isinstance(strict, bool)
    ):
        return None
    if gate not in VALID_GATES or risk_class not in VALID_RISK_CLASSES:
        return None

    affirmed: set[str] = set()
    skipped: set[str] = set()
    seen: set[str] = set()
    for entry in aff_set:
        if not isinstance(entry, Mapping):
            return None
        item_id = entry.get("id")
        status = entry.get("status")
        if not (isinstance(item_id, str) and isinstance(status, str)):
            return None
        seen.add(item_id)
        if status == STATUS_AFFIRMED:
            affirmed.add(item_id)
        elif status == STATUS_SKIPPED:
            skipped.add(item_id)
        elif status == STATUS_DENIED:
            pass  # denied = neither affirmed nor skipped
        else:
            return None
    # The affirmation set must cover exactly the gate's items (the predicate's
    # gate_items); a partition that omits a gate item cannot be recomputed.
    if seen != set(gate_items):
        return None

    result = evaluate_gate(gate, frozenset(affirmed), frozenset(skipped), risk_class, bool(strict))
    return result.status.value


def _predicate_matches_builtin(document: Mapping[str, object]) -> bool:
    """Check that the signed predicate block pins the built-in gate rule."""
    gate = document.get("gate")
    risk_class = document.get("risk_class")
    predicate = document.get("predicate")
    if not (
        isinstance(gate, str)
        and gate in VALID_GATES
        and isinstance(risk_class, str)
        and risk_class in VALID_RISK_CLASSES
        and isinstance(predicate, Mapping)
    ):
        return False

    expected_hash = gate_predicate_content_hash()
    if document.get("framework_content_hash") != expected_hash:
        return False
    if predicate.get("predicate_content_hash") != expected_hash:
        return False
    if predicate.get("gate_items") != sorted(item.id for item in ITEMS_BY_GATE[gate]):
        return False
    if predicate.get("risk_class") != risk_class:
        return False
    strict = predicate.get("strict")
    if not isinstance(strict, bool):
        return False
    if predicate.get("strict_effective") != bool(strict or risk_class == "high"):
        return False
    return True


def verify_certificate(
    document: Mapping[str, object],
    trust: Mapping[str, object],
    *,
    now: Optional[datetime] = None,
    min_grounding: Optional[str] = None,
    min_evidence_tier: Optional[str] = None,
) -> VerificationResult:
    """Verify a gate certificate against a trust store — fail-closed, DB-free.

    Order (each with a distinct reason):

    1. **schema** — ``schema`` must be the certificate const, else
       ``unknown-schema``.
    2. **issuer signature** — the detached signature over
       :func:`signing_bytes` must verify against ``trust`` (``bad-signature`` /
       ``unknown-issuer``).
    3. **assurance tier** — a certificate declaring any tier this verifier
       cannot check ⇒ ``unsupported-assurance-tier``.
    4. **predicate identity** — ``framework_content_hash`` and
       ``predicate.predicate_content_hash`` must equal the built-in gate
       predicate hash this verifier actually uses (``predicate-content-mismatch``).
    5. **validity** — a malformed ``not_after`` or ``parents`` is
       ``malformed-certificate``; ``now`` (default: the wall clock, UTC) past
       ``not_after`` ⇒ ``expired``.
    6. **embedded evidence-refs** — every embedded ref is re-verified against
       the *same* trust store; any failure ⇒ ``evidence-ref-failure``. The
       weakest declared tier is compared to ``min_evidence_tier`` if given
       (``evidence-tier-below-minimum``).
    7. **decision recomputation** — the decision is recomputed from the
       embedded affirmation set + predicate and compared to the claim; mismatch
       ⇒ ``decision-mismatch``.
    8. **grounding** — recomputed from the affirmation set; a recorded
       ``grounding`` that disagrees ⇒ ``grounding-mismatch``; below
       ``min_grounding`` if given ⇒ ``grounding-below-minimum``.

    Never reads the assessments DB. Uses only the certificate and the trust
    store. Any structural problem short-circuits to a fail-closed result.
    """
    if not isinstance(document, Mapping):
        return VerificationResult(False, REASON_MALFORMED)
    if document.get("schema") != CERTIFICATE_SCHEMA:
        return VerificationResult(False, REASON_UNKNOWN_SCHEMA)
    if min_grounding is not None and min_grounding not in GROUNDINGS:
        raise CertificateError(f"unknown grounding {min_grounding!r}")
    if min_evidence_tier is not None and min_evidence_tier not in ASSURANCE_TIERS:
        raise CertificateError(f"unknown assurance tier {min_evidence_tier!r}")

    # (2) issuer signature
    sig_ok, sig_reason, signer = _verify_issuer_signature(document, trust)
    if not sig_ok:
        return VerificationResult(False, sig_reason, signer=signer)

    # (3) the certificate's own tier: only the attested form is verifiable here.
    tier = document.get("assurance_tier", CERTIFICATE_ASSURANCE_TIER)
    if tier != CERTIFICATE_ASSURANCE_TIER:
        return VerificationResult(False, REASON_UNSUPPORTED_TIER, signer=signer)

    # (4) predicate identity: signed cert must pin the rule this verifier uses.
    if not _predicate_matches_builtin(document):
        return VerificationResult(False, REASON_PREDICATE_MISMATCH, signer=signer)

    # (5) validity bound and lineage shape
    not_after = document.get("not_after", "")
    if not_after != "":
        bound = parse_timestamp(not_after)
        if bound is None:
            return VerificationResult(False, REASON_MALFORMED, signer=signer)
        moment = now if now is not None else datetime.now(timezone.utc)
        if moment.tzinfo is None:
            raise CertificateError("now must be timezone-aware")
        if moment > bound:
            return VerificationResult(False, REASON_EXPIRED, signer=signer, not_after=not_after)
    if not isinstance(document.get("require_evidence", False), bool):
        return VerificationResult(False, REASON_MALFORMED, signer=signer)
    raw_parents = document.get("parents")
    parents: tuple[str, ...] = ()
    if raw_parents is not None:
        try:
            validated = _validate_parents(raw_parents)
        except CertificateError:
            return VerificationResult(False, REASON_MALFORMED, signer=signer)
        if not validated:  # P3: present means non-empty
            return VerificationResult(False, REASON_MALFORMED, signer=signer)
        parents = tuple(validated)

    common = {"signer": signer, "not_after": not_after, "parents": parents}

    # (6) re-verify every embedded evidence-ref against the trust store
    aff_set = document.get("affirmation_set")
    if not isinstance(aff_set, list):
        return VerificationResult(False, REASON_MALFORMED, **common)
    evidence_checked = 0
    evidence_ok = 0
    weakest_tier: Optional[str] = None
    for entry in aff_set:
        if not isinstance(entry, Mapping):
            return VerificationResult(False, REASON_MALFORMED, **common)
        raw = entry.get("evidence_ref")
        if raw is None:
            continue
        evidence_checked += 1
        ref = _parse_embedded_ref(raw)
        # The embedded ref must parse and carry the item it affirms.
        if ref is None or ref.item_id != entry.get("id") or not verify_ref(ref, trust):
            return VerificationResult(
                False,
                REASON_EVIDENCE_REF_FAILURE,
                evidence_checked=evidence_checked,
                evidence_ok=evidence_ok,
                **common,
            )
        evidence_ok += 1
        if weakest_tier is None or TIER_RANK[ref.assurance_tier] < TIER_RANK[weakest_tier]:
            weakest_tier = ref.assurance_tier
    common.update(
        evidence_checked=evidence_checked,
        evidence_ok=evidence_ok,
        evidence_tier_min=weakest_tier or "",
    )
    if (
        min_evidence_tier is not None
        and weakest_tier is not None
        and TIER_RANK[weakest_tier] < TIER_RANK[min_evidence_tier]
    ):
        return VerificationResult(False, REASON_EVIDENCE_TIER_BELOW_MINIMUM, **common)

    # (7) recompute the decision from the certificate alone
    claimed = document.get("decision")
    if not isinstance(claimed, str):
        return VerificationResult(False, REASON_MALFORMED, **common)
    recomputed = _recompute_decision(document)
    if recomputed is None:
        return VerificationResult(False, REASON_MALFORMED, decision_claimed=claimed, **common)
    common.update(decision_claimed=claimed, decision_recomputed=recomputed)
    if recomputed != claimed:
        return VerificationResult(False, REASON_DECISION_MISMATCH, **common)

    # (8) grounding: recompute, compare to the recorded claim, apply the floor.
    grounding = _grounding_of(aff_set)
    common["grounding"] = grounding
    recorded = document.get("grounding")
    if recorded is not None and recorded != grounding:
        return VerificationResult(False, REASON_GROUNDING_MISMATCH, **common)
    if min_grounding is not None and GROUNDING_RANK[grounding] < GROUNDING_RANK[min_grounding]:
        return VerificationResult(False, REASON_GROUNDING_BELOW_MINIMUM, **common)

    return VerificationResult(True, REASON_OK, **common)


_EMBEDDED_REF_FIELDS = (
    "item_id",
    "source",
    "source_version",
    "ledger_ref",
    "content_hash",
    "signer",
    "signature",
    "claimed_at",
)


def _parse_embedded_ref(raw: object) -> Optional[EvidenceRef]:
    """Rebuild an :class:`EvidenceRef` from an embedded ref block, or None."""
    if not isinstance(raw, Mapping):
        return None
    values: dict[str, str] = {}
    for field in _EMBEDDED_REF_FIELDS:
        v = raw.get(field)
        if not isinstance(v, str) or not v or len(v) > _MAX_STR:
            return None
        values[field] = v
    tier = raw.get("assurance_tier", DEFAULT_ASSURANCE_TIER)
    if tier not in ASSURANCE_TIERS:
        return None
    return EvidenceRef(**values, assurance_tier=tier)


# Kept for the sake of a stable public surface used by GateCertificate.decision.
__all__ = [
    "CERTIFICATE_SCHEMA",
    "CERTIFICATE_ASSURANCE_TIER",
    "GROUNDING_SELF",
    "GROUNDING_EVIDENCE_VERIFIED",
    "GROUNDINGS",
    "CertificateError",
    "GateCertificate",
    "GateStatus",
    "VerificationResult",
    "build_certificate",
    "canonical_bytes",
    "gate_predicate_content_hash",
    "sha256_hex",
    "sign",
    "signing_bytes",
    "verify_certificate",
    "REASON_OK",
    "REASON_UNKNOWN_SCHEMA",
    "REASON_MALFORMED",
    "REASON_BAD_SIGNATURE",
    "REASON_UNKNOWN_ISSUER",
    "REASON_EVIDENCE_REF_FAILURE",
    "REASON_DECISION_MISMATCH",
    "REASON_PREDICATE_MISMATCH",
    "REASON_EXPIRED",
    "REASON_UNSUPPORTED_TIER",
    "REASON_GROUNDING_MISMATCH",
    "REASON_GROUNDING_BELOW_MINIMUM",
    "REASON_EVIDENCE_TIER_BELOW_MINIMUM",
    "parse_timestamp",
    "now_iso",
    "add_days",
]
