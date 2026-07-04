"""Workshop evidence sovereignty (T-B4) — customer anchors, presidio attests.

Core logic for the v0.22.0 T-B4 arc (PRESIDIO-REQ; strategy session 2026-07-02):

* **Owner signing (R1).** The customer generates an Ed25519 keypair on their
  own hardware (``keygen``) and signs the workshop manifest themselves
  (``sign``). The manifest gains an *optional additive* ``owner`` block
  (signer id + public key + timestamp) inside the signed content — additive
  optional fields stay within ``workshop-leavebehind@1`` per evidence
  ADR-0001 D5.
* **Assessor attestation (R2).** Presidio countersigns via a **separate
  attestation document**, not a second signature over the same bytes: a
  ``presidio-hardened/workshop-attestation@1`` payload wrapped in a standard
  ``evidence-ref@1`` envelope. ``attests`` and ``parents[0]`` carry the
  content hash of the (customer-signed) manifest — the ADR-0002 provenance
  DAG edge (L-EV-6). The schema is **frozen by the family golden vector**
  ``presidio-evidence vectors/workshop-attestation/`` (appended 2026-07-02,
  both language suites green); the conformance test in this repo pins that
  vector's content hash and deterministic Ed25519 signature.
* **Standalone signer (R3).** A self-contained ``sign.py`` ships inside the
  leave-behind for customers who cannot install ``iga``; its SHA-256 is
  listed among the manifest artifacts.

Fail-closed discipline: there is no unsigned attestation; malformed fields
raise :class:`SovereigntyError` before anything is written or signed.
"""

from __future__ import annotations

import hashlib
import json
import re
import string
from datetime import datetime, timezone
from pathlib import Path

from presidio_ikigov_assess import __version__

ATTESTATION_SCHEMA = "presidio-hardened/workshop-attestation@1"
ENVELOPE_SCHEMA = "presidio-hardened/evidence-ref@1"
DEFAULT_ASSESSOR_SIGNER = "presidio-hardened-ikigov-assess"
#: Default scope wording — matches the frozen family golden vector.
DEFAULT_SCOPE = "facilitation + methodology conformance"

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_HEX_RE = re.compile(r"^[0-9a-f]{8,128}$")
_PRINTABLE_ASCII = frozenset(string.printable) - frozenset("\t\n\r\x0b\x0c")
_MAX_FIELD_LEN = 128
_MAX_SCOPE_LEN = 512


class SovereigntyError(ValueError):
    """Raised on invalid sovereignty input (fail-closed, nothing written)."""


# ── Canonical layer (family profile: sorted keys, compact, UTF-8) ────────────


def canonical_bytes(payload: object) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_hex(payload: object) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


# ── Ed25519 (family Layer 1: detached sig over {content_hash, signer}) ───────


def _require_ed25519():  # noqa: ANN202
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - needs missing extra
        raise SovereigntyError(
            "Ed25519 requires the [crypto] extra: pip install 'presidio-hardened-ikigov-assess[crypto]'"
        ) from exc
    return ed25519


def generate_keypair() -> tuple[str, str]:
    """Generate an Ed25519 keypair; return (private_hex, public_hex)."""
    from cryptography.hazmat.primitives import serialization

    ed25519 = _require_ed25519()
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ).hex()
    pub_hex = (
        priv.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )
    return priv_hex, pub_hex


def derive_public_key(private_key_hex: str) -> str:
    from cryptography.hazmat.primitives import serialization

    ed25519 = _require_ed25519()
    try:
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    except ValueError as exc:
        raise SovereigntyError(
            "private key must be a raw 32-byte Ed25519 seed as 64 hex characters"
        ) from exc
    return (
        priv.public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        .hex()
    )


def sign_layer1(content_hash: str, signer: str, private_key_hex: str) -> str:
    """Family Layer-1 signature: Ed25519 over canonical({content_hash, signer})."""
    ed25519 = _require_ed25519()
    try:
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    except ValueError as exc:
        raise SovereigntyError(
            "private key must be a raw 32-byte Ed25519 seed as 64 hex characters"
        ) from exc
    message = canonical_bytes({"content_hash": content_hash, "signer": signer})
    return priv.sign(message).hex()


def trust_store_snippet(signer: str, public_key_hex: str) -> str:
    """A ``trust-store@1`` entry for the engagement trust store (R4)."""
    return json.dumps(
        {signer: {"alg": "ed25519", "public_key": public_key_hex}},
        indent=2,
        sort_keys=True,
    )


# ── Field validation (fail-closed before anything is signed) ─────────────────


def _ascii_field(value: object, name: str, max_len: int = _MAX_FIELD_LEN) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SovereigntyError(f"{name} must be a non-empty string")
    if len(value) > max_len:
        raise SovereigntyError(f"{name} must be <= {max_len} characters")
    if any(ch not in _PRINTABLE_ASCII for ch in value):
        # ASCII-only keeps the payload inside the golden-vector conformance
        # envelope (canonical-JSON escaping differences are never exercised).
        raise SovereigntyError(f"{name} must be printable ASCII (no control chars)")
    return value


def _date_field(value: object, name: str) -> str:
    if not isinstance(value, str) or not _DATE_RE.match(value):
        raise SovereigntyError(f"{name} must be an ISO date (YYYY-MM-DD)")
    return value


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ── Attestation (R2) — schema frozen by the family golden vector ─────────────


def build_attestation(
    manifest: dict,
    *,
    engagement: str,
    private_key_hex: str,
    scope: str = DEFAULT_SCOPE,
    workshop_date: str | None = None,
    signer: str = DEFAULT_ASSESSOR_SIGNER,
    ledger_ref: str | None = None,
    source_version: str | None = None,
    generated_at: str | None = None,
) -> tuple[dict, dict]:
    """Build the attestation (reading, envelope) for a workshop manifest.

    ``attests`` / ``parents[0]`` = the canonical content hash of *manifest*
    (the customer-signed leave-behind manifest). Returns the Layer-0 reading
    (``workshop-attestation@1``) and the signed ``evidence-ref@1`` envelope —
    exactly the shapes of the family golden vector.
    """
    engagement = _ascii_field(engagement, "engagement")
    scope = _ascii_field(scope, "scope", _MAX_SCOPE_LEN)
    date = _date_field(workshop_date or _utcnow_iso()[:10], "workshop_date")
    signer = _ascii_field(signer, "signer")
    if not isinstance(manifest, dict) or not manifest:
        raise SovereigntyError("manifest must be a non-empty mapping")

    manifest_hash = sha256_hex(manifest)
    attested_content = {
        "role": "assessor",
        "attests": manifest_hash,
        "parents": [manifest_hash],
        "engagement": engagement,
        "scope": scope,
        "workshop_date": date,
    }
    content_hash = sha256_hex(attested_content)
    signature = sign_layer1(content_hash, signer, private_key_hex)

    version = source_version or __version__
    ts = generated_at or _utcnow_iso()
    use_case_id = manifest.get("use_case_id", "")

    reading = {
        "schema": ATTESTATION_SCHEMA,
        "attested_content": attested_content,
        "content_hash": content_hash,
        "source": signer,
        "source_version": version,
        "generated_at": ts,
    }
    envelope = {
        "schema": ENVELOPE_SCHEMA,
        "use_case": "workshop-attestation",
        "source": signer,
        "source_version": version,
        "generated_at": ts,
        "evidence": [
            {
                "item_id": f"workshop-attestation/{engagement}",
                "source": signer,
                "source_version": version,
                "ledger_ref": ledger_ref or f"iga-workshop:{use_case_id or engagement}",
                "content_hash": content_hash,
                "signer": signer,
                "signature": signature,
                "claimed_at": ts,
            }
        ],
    }
    return reading, envelope


def verify_attestation(uc_dir: Path, assessor_public_key_hex: str) -> tuple[bool, str, str]:
    """Verify the attestation in *uc_dir* fail-closed.

    Checks, in order: files present and well-formed; the reading's
    ``content_hash`` recomputes from ``attested_content`` and matches the
    envelope ref; the Ed25519 signature verifies against the assessor public
    key (via the family trust-store path); ``role`` is ``assessor``; and
    ``attests`` / ``parents[0]`` equal the recomputed canonical hash of the
    on-disk ``manifest.json``. Returns ``(ok, reason, signer)``.
    """
    from presidio_ikigov_assess.evidence import EvidenceRef, verify_ref

    try:
        reading = json.loads((uc_dir / "attestation.content.json").read_text("utf-8"))
        envelope = json.loads((uc_dir / "attestation.json").read_text("utf-8"))
        manifest = json.loads((uc_dir / "manifest.json").read_text("utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return False, "missing-or-unreadable", ""

    if reading.get("schema") != ATTESTATION_SCHEMA:
        return False, "bad-reading-schema", ""
    content = reading.get("attested_content")
    if not isinstance(content, dict):
        return False, "no-attested-content", ""
    content_hash = sha256_hex(content)
    if content_hash != reading.get("content_hash"):
        return False, "content-hash-mismatch", ""

    # Structural validation of the evidence-ref@1 envelope. We deliberately do
    # NOT reuse evidence.parse_document here: its item_id domain check is
    # scoped to checklist items (S1, D2, …) by design (consumer-side domain
    # validation, evidence-repo REQ), while attestation item_ids live in the
    # "workshop-attestation/<engagement>" domain. The cryptographic path
    # (verify_ref: canonical bytes, trust store, timing-safe) is shared.
    if envelope.get("schema") != ENVELOPE_SCHEMA:
        return False, "bad-envelope", ""
    refs_raw = envelope.get("evidence")
    if not isinstance(refs_raw, list) or len(refs_raw) != 1:
        return False, "bad-envelope", ""
    raw = refs_raw[0]
    fields = (
        "item_id",
        "source",
        "source_version",
        "ledger_ref",
        "content_hash",
        "signer",
        "signature",
        "claimed_at",
    )
    if not isinstance(raw, dict) or any(
        not isinstance(raw.get(f), str) or not raw[f] or len(raw[f]) > 512 for f in fields
    ):
        return False, "bad-envelope", ""
    if not (_HEX_RE.match(raw["content_hash"]) and _HEX_RE.match(raw["signature"])):
        return False, "bad-envelope", ""
    if not raw["item_id"].startswith("workshop-attestation/"):
        return False, "bad-envelope", ""
    if raw["content_hash"] != content_hash:
        return False, "envelope-hash-mismatch", ""

    ref = EvidenceRef(**{f: raw[f] for f in fields})
    trust = {ref.signer: {"alg": "ed25519", "public_key": assessor_public_key_hex}}
    from presidio_ikigov_assess.evidence import load_trust_store

    normalised = load_trust_store(json.dumps(trust))
    if not verify_ref(ref, normalised):
        return False, "signature-invalid", ref.signer

    if content.get("role") != "assessor":
        return False, "wrong-role", ref.signer
    manifest_hash = sha256_hex(manifest)
    if content.get("attests") != manifest_hash:
        return False, "attests-manifest-mismatch", ref.signer
    parents = content.get("parents")
    if not isinstance(parents, list) or not parents or parents[0] != manifest_hash:
        return False, "parents-manifest-mismatch", ref.signer
    return True, "", ref.signer


# ── Owner signing (R1) ────────────────────────────────────────────────────────


def owner_sign_manifest(
    uc_dir: Path,
    private_key_hex: str,
    signer: str,
    *,
    signed_at: str | None = None,
) -> tuple[str, str | None]:
    """Customer-side manifest signing: embed the owner block, sign, write.

    Adds the optional additive ``owner`` block *inside* the signed content,
    flips ``signed``/``UNSIGNED``, rewrites ``manifest.json``, and writes the
    owner signature to ``manifest.sig`` (role ``owner``). Returns
    ``(owner_public_key_hex, replaced_signer_or_None)``.
    """
    signer = _ascii_field(signer, "signer")
    manifest_path = uc_dir / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SovereigntyError(f"cannot read manifest.json: {exc}") from exc

    replaced: str | None = None
    sig_path = uc_dir / "manifest.sig"
    if sig_path.exists():
        try:
            old = json.loads(sig_path.read_text("utf-8"))
            if not old.get("UNSIGNED"):
                replaced = str(old.get("signer", "unknown"))
        except (json.JSONDecodeError, OSError):
            replaced = "unknown"

    pub_hex = derive_public_key(private_key_hex)
    manifest["owner"] = {
        "signer": signer,
        "public_key": pub_hex,
        "signed_at": signed_at or _utcnow_iso(),
    }
    manifest["signed"] = True
    manifest["UNSIGNED"] = False

    manifest_bytes = canonical_bytes(manifest)
    ed25519 = _require_ed25519()
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
    signature_hex = priv.sign(manifest_bytes).hex()

    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    sig_path.write_text(
        json.dumps(
            {
                "alg": "ed25519",
                "role": "owner",
                "signer": signer,
                "signature": signature_hex,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return pub_hex, replaced


# ── Standalone signer (R3) — shipped inside the leave-behind ─────────────────

STANDALONE_SIGNER = '''#!/usr/bin/env python3
"""Standalone workshop-manifest owner signer (presidio T-B4).

For customers who cannot install `iga`. Requires only Python 3.10+ and the
`cryptography` package (`pip install cryptography`). Run ON YOUR OWN machine;
the private key never leaves it.

  python sign.py keygen --out customer-key.hex
  python sign.py sign  --dir <this folder> --key customer-key.hex --signer "ACME GmbH"

Then return manifest.json + manifest.sig to the facilitator (USB is fine).
Verification: `iga workshop verify --dir <folder> --pubkey <your pubkey>`.
"""
import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def keygen(out):
    path = Path(out)
    if path.exists():
        sys.exit(f"refusing to overwrite existing key file: {path}")
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    ).hex()
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(priv_hex + "\\n")
    Path(str(path) + ".pub").write_text(pub_hex + "\\n", encoding="utf-8")
    print("private key:", path, "(mode 0600 — never share this file)")
    print("public key: ", pub_hex)


def sign(dir_path, key_path, signer):
    uc_dir = Path(dir_path)
    manifest_path = uc_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text("utf-8"))
    priv_hex = Path(key_path).read_text("utf-8").strip()
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    pub_hex = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    manifest["owner"] = {
        "signer": signer,
        "public_key": pub_hex,
        "signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    manifest["signed"] = True
    manifest["UNSIGNED"] = False
    signature = priv.sign(canonical(manifest)).hex()
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    (uc_dir / "manifest.sig").write_text(
        json.dumps({"alg": "ed25519", "role": "owner", "signer": signer, "signature": signature}, indent=2),
        encoding="utf-8",
    )
    print("signed as owner:", signer)
    print("public key:", pub_hex)
    print("manifest sha256:", hashlib.sha256(canonical(manifest)).hexdigest())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    kg = sub.add_parser("keygen")
    kg.add_argument("--out", default="customer-key.hex")
    sg = sub.add_parser("sign")
    sg.add_argument("--dir", default=".")
    sg.add_argument("--key", required=True)
    sg.add_argument("--signer", required=True)
    args = p.parse_args()
    if args.cmd == "keygen":
        keygen(args.out)
    else:
        sign(args.dir, args.key, args.signer)


if __name__ == "__main__":
    main()
'''

#: Bilingual USB signing-ceremony runbook shipped in every leave-behind (R3).
SIGNING_CEREMONY_MD = """\
# Signier-Zeremonie / Signing ceremony (T-B4)

## Deutsch

Ihre Workshop-Unterlagen gehören **Ihnen** — deshalb signieren Sie sie mit
einem Schlüssel, der Ihre Hardware nie verlässt. Presidio gegensigniert als
Assessor in einem separaten Attestierungs-Dokument.

1. **Schlüssel erzeugen (einmalig, auf IHREM Rechner):**
   `python sign.py keygen --out customer-key.hex`
   Die Datei `customer-key.hex` bleibt bei Ihnen (Modus 0600, niemals teilen).
   Den **öffentlichen** Schlüssel (`customer-key.hex.pub`) geben Sie an
   Presidio für den Engagement-Trust-Store.
2. **Ordner signieren:** Diesen Ordner (USB-Stick genügt) auf Ihren Rechner
   kopieren, dann:
   `python sign.py sign --dir . --key customer-key.hex --signer "<Ihre Organisation>"`
3. **Rückgabe:** Nur `manifest.json` und `manifest.sig` zurück an den
   Facilitator (USB). Presidio erstellt daraufhin die Attestierung
   (`attestation.json`).
4. **Prüfen (jederzeit, offline):**
   `iga workshop verify --dir <Ordner> --pubkey <Ihr öffentlicher Schlüssel>`
   Mit `--require-attestation --attestation-pubkey <presidio-Schlüssel>`
   prüfen Sie zusätzlich die Presidio-Gegensignatur (siehe `assessor.pub`).

Benötigt nur Python 3.10+ und `pip install cryptography`.

## English

Your workshop artifacts belong to **you** — so you sign them with a key that
never leaves your hardware. Presidio countersigns as assessor in a separate
attestation document.

1. **Generate a key (once, on YOUR machine):**
   `python sign.py keygen --out customer-key.hex`
   Keep `customer-key.hex` (mode 0600, never share it). Hand the **public**
   key (`customer-key.hex.pub`) to presidio for the engagement trust store.
2. **Sign this folder:** copy it to your machine (a USB stick is fine), then:
   `python sign.py sign --dir . --key customer-key.hex --signer "<your org>"`
3. **Return:** only `manifest.json` and `manifest.sig` go back to the
   facilitator (USB). Presidio then issues the attestation
   (`attestation.json`).
4. **Verify (any time, offline):**
   `iga workshop verify --dir <folder> --pubkey <your public key>`
   Add `--require-attestation --attestation-pubkey <presidio key>` to also
   check presidio's countersignature (see `assessor.pub`).

Requires only Python 3.10+ and `pip install cryptography`.
"""
