"""
snp_verify.py — Minimal AMD SEV-SNP attestation verifier (PoC)

Security & Ops
- Purpose: Verify a (PoC) SEV-SNP report that’s been JSON-encoded by an in-guest agent.
  The verifier:
    1) Binds a server-issued nonce (challenge) into the report via report_data.
    2) Pins the VM/image measurement and (optionally) a policy/config hash.
    3) Verifies an ECDSA signature using the VCEK public key (PEM).

- Trust Boundaries:
  * This PoC assumes the agent extracted the SNP report and provided a JSON with:
      { version, policy, family_id, image_id, measurement, report_data,
        signature: {r, s}, signed_bytes }
    In production you MUST parse the **binary** SNP report structure and compute the
    signed region bytes exactly as specified by AMD.

- Failure Handling:
  * Any parsing or signature error returns False (no exceptions leak by default).
  * Callers should log denials with enough context for forensics (no secrets).

Tunable / Config
- expected_measurements (List[str]): Allowlist of approved image/boot measurements.
- expected_policy_hash (str|None): Optional allowlist pin for build-time policy/config.
- bind_nonce (bytes|None): If provided, SHA-256(nonce) must match report.report_data.

Production Readiness / Improvements
- Full Chain & TCB Validation:
  * Verify the entire SNP certificate chain: ARK → ASK → VCEK, including CRLs/OCSP and
    **TCBVersion** checks against AMD’s reference values.
  * Validate the report’s signature over the canonical 0..0x2A0 bytes (or spec-defined
    region) from the **binary** report; do NOT trust “signed_bytes” supplied by an agent.
- Replay / Freshness:
  * Enforce freshness on nonce (unique, short TTL) and reject reused report_data.
- Context Binding:
  * Bind additional context (cluster, image digest, policy hash, audience) into nonce.
- Robust Parsing:
  * Implement a strict binary parser; reject unknown/extra fields and inconsistent lengths.
- Side-Channel / Constant-Time:
  * Use constant-time comparisons for measurement/policy strings where feasible.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509 import load_pem_x509_certificate


@dataclass
class SnpReport:
    """
    PoC representation of an SNP report as provided by an in-guest agent.

    NOTE: This is NOT the binary AMD SNP report format. For production, replace this with a
    strict binary parser and compute the canonical signed region per AMD spec.
    """
    version: int
    policy: str
    family_id: str
    image_id: str
    measurement: str        # hex string
    # hex string (should equal sha256(nonce) when nonce binding used)
    report_data: str
    signature_r: str        # hex string (ECDSA r)
    signature_s: str        # hex string (ECDSA s)


def _parse_report(raw: bytes) -> SnpReport:
    """
    Parse a JSON-encoded SNP report (PoC).

    Expected JSON keys:
      version, policy, family_id, image_id, measurement, report_data,
      signature: { r, s }
    """
    doc = json.loads(raw.decode("utf-8"))
    return SnpReport(
        version=doc["version"],
        policy=str(doc["policy"]),
        family_id=str(doc["family_id"]),
        image_id=str(doc["image_id"]),
        measurement=str(doc["measurement"]),
        report_data=str(doc["report_data"]),
        signature_r=str(doc["signature"]["r"]),
        signature_s=str(doc["signature"]["s"]),
    )


def verify_snp_report(
    report_b64: str,
    vcek_pem_b64: str,
    expected_measurements: List[str],
    expected_policy_hash: Optional[str],
    bind_nonce: Optional[bytes],
) -> bool:
    """
    Verify a PoC SEV-SNP report.

    Args:
      report_b64: Base64 of the JSON document produced by the in-guest agent. The JSON
                  MUST include a `signed_bytes` hex string used for ECDSA verification
                  (PoC shortcut; production must compute from binary report).
      vcek_pem_b64: Base64 of a PEM-encoded VCEK certificate (public key).
      expected_measurements: Case-insensitive allowlist of measurements (hex).
      expected_policy_hash: Optional case-insensitive expected policy hash (hex).
      bind_nonce: If provided, we require report.report_data == sha256(nonce).hex().

    Returns:
      True iff all checks pass (nonce binding, measurement/policy pin, ECDSA verify).
      False on any failure or parsing error.

    SECURITY: This is a PoC. Do NOT use in production without:
      - Full AMD SNP binary parsing and signed region computation.
      - SNP certificate chain/TCB validation and revocation checking.
    """
    try:
        # Decode and parse the report JSON (PoC format).
        report_bytes = base64.b64decode(report_b64)
        report = _parse_report(report_bytes)

        # 1) Optional nonce binding: ensure report_data == sha256(nonce)
        if bind_nonce is not None:
            nonce_hash_hex = hashlib.sha256(bind_nonce).hexdigest()
            # Use constant-time comparison on normalized hex
            if not hmac.compare_digest(report.report_data.lower(), nonce_hash_hex.lower()):
                return False

        # 2) Measurement pinning (case-insensitive set membership)
        if expected_measurements:
            allowed = {m.lower() for m in expected_measurements}
            if report.measurement.lower() not in allowed:
                return False

        # 3) Optional policy pinning (case-insensitive exact match)
        if expected_policy_hash:
            if not hmac.compare_digest(report.policy.lower(), expected_policy_hash.lower()):
                return False

        # 4) ECDSA signature verification with VCEK public key
        #    PoC expectation: the same base64 JSON also contains "signed_bytes" (hex).
        doc = json.loads(report_bytes.decode("utf-8"))
        signed_hex = doc.get("signed_bytes", "")
        if not isinstance(signed_hex, str) or not signed_hex:
            # In production: derive from binary report; here we require it to be present.
            return False
        signed_bytes = bytes.fromhex(signed_hex)

        vcek_cert = load_pem_x509_certificate(base64.b64decode(vcek_pem_b64))
        pub = vcek_cert.public_key()

        # Recompose DER ECDSA signature from r,s
        r = int(report.signature_r, 16)
        s = int(report.signature_s, 16)
        sig_der = encode_dss_signature(r, s)

        # Verify signature over signed_bytes using ECDSA-SHA256
        pub.verify(sig_der, signed_bytes, ec.ECDSA(hashes.SHA256()))

        return True

    except Exception:
        # Any parsing/verification error → deny.
        return False
