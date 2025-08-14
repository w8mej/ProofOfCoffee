"""
auth/piv.py — YubiKey PIV attestation & challenge verification (documented)

Security & Ops
- Purpose: Prove possession of a hardware-backed PIV private key (e.g., YubiKey)
  and validate the attestation chain against trusted roots before mint approval.

- What this verifier does:
  1) Loads the **leaf** (holder) certificate and its **intermediate chain**.
  2) Performs a **minimal** chain validation up to one of the provided **root** CAs.
     (PoC: signature checks only — NOT a full RFC 5280 path build.)
  3) Enforces Extended Key Usage (**ClientAuth**) on the **leaf** certificate.
  4) Verifies the **signature over the server challenge** with the leaf public key.

- Trust boundaries & caveats (PoC):
  • Chain building here is simplified; production must use a full path validator
    (name constraints, key usage, basic constraints, validity, CRL/OCSP, AIA).
  • No revocation checks are performed. Enable CRL/OCSP in production.
  • Policy OIDs (e.g., Yubico PIV Attestation policy) are **not** enforced here.
  • Time validity of certificates is **not** checked here (PoC); enforce in prod.

Tunable / Config
- PIV_EKU (const): Required EKU for the leaf; set to `CLIENT_AUTH`.
- Trust anchors: pass the **attestation roots** (e.g., `yubico-piv-attestation-ca.pem`).
- Challenge: use a unique, short-TTL nonce bound to the Web session/request. Store/reject replays.

Production Readiness / Improvements
- Replace `_verify_chain` with a **full** RFC 5280 path validator (e.g., `certvalidator` lib):
  - Validate **time** (notBefore/notAfter) against a trusted clock.
  - Enforce **key usage**, **basic constraints**, and **name constraints**.
  - Enforce **Policy OIDs** expected for PIV attestation.
  - Perform **revocation** (CRL/OCSP), follow AIA URIs, and enforce **TCB** metadata if applicable.
- Log structured audit events (subject, serial, policy version, key OCID) to SIEM with WORM retention.
- Constant-time comparisons where appropriate; avoid error detail leakage to clients.
- Consider pinning device model/firmware or AAGUID-like metadata (if present in the chain).
"""

from dataclasses import dataclass
from typing import List
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.x509.oid import ExtendedKeyUsageOID

# Require ClientAuth on PIV leaf certificate (authN use-case).
PIV_EKU = ExtendedKeyUsageOID.CLIENT_AUTH


@dataclass
class PIVAttestationResult:
    """Result surfaced to callers for audit/policy decisions."""
    subject: str  # RFC4514 string (e.g., CN=...,O=...,...)
    serial: str   # Hex-encoded serial number (e.g., '0x1a2b...')
    policy_ok: bool


def _load_chain(pems: List[bytes]) -> List[x509.Certificate]:
    """Decode a sequence of PEM-encoded certificates."""
    return [x509.load_pem_x509_certificate(p) for p in pems]


def _verify_chain(chain: List[x509.Certificate], roots: List[x509.Certificate]) -> bool:
    """
    Minimal chain check (PoC):
    - Verifies each cert in `chain` is signed by its issuer (next element).
    - Verifies the last chain cert is signed by **one** of the provided roots.

    NOTE: This is NOT a full RFC 5280 validator. No time/CRL/OCSP/policy checks.
    """
    try:
        # For leaves through intermediates: chain[0] signed by chain[1], etc.
        for i in range(len(chain) - 1):
            child = chain[i]
            issuer_cert = chain[i + 1]
            issuer_pub = issuer_cert.public_key()

            if isinstance(issuer_pub, ec.EllipticCurvePublicKey):
                issuer_pub.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    ec.ECDSA(child.signature_hash_algorithm),
                )
            else:
                # Assume RSA for anything else in this PoC.
                issuer_pub.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    child.signature_hash_algorithm,
                )

        # Last chain element must chain to one of the provided roots.
        last = chain[-1]
        for root in roots:
            root_pub = root.public_key()
            try:
                if isinstance(root_pub, ec.EllipticCurvePublicKey):
                    root_pub.verify(
                        last.signature,
                        last.tbs_certificate_bytes,
                        ec.ECDSA(last.signature_hash_algorithm),
                    )
                else:
                    root_pub.verify(
                        last.signature,
                        last.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        last.signature_hash_algorithm,
                    )
                return True  # accepted by a trusted root
            except Exception:
                continue

        return False
    except Exception:
        # Any failure in signature checks → invalid chain
        return False


def _eku_ok(cert: x509.Certificate) -> bool:
    """
    Enforce Extended Key Usage on the leaf.

    For PIV client authentication we require `ClientAuth` EKU present.
    """
    try:
        eku = cert.extensions.get_extension_for_class(
            x509.ExtendedKeyUsage).value
        return PIV_EKU in eku
    except Exception:
        # Missing or malformed EKU → reject
        return False


def verify_piv_attestation(
    leaf_pem: bytes,
    chain_pems: List[bytes],
    root_pems: List[bytes],
    challenge: bytes,
    signature: bytes,
) -> PIVAttestationResult:
    """
    Verify a PIV leaf certificate + chain and the signature over a server challenge.

    Args:
      leaf_pem   : PEM-encoded holder (end-entity) certificate.
      chain_pems : PEM-encoded intermediates (0..N). Optional; can be empty.
      root_pems  : PEM-encoded **trusted roots** (attestation roots).
      challenge  : Server-provided nonce bytes (unique, short TTL).
      signature  : Signature over `challenge` produced by the PIV private key.

    Returns:
      PIVAttestationResult(subject, serial, policy_ok=True) on success.

    Raises:
      ValueError if chain verification fails or EKU/policy checks fail.
      (Signature failures also raise ValueError via verify exceptions.)
    """
    # Parse certs
    leaf = x509.load_pem_x509_certificate(leaf_pem)
    chain = [leaf] + _load_chain(chain_pems)
    roots = _load_chain(root_pems)

    # 1) Verify chain to a trusted root (PoC: signature checks only)
    if not _verify_chain(chain, roots):
        raise ValueError("PIV chain verification failed")

    # 2) Enforce EKU on leaf for ClientAuth usage
    if not _eku_ok(leaf):
        raise ValueError("PIV certificate EKU does not allow ClientAuth")

    # 3) Verify the challenge signature using the leaf public key
    pub = leaf.public_key()
    try:
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(signature, challenge, ec.ECDSA(hashes.SHA256()))
        else:
            # Assume RSA for the PoC; enforce PKCS#1 v1.5 + SHA-256
            pub.verify(signature, challenge,
                       padding.PKCS1v15(), hashes.SHA256())
    except Exception as e:
        raise ValueError("Challenge signature verification failed") from e

    # Return minimal identity details for audit/policy
    subject = leaf.subject.rfc4514_string()
    serial = hex(leaf.serial_number)
    return PIVAttestationResult(subject=subject, serial=serial, policy_ok=True)
