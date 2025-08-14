"""
frost_client.py — Client Helper for FROST Threshold Signing (Documented)

Purpose
-------
Provides a lightweight Python interface to request **FROST** (Flexible Round-Optimized
Schnorr Threshold signatures) signing from a remote FROST Coordinator service.

This helper abstracts:
  • Encoding the message into base64 for transport
  • Passing participant set and signer service URLs
  • Parsing and decoding the returned group signature & public key

Intended Use
------------
- Typically called from higher-level MPC/JWT issuance workflows to obtain a group
  signature over a signing input.
- Can be reused in test harnesses to simulate multi-signer coordination.

Security & Ops Notes
--------------------
- Transport Security: This PoC uses HTTP (unencrypted). In production, use HTTPS/mTLS
  between the client and FROST Coordinator to prevent message interception/tampering.
- Authentication: This client does not authenticate to the Coordinator. Add request-signing
  or token-based auth in production.
- Signature verification: Callers are expected to verify the returned `sig` against the
  `group_pub` before trusting it.

Production Considerations
-------------------------
- Timeouts: Default request timeout is 10s; adjust for network conditions.
- Error handling: `r.raise_for_status()` will raise on non-2xx HTTP; catch exceptions
  to provide more graceful UX in CLI/UI layers.
- Participant selection: Here `participants` defaults to `[1,2]`. In real deployments,
  this should be policy-driven, possibly dynamic per signing request.
- Signer URLs: Hard-coded to `http://127.0.0.1:7001` & `7002` by default for local testing.
  In production, supply actual signer endpoints via environment or config.

Environment Variables
---------------------
- FROST_COORD_URL: Base URL for FROST Coordinator (default: http://127.0.0.1:7100).
"""

import os
import base64
import json
import requests

# Base URL for the FROST Coordinator service
FROST_COORD = os.getenv("FROST_COORD_URL", "http://127.0.0.1:7100")


def frost_sign(signing_input: bytes, participants=None, signer_urls=None):
    """
    Request a FROST threshold signature over `signing_input` from the Coordinator.

    Args:
      signing_input (bytes):
        The message to be signed (raw bytes).
      participants (list[int], optional):
        Participant IDs to include in the signing quorum.
        Defaults to [1, 2] for local testing.
      signer_urls (list[str], optional):
        URLs for FROST signer services participating in signing.
        Defaults to ["http://127.0.0.1:7001", "http://127.0.0.1:7002"].

    Returns:
      tuple:
        (sig, group_pub)
          sig (bytes): The aggregated group Schnorr signature.
          group_pub (bytes): The group public key corresponding to the threshold key.

    Raises:
      requests.HTTPError: If the Coordinator returns a non-2xx status.
      requests.RequestException: For network-level errors.

    Example:
      >>> sig, group_pub = frost_sign(b"important message")
      >>> print(len(sig), len(group_pub))
    """
    participants = participants or [1, 2]
    signer_urls = signer_urls or [
        "http://127.0.0.1:7001",
        "http://127.0.0.1:7002"
    ]

    payload = {
        "msg_b64": base64.b64encode(signing_input).decode(),
        "participants": participants,
        "signer_urls": signer_urls
    }

    r = requests.post(f"{FROST_COORD}/sign", json=payload, timeout=10)
    r.raise_for_status()

    data = r.json()
    sig = base64.b64decode(data["signature_b64"])
    group_pub = base64.b64decode(data["group_public_b64"])
    return sig, group_pub
