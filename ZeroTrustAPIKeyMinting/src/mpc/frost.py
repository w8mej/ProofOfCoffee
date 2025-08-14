"""
frost.py — Pluggable FROST interface (documented)

Purpose
-------
Define a minimal, **pluggable interface** for a threshold Ed25519 signer so the rest of
the system (mint API, JWT builder, tests) can depend on a stable surface while you
swap in a real implementation (e.g., rust `frost-ed25519`, or a networked signer set).

This PoC includes a trivial simulator that:
  • Tracks liveness for N signers.
  • Enforces a threshold `t` for quorum.
  • "Signs" by returning SHA-256(msg) to emulate completion (NOT a real signature!).

Security & Ops
--------------
- This module does **not** perform cryptographic threshold signing. It is a simulator.
- Only use this to exercise control flow (quorum, failover) in development and CI.
- Production must replace `ThresholdSigner.sign()` with a real FROST orchestration that
  produces an Ed25519 signature aggregating partial shares without reconstructing the key.

Tunable / Config
----------------
- `n` : total number of signers (int).
- `t` : threshold required for signing (int).
- Liveness manipulation via `set_offline([idxs])` to simulate outages.

Production Readiness / Improvements
-----------------------------------
- Replace the simulator with a real FROST driver:
  • Round 1: nonce/commitment generation & distribution.
  • Round 2: partial signatures from live signers (t-of-n).
  • Aggregation: final Ed25519 signature (64 bytes).
- Transport & Auth:
  • Use mTLS, JWT, and allow-listing between coordinator ↔ signers.
  • Include request IDs and anti-replay challenges.
- Observability:
  • Emit metrics for quorum availability, round latency, signer error rates.
- Resilience:
  • Implement backoff/hedged requests and signer selection strategies.

Example
-------
>>> ts = ThresholdSigner(n=3, t=2)
>>> ts.sign(b"hello")  # returns sha256 digest in this simulator
b'...32 bytes...'
>>> ts.set_offline([0, 1])
>>> ts.sign(b"hello")  # raises due to insufficient quorum
RuntimeError: insufficient online signers for threshold sign
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass
class SignerStatus:
    """
    Health snapshot for a single signer.

    Fields:
      signer_id : logical identifier (e.g., "signer-1")
      online    : whether the signer is currently reachable/healthy
    """
    signer_id: str
    online: bool


class ThresholdSigner:
    """
    PoC threshold signer simulator.

    Responsibilities:
      - Maintain a roster of N signers.
      - Allow callers to toggle liveness for specific signers.
      - Enforce threshold t-of-n quorum before "signing".

    NOTE: `.sign()` returns SHA-256(msg) to simulate a successful signing operation.
          It is **NOT** a cryptographic signature and must not be used in production.
    """

    def __init__(self, n: int, t: int):
        """
        Initialize with N total signers and threshold T.

        Args:
          n: total number of signers.
          t: required number of online signers to proceed.

        Raises:
          ValueError if t > n or n <= 0 or t <= 0.
        """
        if n <= 0 or t <= 0 or t > n:
            raise ValueError(
                "invalid threshold parameters (require 0 < t <= n)")
        self.n = n
        self.t = t
        self.signers: List[SignerStatus] = [
            SignerStatus(f"signer-{i+1}", True) for i in range(n)]

    # --- Liveness / Quorum ----------------------------------------------------------------------

    def set_offline(self, idxs: List[int]) -> None:
        """
        Mark specific signer indices as offline.

        Args:
          idxs: zero-based indices to set offline (ignored if out of range).
        """
        for i in idxs:
            if 0 <= i < self.n:
                self.signers[i].online = False

    def set_online(self, idxs: List[int]) -> None:
        """
        Mark specific signer indices as online.

        Args:
          idxs: zero-based indices to set online (ignored if out of range).
        """
        for i in idxs:
            if 0 <= i < self.n:
                self.signers[i].online = True

    def require_quorum(self) -> bool:
        """Return True if at least `t` signers are online."""
        return sum(1 for s in self.signers if s.online) >= self.t

    def online_ids(self) -> List[str]:
        """List signer_ids that are currently online (for logging/metrics)."""
        return [s.signer_id for s in self.signers if s.online]

    # --- Signing (Simulator) --------------------------------------------------------------------

    def sign(self, msg: bytes) -> bytes:
        """
        "Sign" the message if quorum is met.

        Behavior:
          - Checks quorum via `require_quorum()`.
          - Returns SHA-256(msg) to indicate a successful operation (simulator only).

        Args:
          msg: message bytes to "sign".

        Returns:
          32-byte digest (simulated signature).

        Raises:
          RuntimeError if insufficient online signers to meet threshold.
        """
        if not self.require_quorum():
            raise RuntimeError(
                "insufficient online signers for threshold sign")

        # In a real FROST implementation:
        #   1) Coordinator asks each online signer to produce round-1 commitments (nonces).
        #   2) Coordinator computes challenge; signers return round-2 partial signatures.
        #   3) Coordinator aggregates partial signatures into a single Ed25519 signature.
        # For the PoC simulator, return a digest to represent "success".
        import hashlib
        return hashlib.sha256(msg).digest()
