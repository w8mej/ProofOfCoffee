"""
tests/frost_chaos.py — Chaos-style tests for the ThresholdSigner simulator (documented)

Purpose
-------
Exercise the PoC `ThresholdSigner` quorum logic under varying liveness to demonstrate:
  • Quorum detection when enough signers are online (≥ t),
  • Quorum failure when too many signers are offline (< t),
  • Sign path behavior (success with quorum, failure without).

These tests target the **simulator** in `src.mpc.frost.ThresholdSigner`. In production,
replace the simulator with a real FROST implementation and adapt tests to:
  • Assert correct round orchestration,
  • Validate aggregated Ed25519 signatures,
  • Measure latency and partial signer outages.

How to run
----------
$ pytest -q
"""

from __future__ import annotations

import pytest

from src.mpc.frost import ThresholdSigner


def test_quorum():
    """
    Baseline quorum test:
      - With n=5, t=3 → quorum should initially be True (all online)
      - After taking 3 signers offline → quorum should be False
    """
    ts = ThresholdSigner(n=5, t=3)
    assert ts.require_quorum() is True, "expected quorum with all signers online"

    # Take 3 signers offline (indices 0,1,2), leaving only 2 online (< t)
    ts.set_offline([0, 1, 2])
    assert ts.require_quorum() is False, "expected no quorum after taking 3/5 offline"


def test_sign_succeeds_with_quorum():
    """
    Signing succeeds when quorum is met.
    NOTE: The simulator returns SHA-256(msg) as a stand-in for a real signature.
    """
    ts = ThresholdSigner(n=4, t=3)
    # Keep 3 online (indices 0,1,2 online; index 3 offline)
    ts.set_offline([3])
    assert ts.require_quorum() is True

    msg = b"threshold-test"
    sig = ts.sign(msg)
    assert isinstance(sig, bytes) and len(
        sig) == 32, "simulated signature should be a 32-byte digest"


def test_sign_fails_without_quorum():
    """
    Signing fails (raises) when quorum is not met.
    """
    ts = ThresholdSigner(n=4, t=3)
    ts.set_offline([0, 1])  # only 2 online remain (< t)
    assert ts.require_quorum() is False

    with pytest.raises(RuntimeError, match="insufficient online signers"):
        ts.sign(b"no-quorum")
