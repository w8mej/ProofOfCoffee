"""
shares.py — Shamir's Secret Sharing (PoC) for MPC seed (documented)

Purpose
-------
Provide a tiny, auditable implementation of Shamir’s Secret Sharing over a large prime
field to (a) split a 256-bit seed into N shares with threshold T, and (b) recover the
seed from ≥T shares. The recovered seed is later HKDF’d into an Ed25519 private key
(see mpc/coordinator.py).

Security & Ops
--------------
- Field: We operate modulo a 521-bit prime P (> 2^512) to keep arithmetic simple and safe
  for 256-bit secrets (uniformly random in [0, 2^256)). This avoids wrap/overflow issues.
- Randomness: Coefficients are sampled via `secrets.randbelow(P)`, a CSPRNG.
- Indexing: Shares are issued at x = 1..N (non-zero, distinct) to allow Lagrange recovery at x=0.
- CLI output: Writes share_i.json files containing (x, y) only; the secret is never written.
- Trust: This file does **not** authenticate who reads shares from disk. Protect the output
  directory with strict permissions and ship to HSM/TEEs as soon as possible.

Tunable / Config
----------------
- Threshold T and total N via CLI flags (`--t`, `--n`). Guarded by 1 < T ≤ N ≤ 10 in this PoC.
- Output directory (`--out`) defaults to `.mpc_shares/`.
- You can seed from an external source by replacing `secrets.randbits(256)` below.

Production Readiness / Improvements
-----------------------------------
- Use an audited SSSS implementation (e.g., libsodium’s `crypto_shamir`) or FROST DKG instead.
- Add integrity/authenticity for stored shares (per-share signature/MAC, envelope encryption).
- Zeroize secrets & intermediate buffers; isolate share handling in a Confidential VM/TEE.
- Add redundancy & escrow process for t-of-n with rotation, plus break-glass with auto-expire.
"""

from __future__ import annotations

import json
import os
import secrets
from typing import List, Tuple

import click

# Large prime P (521-bit). Must be > max(secret, coefficients) and prime for field invertibility.
# This constant is (2^521 - 1) with all bits set below 521, expressed explicitly for clarity.
P = int(
    "0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    16,
)


# -------------------------------- Field / Polynomial Helpers ------------------------------------

def _eval_poly(coeffs: List[int], x: int) -> int:
    """
    Evaluate a polynomial (with coefficients modulo P) at point x.

    coeffs[0] is the constant term (the secret); coeffs[i] is x^i coefficient.
    Uses Horner's method modulo P.
    """
    res = 0
    for c in reversed(coeffs):
        res = (res * x + c) % P
    return res


# -------------------------------- Split & Recover -----------------------------------------------

def split_secret(secret_int: int, n: int, t: int) -> List[Tuple[int, int]]:
    """
    Split `secret_int` into N shares with threshold T using Shamir's scheme.

    Args:
      secret_int : integer in [0, 2^256) (recommended)
      n          : total number of shares to produce (1 < T ≤ N ≤ 10 enforced in PoC)
      t          : threshold required for recovery

    Returns:
      List of (x, y) tuples with x in {1..N}, y in field Z_P.

    Raises:
      AssertionError for invalid parameters (PoC guard).
    """
    assert 1 < t <= n <= 10, "PoC guard: 1 < t <= n <= 10"
    if not (0 <= secret_int < P):
        # Defensive: ensure secret fits the field
        raise ValueError("secret must be in [0, P)")

    # Random t-1 coefficients (a1..a_{t-1}); a0 is the secret
    coeffs = [secret_int] + [secrets.randbelow(P) for _ in range(t - 1)]

    shares: List[Tuple[int, int]] = []
    for i in range(1, n + 1):
        x = i  # x must be non-zero & unique
        y = _eval_poly(coeffs, x)
        shares.append((x, y))
    return shares


def recover_secret(shares: List[Tuple[int, int]]) -> int:
    """
    Reconstruct the secret from a list of (x, y) shares via Lagrange interpolation at x = 0.

    Args:
      shares: list of at least T distinct points (x, y) with x != 0

    Returns:
      The reconstructed secret (integer in Z_P).

    Raises:
      ValueError if fewer than 2 shares provided or duplicate x detected.
    """
    if len(shares) < 2:
        raise ValueError(
            "need at least 2 shares to attempt recovery (PoC guard)")
    # Ensure distinct x-coordinates
    xs = [x for x, _ in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate x in shares")

    # Lagrange basis interpolation:
    # secret = Σ_j ( y_j * Π_{m≠j} (0 - x_m) / (x_j - x_m) ) mod P
    secret = 0
    for j, (xj, yj) in enumerate(shares):
        num, den = 1, 1
        for m, (xm, _) in enumerate(shares):
            if m == j:
                continue
            num = (num * (-xm % P)) % P
            den = (den * ((xj - xm) % P)) % P
        # Modular inverse of den in field Z_P
        inv_den = pow(den, -1, P)
        lagrange_coeff = (num * inv_den) % P
        secret = (secret + (yj * lagrange_coeff)) % P
    return secret


# -------------------------------- CLI ------------------------------------------------------------

@click.command()
@click.option("--init", is_flag=True, help="Initialize new MPC shares from a random 256-bit seed")
@click.option("--n", type=int, default=3, show_default=True, help="Total shares to create")
@click.option("--t", type=int, default=2, show_default=True, help="Threshold to recover the secret")
@click.option("--out", type=str, default=".mpc_shares", show_default=True, help="Output directory")
def main(init: bool, n: int, t: int, out: str) -> None:
    """
    Create N Shamir shares (threshold T) from a fresh 256-bit random seed and write them to disk.

    Files written:
      {out}/share_1.json .. share_N.json   → each contains {"x": int, "y": int}
      {out}/meta.json                      → {"threshold": T, "total": N, "created": true}

    Notes:
      - The raw secret is **not** persisted.
      - Protect {out} with strict permissions; distribute shares to distinct custodians.
    """
    if not init:
        click.echo("Nothing to do. Pass --init to create fresh shares.")
        return

    os.makedirs(out, exist_ok=True)
    # 256-bit random seed; can be replaced by external entropy/seed source if required.
    seed_int = secrets.randbits(256)
    shares = split_secret(seed_int, n, t)

    # Write shares as JSON (no leading zeros/encoding tricks; integers only).
    for idx, (x, y) in enumerate(shares, 1):
        with open(os.path.join(out, f"share_{idx}.json"), "w", encoding="utf-8") as f:
            json.dump({"x": x, "y": y}, f)

    meta = {"threshold": t, "total": n, "created": True}
    with open(os.path.join(out, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    click.echo(f"Created {n} shares with threshold {t} in {out}")


if __name__ == "__main__":
    main()
