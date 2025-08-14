"""
cli/piv_approver.py — PIV Approver CLI (PKCS#11) that signs a server challenge and emits a JSON payload

Security & Ops
- Purpose: Produce the exact payload `/mint` expects for PIV-based approvals:
  {
    "leaf_pem_b64", "chain_pems_b64", "root_pems_b64",
    "challenge_b64", "signature_b64"
  }
  The signature is created by a hardware-backed PIV private key via PKCS#11.

- Trust boundaries
  • Private key never leaves the token; signing occurs inside the PIV device (YubiKey/SmartCard).
  • The server will verify the signature over its challenge and validate the certificate chain
    against trusted attestation roots, plus any policy OIDs/eku/CRL/OCSP (see server-side checks).

- Input expectations
  • `--challenge-file` is an opaque byte blob authored by the server (e.g., random nonce).
  • `--leaf-pem` is the end-entity certificate corresponding to the PIV key used for signing.
  • `--root-pem/--chain-pem` help the server verify the chain (roots are trust anchors).

Tunable / Config
- PKCS11_LIB (or --pkcs11-lib): Path to the provider, e.g., `/usr/lib/opensc-pkcs11.so`.
- PKCS11_PIN (or --pin): PIV user PIN for the token.
- PKCS11_KEY_LABEL (or --key-label): Label of the PIV private key object (e.g., `PIV AUTH key`).
- Challenge/cert files: pass paths via flags; you can supply multiple `--root-pem` / `--chain-pem`.

Production Readiness / Improvements
- Slot selection: This PoC picks the first present token; add `--slot` / `--serial` to disambiguate.
- Mechanism negotiation: Some tokens need raw `ECDSA` (hash externally) vs `ECDSA_SHA256`.
- Key discovery: Support `--key-id` and search by `ID`/`CKA_ID` in addition to `LABEL`.
- Secure UX: Avoid printing sensitive JSON to shared terminals; add `--out` path with 0600 perms.
- Robust error handling: Map PKCS#11 exceptions to actionable messages (PIN locked, wrong label, etc.).
- Attestation: You can optionally include the **attestation cert** chain for the PIV key if supported.

Usage
  python cli/piv_approver.py \
    --challenge-file /tmp/challenge.bin \
    --pkcs11-lib /usr/lib/opensc-pkcs11.so \
    --pin 123456 \
    --key-label authkey \
    --leaf-pem /path/leaf.pem \
    --root-pem certs/yubico-piv-attestation-ca.pem \
    --chain-pem /path/intermediate.pem

Output (to stdout)
  JSON with base64-encoded leaf/chain/roots, the original challenge, and the signature.
  Pipe directly into your `/mint` client request to populate the `piv_*` fields.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os

import click
from dotenv import load_dotenv

# Load developer-friendly env overrides (do not rely on .env in production).
load_dotenv()


@click.command()
@click.option(
    "--challenge-file",
    type=click.Path(exists=True),
    required=True,
    help="Path to challenge bytes issued by the server (opaque; will be signed).",
)
@click.option(
    "--pkcs11-lib",
    envvar="PKCS11_LIB",
    required=True,
    help="Path to PKCS#11 provider (e.g., /usr/lib/opensc-pkcs11.so).",
)
@click.option(
    "--pin",
    envvar="PKCS11_PIN",
    required=True,
    hide_input=True,
    help="PIV user PIN for the token.",
)
@click.option(
    "--key-label",
    envvar="PKCS11_KEY_LABEL",
    required=True,
    help="PIV private key label (e.g., 'authkey').",
)
@click.option(
    "--leaf-pem",
    type=click.Path(exists=True),
    required=True,
    help="Leaf certificate PEM that corresponds to the private key.",
)
@click.option(
    "--root-pem",
    type=click.Path(exists=True),
    multiple=True,
    help="Trusted root PEM(s) for server-side attestation verification (repeatable).",
)
@click.option(
    "--chain-pem",
    type=click.Path(exists=True),
    multiple=True,
    help="Intermediate chain PEM(s) (repeatable).",
)
def approve(
    challenge_file: str,
    pkcs11_lib: str,
    pin: str,
    key_label: str,
    leaf_pem: str,
    root_pem: tuple[str, ...],
    chain_pem: tuple[str, ...],
) -> None:
    """
    Sign a server-issued challenge using a PIV key via PKCS#11 and emit a JSON payload
    that the backend `/mint` endpoint expects for PIV validation.
    """
    # Import PKCS#11 library lazily to provide friendly error if missing.
    try:
        import pkcs11
        from pkcs11 import Attribute, ObjectClass, Mechanism
    except Exception as e:
        raise click.ClickException(f"python-pkcs11 not installed: {e}")

    # 1) Read challenge bytes (opaque; do not alter).
    try:
        with open(challenge_file, "rb") as f:
            challenge = f.read()
    except Exception as e:
        raise click.ClickException(f"Failed to read challenge: {e}")

    # 2) Open the first available token. In production, expose --slot/--serial.
    try:
        lib = pkcs11.lib(pkcs11_lib)
        token = list(lib.get_slots(token_present=True))[0].get_token()
    except Exception as e:
        raise click.ClickException(
            f"No PKCS#11 token available or bad provider: {e}")

    # 3) Locate the private key by label and sign the digest.
    # Notes:
    # - Using Mechanism.ECDSA_SHA256 computes the hash inside the token when supported.
    # - If your token requires raw ECDSA, pre-hash and use Mechanism.ECDSA with ASN.1 DER sig.
    try:
        with token.open(user_pin=pin) as session:
            priv = next(
                session.get_objects(
                    {Attribute.LABEL: key_label,
                        Attribute.CLASS: ObjectClass.PRIVATE_KEY}
                ),
                None,
            )
            if priv is None:
                raise click.ClickException("Private key not found by label")

            # For broad compatibility, pre-hash the challenge and let the mechanism hash again.
            # If your device rejects double-hashing, switch to Mechanism.ECDSA and pass raw hash.
            digest = hashlib.sha256(challenge).digest()
            try:
                sig = priv.sign(digest, mechanism=Mechanism.ECDSA_SHA256)
            except Exception:
                # Fallback: raw ECDSA over pre-hashed message (common for some tokens)
                sig = priv.sign(digest, mechanism=Mechanism.ECDSA)
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(f"PKCS#11 signing failed: {e}")

    # 4) Read certificates and base64-encode for transport.
    try:
        with open(leaf_pem, "rb") as f:
            leaf_b64 = base64.b64encode(f.read()).decode("ascii")
    except Exception as e:
        raise click.ClickException(f"Failed to read leaf PEM: {e}")

    roots_b64: list[str] = []
    for rp in root_pem:
        try:
            with open(rp, "rb") as f:
                roots_b64.append(base64.b64encode(f.read()).decode("ascii"))
        except Exception as e:
            raise click.ClickException(f"Failed to read root PEM {rp}: {e}")

    chain_b64: list[str] = []
    for cp in chain_pem:
        try:
            with open(cp, "rb") as f:
                chain_b64.append(base64.b64encode(f.read()).decode("ascii"))
        except Exception as e:
            raise click.ClickException(f"Failed to read chain PEM {cp}: {e}")

    # 5) Emit the approver payload expected by /mint (PIV path).
    out = {
        "leaf_pem_b64": leaf_b64,
        "chain_pems_b64": chain_b64,
        "root_pems_b64": roots_b64,
        "challenge_b64": base64.b64encode(challenge).decode("ascii"),
        "signature_b64": base64.b64encode(sig).decode("ascii"),
    }
    click.echo(json.dumps(out, indent=2))


if __name__ == "__main__":
    approve()
