"""
cli/mint_basic.py — Minimal engineer self-service CLI to mint short-lived tokens

Security & Ops
- Purpose: Provide a **non-WebAuthn** fast path to request a short-lived token from the
  coordinator’s `/mint` endpoint. Intended for *development* and automated tests.
- Risk: This command does **not** perform hardware-backed auth itself; it relies on the
  server to apply policy and, ideally, require WebAuthn/PIV (or reject if missing).
- Telemetry: Prefer running with verbose API logs off on the server and avoid printing
  full responses containing tokens to multi-user terminals. Tokens are short-lived but
  still sensitive.

Tunable / Config
- Environment:
  • COORDINATOR_URL: default backend base URL (fallback: http://127.0.0.1:8080)
  • TOKEN_DEFAULT_TTL_SECONDS: default TTL for minted tokens (fallback: 900)
  • .env support via python-dotenv for developer convenience (not for prod secrets)
- CLI options:
  • --user   : identity/subject
  • --role   : logical role used by policy (engineer/sre/…)
  • --scopes : comma-separated scopes (server will further restrict)
  • --ttl    : requested TTL seconds (server caps per policy)
  • --url    : override API base URL

Operational Guidance
- Use this only in dev or CI where an upstream layer will still require WebAuthn/PIV
  or SEV-SNP attestation as configured. In production user flows, prefer the **loopback
  WebAuthn CLI** (mint_webauthn_loopback.py) or browser-initiated flows.
- Integrate with CI to exercise negative/positive minting policy tests (e.g., overscoped,
  excessive TTL, wrong role/env).

Production Considerations / Improvements
- Remove .env reliance; configure the base URL via deployment (env/flag) and route through
  mTLS ingress with OPA/Envoy `ext_authz` enforcing KMS receipt + JWT checks.
- Add a `--webauthn` flag to invoke the loopback flow automatically, or a `--piv` path
  that signs the server challenge using a PIV key (approver CLI).
- Plumb in structured logging and redact tokens by default; add `--raw` to print JSON if needed.
- Add retry/backoff and circuit-breaker behavior for transient network errors.
"""

from __future__ import annotations

import json
import os
from typing import List

import click
import requests
from dotenv import load_dotenv

# Load developer overrides; avoid in production.
load_dotenv()

DEFAULT_URL = os.getenv("COORDINATOR_URL", "http://127.0.0.1:8080")
DEFAULT_TTL = int(os.getenv("TOKEN_DEFAULT_TTL_SECONDS", "900"))


@click.group()
def cli() -> None:
    """Engineer self-service CLI to mint short-lived tokens (dev/test convenience)."""
    pass


@cli.command()
@click.option("--user", required=True, help="Your username/email (JWT subject)")
@click.option("--role", default="engineer", show_default=True, help="Role for policy evaluation")
@click.option(
    "--scopes",
    required=True,
    help="Comma-separated scopes, e.g., read:logs,write:staging",
)
@click.option(
    "--ttl",
    type=int,
    default=DEFAULT_TTL,
    show_default=True,
    help="Requested TTL seconds (server may cap)",
)
@click.option(
    "--url",
    default=DEFAULT_URL,
    show_default=True,
    help="Mint API base URL",
)
def mint(user: str, role: str, scopes: str, ttl: int, url: str) -> None:
    """
    Request a token from the mint API without performing client-side WebAuthn/PIV.
    The server is expected to enforce proper authentication and policy.

    Returns JSON to stdout:
      {
        "token": "...",
        "kid": "...",
        "exp": 1234567890,
        "scopes": [...],
        ...
      }
    """
    # Build request payload. Server-side policy enforces role/scope/ttl constraints.
    scope_list: List[str] = [s.strip() for s in scopes.split(",") if s.strip()]
    data = {
        "user": user,
        "role": role,
        "scopes": scope_list,
        "ttl_seconds": ttl,
        # Optional: backend may accept auth_method hints; omitted here.
    }

    try:
        r = requests.post(f"{url}/mint", json=data, timeout=10)
    except Exception as e:
        click.echo(f"Network error calling {url}/mint: {e}")
        raise SystemExit(2)

    if r.status_code != 200:
        # Print server’s error details (it should avoid leaking internals).
        click.echo(f"Error: {r.status_code} {r.text}")
        raise SystemExit(1)

    try:
        out = r.json()
    except Exception:
        click.echo("Non-JSON response from server")
        click.echo(r.text)
        raise SystemExit(3)

    # Print the result. Consider redacting the token unless --raw flag is added.
    click.echo(json.dumps(out, indent=2))


if __name__ == "__main__":
    cli()
