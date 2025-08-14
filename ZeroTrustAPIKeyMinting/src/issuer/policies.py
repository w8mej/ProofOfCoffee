"""
policy/loader.py — Simple role-based mint policy loader & evaluator (documented)

Security & Ops
- Purpose: Enforce **least privilege** for token minting by checking:
  1) The caller’s declared role exists in policy.
  2) All requested `scopes` are allowed for that role.
  3) The requested TTL does not exceed the role’s `max_ttl_seconds`.

- Trust boundaries:
  • This module only evaluates **static JSON policy** loaded from disk; it does not
    authenticate users or verify signatures. Upstream layers (WebAuthn/PIV, OPA) must
    authenticate and authorize identities first.
  • Do not allow untrusted users to modify the policy file path or contents.

Tunable / Config
- Policy file schema (JSON):
  {
    "roles": {
      "<role>": {
        "allow_scopes": ["read:test", "write:staging", ...],
        "max_ttl_seconds": 1800
      },
      ...
    }
  }
- You may keep one policy file per environment (dev/staging/prod) and select via an env var.

Production Readiness / Improvements
- Schema validation: Validate the JSON against a JSON Schema at startup to fail fast.
- Dynamic policy: Fetch policy from a signed/configured source (e.g., OPA bundle) instead of local disk.
- Audit: Log all denials with structured reasons (role missing, scope elevation, ttl exceed).
- ABAC: Extend evaluator for attributes like `env`, `ticket_id`, `change_window`, and merge with OPA.
- Wildcards: Add optional wildcard semantics (e.g., "read:*") with explicit, well-tested matching.
"""

from __future__ import annotations

import json
import os
from typing import Iterable, Tuple


class Policy:
    """
    Load and evaluate role-based mint policy.

    Usage:
      p = Policy("/etc/mint/policy.json")
      ok, reason = p.allowed(role="engineer", scopes=["read:test"], ttl_seconds=900)
      if not ok: deny(reason)

    Notes:
    - This PoC keeps logic intentionally minimal and deterministic.
    - Keep policy small and auditable; prefer additive changes via PRs and CI checks.
    """

    def __init__(self, path: str):
        """
        Initialize the policy from a JSON file.

        Raises:
          FileNotFoundError / json.JSONDecodeError on invalid path/content.
          KeyError if required top-level keys are missing.
        """
        with open(path, "r", encoding="utf-8") as f:
            self.doc = json.load(f)
        if "roles" not in self.doc or not isinstance(self.doc["roles"], dict):
            raise KeyError("policy missing 'roles' mapping")

    def allowed(self, role: str, scopes: Iterable[str], ttl_seconds: int) -> Tuple[bool, str]:
        """
        Evaluate whether the requested scopes and TTL are allowed for `role`.

        Args:
          role: Logical role (e.g., "engineer", "sre").
          scopes: Iterable of requested scopes (strings).
          ttl_seconds: Requested token lifetime, in seconds.

        Returns:
          (True, "ok") if allowed; otherwise (False, "<reason>").
        """
        role_cfg = self.doc["roles"].get(role)
        if not role_cfg:
            return False, f"role {role} not found"

        # Defensive type checks (fail closed if policy malformed)
        allow_scopes = role_cfg.get("allow_scopes", [])
        max_ttl = role_cfg.get("max_ttl_seconds")
        if not isinstance(allow_scopes, list) or not isinstance(max_ttl, int):
            return False, "policy malformed for role"

        # Scope allow-list: all requested scopes must be included in the role's set
        allowed_scopes = set(allow_scopes)
        req_scopes = set(scopes)
        if not req_scopes.issubset(allowed_scopes):
            # Provide minimal leak-free context; avoid echoing sensitive scope names if needed
            return False, "requested scopes not allowed"

        # TTL cap
        if ttl_seconds > max_ttl:
            return False, f"ttl exceeds max {max_ttl}"

        return True, "ok"
