"""
tests/test_mint_integration.py — End-to-end PoC tests for /mint

Covers:
  • FastAPI /mint calls with valid inputs
  • WebAuthn/PIV authentication mocks
  • Policy & scope/TTL enforcement
  • MPC share recovery + Ed25519 JWT verification
  • Optional OCI KMS receipt (x-kms-sig/x-kms-key) via mocks

These tests exercise the PoC paths (local Shamir + Ed25519; FROST disabled).
They do not require real WebAuthn, PIV, SNP, or KMS; we stub/mimic those callouts.
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Any, Dict

import jwt
import pytest
from fastapi.testclient import TestClient

# --- Helpers ------------------------------------------------------------------------------------


def write_constant_shares(dirpath: Path, secret: int, threshold: int = 2, total: int = 2) -> None:
    """
    Create a Shamir share set for a constant polynomial f(x)=secret using two points.
    With (x1, secret), (x2, secret), Lagrange recovery at x=0 yields `secret`.
    """
    dirpath.mkdir(parents=True, exist_ok=True)
    (dirpath / "meta.json").write_text(json.dumps(
        {"threshold": threshold, "total": total, "created": True}, indent=2))
    (dirpath / "share_1.json").write_text(json.dumps({"x": 1, "y": secret}))
    (dirpath / "share_2.json").write_text(json.dumps({"x": 2, "y": secret}))


def make_policy_file(path: Path, allowed_scopes: list[str], max_ttl: int = 3600) -> None:
    policy = {
        "roles": {
            "engineer": {"allow_scopes": allowed_scopes, "max_ttl_seconds": max_ttl},
            "sre": {"allow_scopes": allowed_scopes, "max_ttl_seconds": max_ttl},
        }
    }
    path.write_text(json.dumps(policy, indent=2))


def decode_unverified_header(token: str) -> Dict[str, Any]:
    return jwt.get_unverified_header(token)


# --- Fixtures -----------------------------------------------------------------------------------

@pytest.fixture
def tmp_env(monkeypatch: pytest.MonkeyPatch):
    """
    Prepare a temp environment:
      - SHARE_DIR with two constant shares that reconstruct to a known seed
      - POLICY_FILE that allows specific scopes
      - Disable SNP/FROST; leave KMS unset by default
    """
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        share_dir = tmp / ".mpc_shares"
        policy_path = tmp / "policy.json"

        # Use a small test seed (int) — derive_ed25519_from_seed HKDFs it anyway
        TEST_SEED = 123456789
        write_constant_shares(share_dir, TEST_SEED, threshold=2, total=2)
        make_policy_file(policy_path, allowed_scopes=[
                         "read:logs", "write:staging"], max_ttl=3600)

        monkeypatch.setenv("SHARE_DIR", str(share_dir))
        monkeypatch.setenv("POLICY_FILE", str(policy_path))
        monkeypatch.setenv("ISSUER_KID", "test-kid")
        monkeypatch.setenv("USE_FROST", "false")
        monkeypatch.setenv("REQUIRE_SNP_ATTESTATION", "false")
        # No KMS by default; tests enable via monkeypatch when needed

        yield {"TEST_SEED": TEST_SEED, "share_dir": share_dir, "policy_path": policy_path}


@pytest.fixture
def app_client(tmp_env, monkeypatch: pytest.MonkeyPatch):
    """
    Import the FastAPI app AFTER env is set, and stub out authentication calls
    so we don't need real WebAuthn/PIV material.
    """
    # Import late to pick up env vars
    from src.server import api as server_api

    # Stub authenticate_engineer to always succeed
    def _ok_authenticate_engineer(*args, **kwargs):
        class E:
            user = kwargs.get("user", "alice@example.com")
            role = kwargs.get("role", "engineer")
            device_attested = True
            method = kwargs.get("method", "webauthn")
        return E()

    monkeypatch.setattr(server_api, "authenticate_engineer",
                        _ok_authenticate_engineer)

    # Build test client
    client = TestClient(server_api.app)
    return client


# --- Tests --------------------------------------------------------------------------------------

def test_mint_webauthn_happy_path(tmp_env, app_client):
    """
    Full /mint call with:
      - WebAuthn auth mocked OK
      - Allowed scopes
      - Valid TTL
    Asserts:
      - 200 OK with token
      - JWT verifies under Ed25519 public key derived from Shamir seed
      - Claims include expected fields, audience, and exp/nbf sanity
    """
    # Prepare request
    body = {
        "user": "alice@example.com",
        "role": "engineer",
        "scopes": ["read:logs", "write:staging"],
        "ttl_seconds": 900,
        "auth_method": "webauthn",
        "webauthn_assertion": {"dummy": True},  # accepted by mocked auth
    }

    r = app_client.post("/mint", json=body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert {"token", "kid", "expires_at"} <= set(out.keys())
    token = out["token"]

    # Verify EdDSA signature using public key derived from the same seed
    from src.mpc.coordinator import derive_ed25519_from_seed

    seed = tmp_env["TEST_SEED"]
    mpc_key = derive_ed25519_from_seed(seed, "test-kid")
    pub = mpc_key.private_key.public_key()

    # Decode & verify JWT
    claims = jwt.decode(
        token,
        key=pub,
        algorithms=["EdDSA"],
        audience="internal-services",
        options={"require": ["exp", "nbf", "aud", "iss", "sub"]},
    )
    now = int(time.time())
    assert claims["sub"] == body["user"]
    assert set(claims["scopes"]) == set(body["scopes"])
    assert claims["iss"] == "mpc-minting-poc"
    assert claims["aud"] == "internal-services"
    assert claims["nbf"] <= now <= claims["exp"]

    # Unverified header sanity
    hdr = decode_unverified_header(token)
    assert hdr["alg"] == "EdDSA"
    assert hdr["kid"] == "test-kid"


def test_policy_scope_denied(tmp_env, app_client):
    """
    Request a scope not in policy; expect 403.
    """
    body = {
        "user": "bob@example.com",
        "role": "engineer",
        "scopes": ["read:logs", "write:prod"],  # "write:prod" not allowed
        "ttl_seconds": 900,
        "auth_method": "webauthn",
        "webauthn_assertion": {"dummy": True},
    }
    r = app_client.post("/mint", json=body)
    assert r.status_code == 403
    assert "not allowed" in r.text or "allowed" in r.text


def test_policy_ttl_exceeds(tmp_env, app_client):
    """
    Request a TTL above policy cap; expect 403.
    """
    body = {
        "user": "carol@example.com",
        "role": "engineer",
        "scopes": ["read:logs"],
        "ttl_seconds": 7200,  # policy cap set to 3600 in fixture
        "auth_method": "webauthn",
        "webauthn_assertion": {"dummy": True},
    }
    r = app_client.post("/mint", json=body)
    assert r.status_code == 403
    assert "ttl exceeds" in r.text.lower()


def test_piv_auth_mocked(tmp_env, monkeypatch: pytest.MonkeyPatch):
    """
    Exercise PIV path by mocking authenticate_engineer to accept method="piv".
    """
    from src.server import api as server_api
    from fastapi.testclient import TestClient

    def _ok_authenticate_engineer_piv(*args, **kwargs):
        class E:
            user = kwargs.get("user", "dana@example.com")
            role = kwargs.get("role", "engineer")
            device_attested = True
            method = "piv"
        return E()

    monkeypatch.setattr(server_api, "authenticate_engineer",
                        _ok_authenticate_engineer_piv)
    client = TestClient(server_api.app)

    body = {
        "user": "dana@example.com",
        "role": "engineer",
        "scopes": ["read:logs"],
        "ttl_seconds": 600,
        "auth_method": "piv",
        "piv": {
            "leaf_pem_b64": base64.b64encode(b"dummy").decode(),
            "root_pems_b64": [base64.b64encode(b"dummyroot").decode()],
            "chain_pems_b64": [],
            "challenge_b64": base64.b64encode(b"c").decode(),
            "signature_b64": base64.b64encode(b"s").decode(),
        },
    }
    r = client.post("/mint", json=body)
    # Because we reused the app instance, ensure earlier env still present and shares/policy OK
    assert r.status_code == 200, r.text


def test_kms_receipt_headers(tmp_env, monkeypatch: pytest.MonkeyPatch):
    """
    Enable KMS co-sign path and assert that JWT header includes x-kms-sig and x-kms-key.
    We mock both kms_sign_approval and verify_kms_signature.
    """
    # Set env to trigger the KMS path
    monkeypatch.setenv("OCI_KMS_KEY_OCID", "ocid1.key.oc1..testkms")
    monkeypatch.setenv("OCI_REGION", "us-phoenix-1")

    from src.server import api as server_api
    from fastapi.testclient import TestClient

    # Mock auth OK
    def _ok_auth(*args, **kwargs):
        class E:
            user = kwargs.get("user", "eve@example.com")
            role = kwargs.get("role", "engineer")
            device_attested = True
            method = kwargs.get("method", "webauthn")
        return E()

    monkeypatch.setattr(server_api, "authenticate_engineer", _ok_auth)

    # Mock the KMS approval and its verification
    class FakeRes:
        def __init__(self):
            self.key_ocid = "ocid1.key.oc1..testkms"
            self.signature_b64 = base64.urlsafe_b64encode(
                b"sigbytes").decode().rstrip("=")
            self.public_key_pem = "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----"

    monkeypatch.setattr(server_api, "kms_sign_approval",
                        lambda doc, key, region: FakeRes())
    monkeypatch.setattr(server_api, "verify_kms_signature",
                        lambda doc, sig, pem: True)

    client = TestClient(server_api.app)

    body = {
        "user": "eve@example.com",
        "role": "engineer",
        "scopes": ["read:logs"],
        "ttl_seconds": 600,
        "auth_method": "webauthn",
        "webauthn_assertion": {"dummy": True},
    }
    r = client.post("/mint", json=body)
    assert r.status_code == 200, r.text
    token = r.json()["token"]
    hdr = jwt.get_unverified_header(token)

    assert hdr.get("x-kms-key") == "ocid1.key.oc1..testkms"
    assert "x-kms-sig" in hdr and isinstance(
        hdr["x-kms-sig"], str) and len(hdr["x-kms-sig"]) > 0

# --- Additional negative / required-path tests ---------------------------------------------------


def test_kms_receipt_verification_failure(tmp_env, monkeypatch: pytest.MonkeyPatch):
    """
    KMS is enabled but the local verification of the receipt fails → expect 403.

    Mocks:
      - authenticate_engineer: OK
      - kms_sign_approval: returns a fake signature/key
      - verify_kms_signature: returns False (fail verification)
    """
    # Enable the KMS path
    monkeypatch.setenv("OCI_KMS_KEY_OCID", "ocid1.key.oc1..badkms")
    monkeypatch.setenv("OCI_REGION", "us-phoenix-1")

    from src.server import api as server_api
    from fastapi.testclient import TestClient

    def _ok_auth(*args, **kwargs):
        class E:
            user = kwargs.get("user", "mallory@example.com")
            role = kwargs.get("role", "engineer")
            device_attested = True
            method = kwargs.get("method", "webauthn")
        return E()

    monkeypatch.setattr(server_api, "authenticate_engineer", _ok_auth)

    class FakeRes:
        def __init__(self):
            self.key_ocid = "ocid1.key.oc1..badkms"
            self.signature_b64 = base64.urlsafe_b64encode(
                b"bad").decode().rstrip("=")
            self.public_key_pem = "-----BEGIN PUBLIC KEY-----\nMIIB...\n-----END PUBLIC KEY-----"

    # Return a signature but fail verification
    monkeypatch.setattr(server_api, "kms_sign_approval",
                        lambda doc, key, region: FakeRes())
    monkeypatch.setattr(server_api, "verify_kms_signature",
                        lambda doc, sig, pem: False)

    client = TestClient(server_api.app)

    body = {
        "user": "mallory@example.com",
        "role": "engineer",
        "scopes": ["read:logs"],
        "ttl_seconds": 600,
        "auth_method": "webauthn",
        "webauthn_assertion": {"dummy": True},
    }
    r = client.post("/mint", json=body)
    assert r.status_code == 403
    assert "KMS signature verification failed" in r.text


def test_snp_required_success(tmp_env, monkeypatch: pytest.MonkeyPatch):
    """
    SNP attestation is required and the verifier approves → /mint succeeds.
    """
    monkeypatch.setenv("REQUIRE_SNP_ATTESTATION", "true")
    from src.server import api as server_api
    from fastapi.testclient import TestClient

    # Mock auth OK
    def _ok_auth(*args, **kwargs):
        class E:
            user = kwargs.get("user", "attester@example.com")
            role = kwargs.get("role", "engineer")
            device_attested = True
            method = kwargs.get("method", "webauthn")
        return E()

    monkeypatch.setattr(server_api, "authenticate_engineer", _ok_auth)
    # SNP verifier returns True (attestation valid)
    monkeypatch.setattr(server_api, "verify_snp_report", lambda **kw: True)

    client = TestClient(server_api.app)

    body = {
        "user": "attester@example.com",
        "role": "engineer",
        "scopes": ["read:logs"],
        "ttl_seconds": 600,
        "auth_method": "webauthn",
        "webauthn_assertion": {"dummy": True},
        "attestation": {
            "report_b64": "ZmFrZQ==",     # "fake" (not parsed due to mock)
            "vcek_pem_b64": "ZmFrZV9rZXk=",  # "fake_key"
        },
    }
    r = client.post("/mint", json=body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert "token" in out and isinstance(out["token"], str)


def test_snp_required_failure(tmp_env, monkeypatch: pytest.MonkeyPatch):
    """
    SNP attestation is required but the verifier rejects → expect 401.
    """
    monkeypatch.setenv("REQUIRE_SNP_ATTESTATION", "true")
    from src.server import api as server_api
    from fastapi.testclient import TestClient

    # Mock auth OK
    def _ok_auth(*args, **kwargs):
        class E:
            user = kwargs.get("user", "rejector@example.com")
            role = kwargs.get("role", "engineer")
            device_attested = True
            method = kwargs.get("method", "webauthn")
        return E()

    monkeypatch.setattr(server_api, "authenticate_engineer", _ok_auth)
    # SNP verifier returns False (attestation invalid)
    monkeypatch.setattr(server_api, "verify_snp_report", lambda **kw: False)

    client = TestClient(server_api.app)

    body = {
        "user": "rejector@example.com",
        "role": "engineer",
        "scopes": ["read:logs"],
        "ttl_seconds": 600,
        "auth_method": "webauthn",
        "webauthn_assertion": {"dummy": True},
        "attestation": {
            "report_b64": "ZmFrZQ==",
            "vcek_pem_b64": "ZmFrZV9rZXk=",
        },
    }
    r = client.post("/mint", json=body)
    assert r.status_code == 401
    assert "SEV-SNP attestation failed" in r.text
