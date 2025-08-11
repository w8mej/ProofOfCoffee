import os
import json
import requests
from urllib.parse import urlparse

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200").rstrip("/")
ROLE = "lambda-role"


def _validate_base_url(base_url: str) -> str:
    """Allow only http/https VAULT_ADDR and strip trailing slash."""
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsafe VAULT_ADDR scheme: {parsed.scheme}")
    if not parsed.netloc:
        raise ValueError("VAULT_ADDR must include a host")
    return f"{parsed.scheme}://{parsed.netloc}"  # normalize (no path)


def _vault_url(path: str) -> str:
    base = _validate_base_url(VAULT_ADDR)
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def lambda_handler(event, context):
    # 1) Get AWS identity token (placeholder for demo)
    # in prod, retrieve from AWS IAM auth flow
    jwt = os.getenv("AWS_LAMBDA_JWT")

    # 2) Login to Vault with JWT (requests.post, safe URL)
    login_payload = {"jwt": jwt, "role": ROLE}
    login_url = _vault_url("/v1/auth/aws/login")
    login_resp = requests.post(login_url, json=login_payload, timeout=5)
    login_resp.raise_for_status()
    vault_token = login_resp.json()["auth"]["client_token"]

    # 3) Fetch secret (requests.get, safe URL, token header)
    secret_url = _vault_url("/v1/kv/data/lambda/api-key")  # KV v2 path
    headers = {"X-Vault-Token": vault_token}
    secret_resp = requests.get(secret_url, headers=headers, timeout=5)
    secret_resp.raise_for_status()
    secret = secret_resp.json()["data"]["data"]["key"]

    return {"statusCode": 200, "body": f"Secret is: {secret}"}
