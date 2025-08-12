# PoC API Gateway: Validates X-API-Key requests using a SHA-256 hash
# stored securely in Vault KV. No plaintext API keys are stored server-side.

import base64
import hmac
import hashlib
import os
from fastapi import FastAPI, Request, HTTPException
import hvac

# 🔐 Vault connection details (defaults to local dev instance)
VAULT_ADDR = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN", "root")

# 📛 Application name (used as Vault KV path segment)
APP_NAME = os.getenv("APP_NAME", "myapp")

# 📦 Initialize Vault client
client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)

# ⚡ FastAPI app instance
app = FastAPI()


def get_hash_b64():
    """
    Fetch the stored API key hash from Vault KV v2.
    - Returns Base64-encoded SHA-256 hash
    - Never exposes the original API key
    """
    secret = client.secrets.kv.v2.read_secret_version(
        path=f"api/keys/{APP_NAME}"
    )
    return secret["data"]["data"]["sha256_b64"]


@app.get("/health")
async def health():
    """
    Health check endpoint for monitoring.
    - Returns simple JSON {"status": "ok"}
    """
    return {"status": "ok"}


@app.get("/secret-data")
async def secret_data(req: Request):
    """
    Protected endpoint requiring X-API-Key header.
    - Reads presented key from request header
    - Hashes and compares to stored hash in Vault using constant-time comparison
    - Returns classified data if valid
    """

    # 🛂 Extract API key from request headers
    presented = req.headers.get("x-api-key")
    if not presented:
        raise HTTPException(status_code=401, detail="Missing X-API-Key")

    # 🔒 Compute SHA-256 digest of provided key
    digest = hashlib.sha256(presented.encode()).digest()
    presented_b64 = base64.b64encode(digest).decode()

    # 📥 Fetch stored hash from Vault
    stored_b64 = get_hash_b64()

    # 🧾 Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(presented_b64, stored_b64):
        raise HTTPException(status_code=403, detail="Invalid API key")

    # 🎯 Successful validation — return "classified" data
    return {"ok": True, "data": "highly classified (ish)"}
