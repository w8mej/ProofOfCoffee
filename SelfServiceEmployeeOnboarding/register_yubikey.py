#!/usr/bin/env python3
"""
YubiKey Registration Utility for HashiCorp Vault
=================================================

Purpose:
--------
This script securely registers a YubiKey hardware token's serial number as an
identity in HashiCorp Vault, associating it with access policies. It supports
mapping physical security keys to Vault entities for Kubernetes secret access
(or other Vault-managed resources) and demonstrates best practices for identity
management in infrastructure automation.

Key Features:
-------------
1. **Entity Management**:
   - Creates or updates a Vault Identity Entity for the given YubiKey serial.
   - Associates the entity with pre-defined Vault policies (e.g., "k8s-read-secret").

2. **Alias Binding**:
   - Creates a Vault Entity Alias that links the YubiKey serial number to the entity.
   - Uses the Userpass auth method accessor for the alias mount.

3. **Audit/Integration Output**:
   - Appends the serial/entity mapping to a `registrations.json` file for
     local audit logging or Terraform Cloud automation triggers.

Security Considerations:
------------------------
- Uses `VAULT_ADDR` and `VAULT_TOKEN` from environment variables to avoid
  hardcoding secrets in code.
- Only assigns the minimum required policy to the entity.
- Local JSON file output is for demo purposes; in production, use a secure
  state backend or SCM trigger.

Usage:
------
    $ export VAULT_ADDR="http://127.0.0.1:8200"
    $ export VAULT_TOKEN="s.your-root-or-approle-token"
    $ ./register_yubikey.py <YUBIKEY_SERIAL>

Example:
--------
    $ ./register_yubikey.py 01234567
    ✅ Registered YubiKey serial 01234567 → entity 3a6b8c4a-f1d8-44ef-beb4-5dbb8d2e6c73
"""

import hvac
import json
import os
import sys

# ------------------------------------------------------------------------------
# Vault Client Initialization
# ------------------------------------------------------------------------------
VAULT_ADDR = os.getenv('VAULT_ADDR', 'http://127.0.0.1:8200')
VAULT_TOKEN = os.getenv('VAULT_TOKEN', 'root')
client = hvac.Client(url=VAULT_ADDR, token=VAULT_TOKEN)


def register(serial: str) -> None:
    """
    Register a YubiKey serial number in Vault's Identity system.

    Steps:
    ------
    1. Create or update a Vault Identity Entity with the YubiKey serial.
    2. Attach an entity alias linking the serial to the Vault authentication mount.
    3. Persist the registration mapping to a local JSON audit log.

    Args:
        serial (str): The YubiKey serial number as a string.

    Raises:
        hvac.exceptions.VaultError: If Vault operations fail.
    """
    # 1️⃣ Create or update the Vault Identity Entity
    entity = client.secrets.identity.create_or_update_entity(
        name=f"employee-{serial}",
        policies=["k8s-read-secret"]
    )
    entity_id = entity['data']['id']

    # 2️⃣ Create or update the Entity Alias for the YubiKey
    client.secrets.identity.create_or_update_entity_alias(
        name=serial,
        canonical_id=entity_id,
        mount_accessor=client.auth.userpass.read_accessor()['data']['accessor']
    )

    print(f"✅ Registered YubiKey serial {serial} → entity {entity_id}")

    # 3️⃣ Append mapping to local audit file
    with open('registrations.json', 'a') as f:
        json.dump({serial: entity_id}, f)
        f.write("\n")


if __name__ == "__main__":
    # CLI argument validation
    if len(sys.argv) != 2:
        print("Usage: register_yubikey.py <serial>")
        sys.exit(1)

    # Perform registration
    register(sys.argv[1])
