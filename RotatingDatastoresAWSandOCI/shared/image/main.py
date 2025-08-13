# -----------------------------------------------------------------------------
# Multi-Cloud Credential Rotation Worker (PoC)
# Runs on AWS Lambda (container) AND OCI Functions (container).
#
# WHAT THIS DOES (high level)
# - Reads the current app credential from AWS Secrets Manager + OCI Vault
# - Rotates the password in BOTH databases: AWS RDS (Postgres/MySQL) and Oracle ADB-D
# - Updates both clouds' credential secret + a "connection blob" (DSNs/wallet pointer)
# - Writes an HMAC-signed audit record to local cloud cold storage (S3/OCI Object Storage)
#
# SECURITY & OPS NOTES (PoC)
# - No plaintext secrets in logs (audit payload = metadata + HMAC only)
# - This PoC avoids distributed locks; schedule could overlap. Production: add a lock.
# - Rollback logic prevents split-brain if one DB rotation fails.
# - OCI wallet sourcing supports multiple options; prefer short-lived PAR or mounted secret.
# - Tunables: ROTATION_MINUTES, Lambda/Function timeout/memory, DSN embedding strategy.
# -----------------------------------------------------------------------------

import os
import json
import base64
import hashlib
import hmac
import datetime
import random
import string
import zipfile
import io
import pathlib
import boto3
import oci
import psycopg
import pymysql
import oracledb

# Tunable: rotation cadence (min). Kept as reference metadata; schedulers enforce actual cadence.
ROTATION_MINUTES = int(os.getenv("ROTATION_MINUTES", "20"))

# --------------------------- Password generation -----------------------------


def strong_password(length=32):
    """
    Generate a strong random password (mixed case, digits, symbols).
    SECURITY (PoC): Uses SystemRandom for cryptographic PRNG and enforces class diversity.
    Tunables: increase length or symbol set per org policy.
    """
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}"
    while True:
        pw = "".join(random.SystemRandom().choice(alphabet)
                     for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(c in "!@#$%^&*()-_=+[]{}" for c in pw)):
            return pw


def now_utc():
    """ISO8601 UTC timestamp. Used for rotated_at + audit trail."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

# ------------------------------ AWS Secrets ----------------------------------


def get_aws_secret():
    """
    Fetch credential secret from AWS Secrets Manager.
    SECURITY: No printing of secret values. Reads current version.
    """
    sid = os.environ["AWS_SECRET_ID"]
    sm = boto3.client("secretsmanager")
    val = sm.get_secret_value(SecretId=sid)
    if "SecretString" in val:
        return json.loads(val["SecretString"])
    return json.loads(base64.b64decode(val["SecretBinary"]).decode())


def put_aws_secret(payload: dict):
    """
    Update credential secret in AWS Secrets Manager with new password.
    SECURITY: Rotations are written as a new version; replication handles HA.
    """
    sid = os.environ["AWS_SECRET_ID"]
    boto3.client("secretsmanager").put_secret_value(
        SecretId=sid, SecretString=json.dumps(payload))


def put_aws_conn_blob(payload: dict):
    """
    Update the 'connection blob' (DSNs/wallet pointer) in Secrets Manager.
    PoC: Optional; only runs if AWS_CONN_BLOB_SECRET_ID is set.
    """
    sid = os.getenv("AWS_CONN_BLOB_SECRET_ID")
    if not sid:
        return
    boto3.client("secretsmanager").put_secret_value(
        SecretId=sid, SecretString=json.dumps(payload))

# ------------------------------- OCI Secrets ---------------------------------


def get_oci_secret():
    """
    Fetch credential secret from OCI Vault using Resource Principal (Function identity).
    """
    ocid = os.environ["OCI_SECRET_OCID"]
    signer = oci.auth.signers.get_resource_principals_signer()
    cli = oci.secrets.SecretsClient(config={}, signer=signer)
    bundle = cli.get_secret_bundle(secret_id=ocid).data
    content = bundle.secret_bundle_content.content
    return json.loads(base64.b64decode(content).decode())


def put_oci_secret(payload: dict):
    """
    Update credential secret in OCI Vault (BASE64 content).
    NOTE: OCI secrets are immutable versions under the hood; this updates content to create a new version.
    """
    ocid = os.environ["OCI_SECRET_OCID"]
    signer = oci.auth.signers.get_resource_principals_signer()
    cli = oci.secrets.SecretsClient(config={}, signer=signer)
    content = oci.secrets.models.Base64SecretContentDetails(
        content_type="BASE64",
        content=base64.b64encode(json.dumps(payload).encode()).decode()
    )
    cli.update_secret(secret_id=ocid, update_secret_details=oci.secrets.models.UpdateSecretDetails(
        secret_content=content))


def put_oci_conn_blob(payload: dict):
    """
    Update the 'connection blob' in OCI Vault.
    PoC: Optional; only runs if OCI_CONN_BLOB_SECRET_OCID is set.
    """
    ocid = os.getenv("OCI_CONN_BLOB_SECRET_OCID")
    if not ocid:
        return
    signer = oci.auth.signers.get_resource_principals_signer()
    cli = oci.secrets.SecretsClient(config={}, signer=signer)
    content = oci.secrets.models.Base64SecretContentDetails(
        content_type="BASE64",
        content=base64.b64encode(json.dumps(payload).encode()).decode()
    )
    cli.update_secret(secret_id=ocid, update_secret_details=oci.secrets.models.UpdateSecretDetails(
        secret_content=content))

# ---------------------------- Connection blob I/O -----------------------------


def get_connection_blob():
    """
    Read connection metadata (DSNs, wallet pointer) from the *local* cloud secret store:
    - Prefer AWS SM if running under Lambda (AWS_REGION present)
    - Else try OCI Vault
    SECURITY: This keeps apps/worker reading secrets from the *local* cloud for latency/HA.
    """
    aws_id = os.getenv("AWS_CONN_BLOB_SECRET_ID")
    oci_id = os.getenv("OCI_CONN_BLOB_SECRET_OCID")
    if aws_id and os.getenv("AWS_REGION"):
        try:
            sm = boto3.client("secretsmanager")
            v = sm.get_secret_value(SecretId=aws_id)
            s = v.get("SecretString") or base64.b64decode(
                v["SecretBinary"]).decode()
            return json.loads(s)
        except Exception:
            # PoC: swallow and fall through to OCI; production: log structured error (no secrets) + metrics
            pass
    if oci_id:
        try:
            signer = oci.auth.signers.get_resource_principals_signer()
            cli = oci.secrets.SecretsClient(config={}, signer=signer)
            b = cli.get_secret_bundle(
                secret_id=oci_id).data.secret_bundle_content.content
            return json.loads(base64.b64decode(b).decode())
        except Exception:
            pass
    return None


def update_blob_passwords(blob: dict, new_password: str) -> dict:
    """
    Update any embedded passwords in DSNs (if your DSNs contain 'user:pass@host').
    SECURITY: Prefer DSNs WITHOUT embedded passwords; consumers should fetch the password from the credential secret.
    """
    out = json.loads(json.dumps(blob))  # deep copy via round-trip

    def swap_pw_in_url(url: str) -> str:
        try:
            prefix, rest = url.split("://", 1)
            creds, host = rest.split("@", 1)
            if ":" in creds:
                user, _ = creds.split(":", 1)
                return f"{prefix}://{user}:{new_password}@{host}"
        except Exception:
            return url
        return url
    if "rds" in out and isinstance(out["rds"], dict):
        if "password" in out["rds"]:
            out["rds"]["password"] = new_password
        if "dsn" in out["rds"] and "@" in str(out["rds"]["dsn"]):
            out["rds"]["dsn"] = swap_pw_in_url(out["rds"]["dsn"])
    if "oci" in out and isinstance(out["oci"], dict):
        if "password" in out["oci"]:
            out["oci"]["password"] = new_password
        if "dsn" in out["oci"] and "@" in str(out["oci"]["dsn"]):
            out["oci"]["dsn"] = swap_pw_in_url(out["oci"]["dsn"])
    out["rotated_at"] = now_utc()
    return out

# ---------------------------------- RDS --------------------------------------


def connect_postgres(host, dbname, port, user, password, sslmode="require"):
    """
    Connect to PostgreSQL with SSL required.
    Tunables: sslmode; add sslrootcert if you need to pin CA.
    """
    return psycopg.connect(host=host, dbname=dbname, port=port, user=user, password=password, sslmode=sslmode)


def connect_mysql(host, dbname, port, user, password, ssl_ca=None):
    """
    Connect to MySQL with optional CA bundle.
    Tunables: supply ssl_ca path to enforce server cert verification.
    """
    return pymysql.connect(host=host, db=dbname, port=int(port), user=user, password=password,
                           ssl={"ca": ssl_ca} if ssl_ca else None)


def alter_user_postgres(conn, username, new_password):
    """
    ALTER USER ... WITH PASSWORD in PostgreSQL.
    SECURITY: identifier is quoted safely via psycopg.sql.Identifier (string built within cursor context).
    """
    with conn.cursor() as cur:
        cur.execute("ALTER USER " + psycopg.sql.Identifier(username)
                    .as_string(cur) + " WITH PASSWORD %s", (new_password,))
    conn.commit()


def alter_user_mysql(conn, username, new_password):
    """
    ALTER USER in MySQL.
    NOTE (PoC): Username is interpolated into the SQL string using backticks; for edge cases (host-specific users),
    parameterization of the identifier is not supported—validate 'username' upstream in production.
    """
    with conn.cursor() as cur:
        cur.execute("ALTER USER `%s` IDENTIFIED BY %%s" %
                    username, (new_password,))
    conn.commit()

# ------------------------------- Oracle ADB-D --------------------------------


def _unpack_wallet(zip_bytes: bytes) -> str:
    """
    Unzip an ADB wallet to /tmp (Lambda/Functions writable path).
    SECURITY: /tmp is ephemeral per-invocation; no long-term persistence.
    """
    wallet_dir = "/tmp/adb_wallet"
    pathlib.Path(wallet_dir).mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        zf.extractall(wallet_dir)
    return wallet_dir


def _ensure_wallet_dir():
    """
    Resolve the wallet source in priority order:
      1) Mounted directory (preferred)
      2) Short-lived PAR URL
      3) Base64-encoded zip (size-limited; last resort)
      4) OCI Object Storage via Resource Principal
    SECURITY: Prefer (1) or (2). Do not log wallet data; never store wallet in source control.
    """
    mount = os.getenv("OCI_ADB_WALLET_MOUNT")
    if mount and pathlib.Path(mount).exists():
        return mount
    url = os.getenv("OCI_ADB_WALLET_URL")
    if url:
        import urllib.request
        data = urllib.request.urlopen(url, timeout=10).read()
        return _unpack_wallet(data)
    b64 = os.getenv("OCI_ADB_WALLET_B64")
    if b64:
        return _unpack_wallet(base64.b64decode(b64))
    ns = os.getenv("OCI_OS_NAMESPACE")
    bucket = os.getenv("OCI_OS_BUCKET")
    key = os.getenv("OCI_OS_KEY")
    if ns and bucket and key:
        signer = oci.auth.signers.get_resource_principals_signer()
        osc = oci.object_storage.ObjectStorageClient(config={}, signer=signer)
        obj = osc.get_object(ns, bucket, key).data.content.read()
        return _unpack_wallet(obj)
    raise RuntimeError("No wallet source provided.")


def connect_oracle_adb(user: str, password: str):
    """
    Connect to Oracle ADB-D (TCPS) using python-oracledb 'thin' with wallet.
    Tunables: OCI_ADB_DSN can be TNS alias (from wallet) or EZCONNECT.
    """
    wallet_dir = _ensure_wallet_dir()
    dsn = os.getenv("OCI_ADB_DSN")  # EZCONNECT or TNS alias
    return oracledb.connect(user=user, password=password, dsn=dsn,
                            config_dir=wallet_dir, wallet_location=wallet_dir)


def alter_user_oracle(conn, username, new_password):
    """
    ALTER USER in Oracle (unlock to recover after failed attempts).
    SECURITY: binds password as a parameter to avoid injection; username quoted explicitly.
    """
    with conn.cursor() as cur:
        cur.execute('ALTER USER "{}" IDENTIFIED BY :pw ACCOUNT UNLOCK'.format(
            username), pw=new_password)
    conn.commit()

# --------------------------------- Audit -------------------------------------


def audit_write(message: str):
    """
    Write a minimal, HMAC-authenticated audit record to the *local* cloud cold storage:
      - On AWS: S3 (bucket = LOG_BUCKET), no secrets in body
      - On OCI: Object Storage (namespace + LOG_BUCKET)
    SECURITY: 'salt' should come from a secrets manager or SSM SecureString in production.
    """
    salt = os.getenv("AUDIT_HASH_SALT_SSM", "static-salt-change-me")
    digest = hmac.new(salt.encode(), msg=message.encode(),
                      digestmod=hashlib.sha256).hexdigest()
    stamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    record = {"ts": now_utc(), "hash": digest,
              "rotation_minutes": ROTATION_MINUTES, "message": "rotation-event"}

    # AWS S3 path (prefer local cloud)
    try:
        bucket = os.getenv("LOG_BUCKET")
        if bucket and os.getenv("AWS_REGION"):
            boto3.client("s3").put_object(
                Bucket=bucket, Key=f"rotations/{stamp}.json", Body=json.dumps(record).encode())
    except Exception:
        # PoC: ignore audit failures; production: add metrics/alerts
        pass

    # OCI Object Storage path
    try:
        bucket = os.getenv("LOG_BUCKET")
        ns = os.getenv("OCI_OS_NAMESPACE")
        if bucket and ns and not os.getenv("AWS_REGION"):
            signer = oci.auth.signers.get_resource_principals_signer()
            oci.object_storage.ObjectStorageClient(config={}, signer=signer).put_object(
                ns, bucket, f"rotations/{stamp}.json", json.dumps(record).encode())
    except Exception:
        pass

# ------------------------------- Core rotation -------------------------------


def rotate_once():
    """
    End-to-end rotation (idempotent per execution):
      1) Read current credential from AWS SM + OCI Vault and assert usernames match
      2) Generate a new strong password
      3) Rotate RDS (Postgres/MySQL), then Oracle ADB-D
         - If Oracle fails, rollback the RDS change to avoid split-brain
      4) Update credential secrets in BOTH clouds
      5) Update 'connection blob' (if present) atomically in the same run
      6) Write an audit event
    SECURITY: No credentials are logged; errors are summarized without secret content.
    """
    # 1) Read current
    aws_secret = get_aws_secret()
    oci_secret = get_oci_secret()
    assert aws_secret["username"] == oci_secret["username"], "Username mismatch between stores"

    current_user = aws_secret["username"]
    current_password = aws_secret["password"]
    new_password = strong_password()

    changed = {"rds": False, "oci_oracle": False}

    # 3) Rotate RDS first (smaller blast radius; easier rollback if ADB-D fails)
    rds_engine = os.getenv("RDS_ENGINE", "postgres")
    rds_host = os.getenv("RDS_HOST")
    rds_db = os.getenv("RDS_DBNAME")
    rds_port = int(os.getenv("RDS_PORT", "5432"))
    try:
        if rds_engine == "postgres":
            conn = connect_postgres(
                rds_host, rds_db, rds_port, current_user, current_password)
            alter_user_postgres(conn, current_user, new_password)
            conn.close()
        else:
            conn = connect_mysql(rds_host, rds_db, rds_port, current_user,
                                 current_password, ssl_ca=os.getenv("RDS_SSL_CA"))
            alter_user_mysql(conn, current_user, new_password)
            conn.close()
        changed["rds"] = True
    except Exception as e:
        # PoC: audit and rethrow; production: add retries with backoff for transient errors
        audit_write(f"rds-rotation-failed: {e}")
        raise

    # 3) Rotate Oracle ADB-D; rollback RDS on failure
    try:
        oci_user = os.getenv("OCI_ADB_USER", current_user)
        conn = connect_oracle_adb(oci_user, current_password)
        alter_user_oracle(conn, oci_user, new_password)
        conn.close()
        changed["oci_oracle"] = True
    except Exception as e:
        # Attempt rollback of RDS to previous password to avoid split-brain
        try:
            if changed["rds"]:
                if rds_engine == "postgres":
                    conn = connect_postgres(
                        rds_host, rds_db, rds_port, current_user, new_password)
                    alter_user_postgres(conn, current_user, current_password)
                    conn.close()
                else:
                    conn = connect_mysql(
                        rds_host, rds_db, rds_port, current_user, new_password, ssl_ca=os.getenv("RDS_SSL_CA"))
                    alter_user_mysql(conn, current_user, current_password)
                    conn.close()
        except Exception as rb:
            audit_write(f"rollback-rds-failed: {rb}")
        audit_write(f"oci-oracle-rotation-failed: {e}")
        raise

    # 4) Update credential secrets (both clouds)
    payload_creds = {"username": current_user,
                     "password": new_password, "rotated_at": now_utc()}
    put_aws_secret(payload_creds)
    put_oci_secret(payload_creds)

    # 5) Update connection blob (if present). This helps if consumers embed pw in DSN (not recommended).
    try:
        blob = get_connection_blob()
        if blob:
            updated_blob = update_blob_passwords(blob, new_password)
            put_aws_conn_blob(updated_blob)
            put_oci_conn_blob(updated_blob)
    except Exception as e:
        # Non-fatal: connection blob is advisory; consumers should fetch password from credential secret anyway.
        audit_write(f"connection-blob-update-warning: {e}")

    # 6) Audit completion (summary only)
    audit_write(
        f"rotated {current_user} on rds={changed['rds']}, oci_oracle={changed['oci_oracle']}")
    return {"ok": True, "changed": changed}


def lambda_handler(event=None, context=None):
    """
    AWS Lambda entrypoint (also works for OCI Functions by calling rotate_once() directly).
    """
    return rotate_once()
