# Multi-Cloud Credential Rotation Worker (PoC)

**Automated, Secure, Multi-Cloud Credential Rotation between AWS & OCI**

---

## 📌 Overview

This project is a **proof-of-concept (PoC)** demonstrating a **cross-cloud, automated credential rotation system** that updates and synchronizes user credentials across:

- **AWS RDS (Postgres/MySQL)**
- **Oracle Cloud Infrastructure Autonomous Database Dedicated (ADB-D)**
- **AWS Secrets Manager**  
- **OCI Vault**
- **AWS S3 & OCI Object Storage** (for audit logs)

The rotation worker runs as either:

- An **AWS Lambda container** triggered by **EventBridge** (every 20 minutes), or
- An **OCI Function container** triggered by **OCI Events** (every 20 minutes).

**⚠️ Production Use Warning:**  
This implementation is for **demonstration and interview purposes**. Security hardening, performance tuning, compliance validation, and HA/DR considerations are **required** before real-world deployment.

---

## 🛠️ How It Works

### 1. Rotation Schedule
- AWS: **CloudWatch EventBridge Rule** triggers Lambda.
- OCI: **OCI Events Rule** triggers OCI Function.

### 2. Secrets Retrieval
- Reads the **current credential** from both AWS Secrets Manager and OCI Vault.
- Validates that usernames match across both clouds.

### 3. Database Rotation
- Connects to RDS (Postgres/MySQL) and OCI ADB-D.
- Generates a strong random password meeting complexity requirements.
- Executes secure `ALTER USER` operations.

### 4. Secret Updates
- Writes updated credentials back to AWS Secrets Manager & OCI Vault.
- Optionally updates a **connection blob** secret containing DSNs.

### 5. Audit Logging
- Creates an HMAC-signed JSON record.
- Writes to either:
  - AWS S3 (`rotations/` prefix) or
  - OCI Object Storage (`rotations/` prefix).

---

## 🔐 Security & Operations Notes (PoC)

- **Minimal IAM & OCI Policy Scopes**: Roles are scoped only to required Secrets, Object Storage buckets, and logging.
- **Encryption at Rest**:
  - AWS: Secrets encrypted with KMS.
  - OCI: Secrets stored in Vault (KMS-managed).
- **Transport Security**: Enforces SSL/TLS for all DB connections.
- **Wallet Handling (OCI ADB-D)**: Supports multiple secure retrieval methods; no wallet persisted beyond runtime.
- **Audit Trail Integrity**: Logs include HMAC signatures using a salt stored in AWS SSM or OCI Config.

> **Hardening Needed for Production:**
> - Network isolation (VPC + private subnets + SG/NACL lockdown).
> - CI/CD pipeline with IaC security scanning.
> - DB connection retry and rollback logic enhancements.
> - Secret rotation frequency tuning.
> - Observability (metrics, dashboards, alerts).


---

## ⚙️ Tunables (via Environment Variables)

| Variable                     | Purpose |
|------------------------------|---------|
| `ROTATION_MINUTES`           | Rotation frequency (default: 20) |
| `AWS_SECRET_ID`              | ARN of AWS secret containing credentials |
| `AWS_CONN_BLOB_SECRET_ID`    | ARN of AWS secret containing connection blob |
| `OCI_SECRET_OCID`            | OCID of OCI Vault secret containing credentials |
| `OCI_CONN_BLOB_SECRET_OCID`  | OCID of OCI Vault secret containing connection blob |
| `RDS_ENGINE`                 | `postgres` or `mysql` |
| `RDS_HOST`, `RDS_DBNAME`, `RDS_PORT` | RDS connection info |
| `OCI_ADB_USER`, `OCI_ADB_DSN`| OCI DB connection details |
| `AUDIT_HASH_SALT_SSM`        | HMAC salt for audit logging |

---

## 🚀 Deployment Targets

- **AWS Lambda**  
  - EventBridge rule → Lambda container image
  - IAM role with least-privilege policies

- **OCI Functions**  
  - OCI Events rule → Function container image
  - Dynamic group + policy for Vault & Object Storage access
