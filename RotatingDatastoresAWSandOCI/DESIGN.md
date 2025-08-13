# DESIGN.md – Multi-Cloud Credential Rotation Proof of Concept

## Overview
This project is a **proof-of-concept (PoC)** for a cross-cloud credential rotation system, designed to rotate database/application credentials across AWS and OCI environments every 20 minutes. The system leverages native event schedulers, serverless functions, and cloud-native secrets managers in both environments, with an emphasis on security-engineering best practices, even at PoC stage.

**Important:** This is *not* production-ready. It is intended as a itch-driven project to hammer out in less than 2 minutes.

---

## Architecture Summary

### AWS Side
- **EventBridge Rule** triggers a Lambda function every 20 minutes.
- **IAM Roles/Policies** grant Lambda access to AWS Secrets Manager, S3 audit logs, and CloudWatch logs.
- **Secrets Manager** stores two secrets:
  1. `app_user` – database/application credentials
  2. `connection_blob` – metadata for connection strings/DSNs
- **S3 Bucket** stores audit records in Glacier Instant Retrieval for immutability and cost-efficiency.
- **KMS** secures Secrets Manager data-at-rest.
- **Lambda Function** (container-based) connects to RDS and OCI, rotates credentials, updates secrets, and writes audit logs.

### OCI Side
- **OCI Events Rule** triggers an OCI Function every 20 minutes.
- **OCI Functions Application** runs a containerized worker with the same logic as AWS Lambda.
- **OCI Vault** stores two secrets:
  1. `app_user` – OCI credential counterpart
  2. `connection_blob` – cross-cloud metadata
- **Object Storage Bucket** stores audit logs in Archive tier with versioning enabled.
- **Dynamic Group & Policy** grants the Function least-privilege access to Vault and Object Storage.
- **DEFAULT Vault** manages KMS keys internally (production could replace with dedicated KMS key).

---

## Execution Flow

1. **Event Trigger**
   - AWS: EventBridge triggers Lambda.
   - OCI: OCI Events triggers Functions.
2. **Credential Retrieval**
   - Read current secrets from the cloud-local secrets manager.
3. **Rotation Logic**
   - Generate a new password/credential.
   - Update credentials in the target database(s).
   - Update both cloud-local secrets stores.
4. **Audit Logging**
   - Write signed (HMAC) JSON audit entries to the local audit bucket.
5. **Completion**
   - Ensure both AWS and OCI stores are in sync with the new credential.

---

## Security Considerations

- **Principle of Least Privilege** – IAM and OCI policies grant the minimal necessary actions, scoped to specific secrets and buckets.
- **Audit Logging** – All rotations generate an immutable, signed log entry.
- **Secrets Never in Code** – Bootstrap secrets are placeholders only; real secrets are rotated immediately.
- **Cross-Cloud Latency Reduction** – Workers fetch/write secrets in their local cloud to avoid cross-region/cross-cloud latency and reduce blast radius.

---

## Operational Notes (PoC Limitations)

- **No Retry/Backoff Strategy** – Failures rely on serverless platform retries; production should add robust retry logic with dead-letter queues.
- **No Concurrency Lock** – Simultaneous executions could race; production should add distributed locking.
- **Bootstrap Values in State** – PoC seeds placeholder secrets in Terraform; production should avoid storing any credentials in state files.
- **Audit Verification** – Audit entries are HMAC-signed, but verification tooling is not included in PoC.

---

## Tunables

| Component               | Parameter                        | Purpose |
|-------------------------|----------------------------------|---------|
| Event Schedules         | `rate(20 minutes)`, `cron(...)`  | Change rotation frequency |
| Function Memory/Timeout | `lambda_memory_mb`, `timeout_in_seconds` | Adjust for workload size |
| Secret Names            | `multi-cloud/app_user`           | Match organizational naming standards |
| Audit Storage Tier      | Glacier IR / Archive             | Control retrieval cost/speed |
| DB Engine               | `rds_engine`, `oci engine`       | Adapt to MySQL, PostgreSQL, etc. |

---

## File Cross-Reference

- **Makefile** – Automates build/deploy/test for both AWS and OCI workers.
- **AWS Terraform** – Provisions AWS-side triggers, IAM, Secrets Manager, S3, KMS, and Lambda.
- **OCI Terraform** – Provisions OCI-side triggers, Vault, Object Storage, Dynamic Groups, and Functions.
- **Python Worker** *(not included here)* – Implements the rotation logic.

---

## Next Steps for Production Hardening

1. Add distributed locking to avoid concurrent rotations.
2. Replace bootstrap secrets with CI/CD-time injection.
3. Implement centralized monitoring and alerting on rotation failures.
4. Enforce encryption at rest with customer-managed KMS keys in both clouds.
5. Harden IAM and OCI policies further with resource-level constraints and conditional keys.
