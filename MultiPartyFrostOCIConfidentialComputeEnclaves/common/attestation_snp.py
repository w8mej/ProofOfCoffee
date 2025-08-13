# -----------------------------------------------------------------------------
# File: common/attestation_snp.py
# What it does:
#   Helpers for AMD SEV-SNP attestation inside OCI Confidential VMs. This POC
#   includes a safe placeholder that simulates evidence so the demo runs
#   without /dev/sev-guest access.
#
# Security & Ops notes:
#   - Replace placeholder with real SNP_GET_REPORT ioctl + endorsement chain
#     verification (or call a central Verifier). Bind a fresh NONCE and your
#     POLICY hash into report_data to prevent replay.
# -----------------------------------------------------------------------------
import hashlib
import dataclasses


@dataclasses.dataclass
class Evidence:
    raw: bytes
    nonce: bytes
    policy_hash: bytes


def _fake_report(user_data: bytes) -> bytes:
    # POC placeholder (NOT SECURE).
    return b"SNP_REPORT_PLACEHOLDER:" + hashlib.sha256(user_data).digest()


def get_snp_report(nonce: bytes, policy_hash: bytes) -> Evidence:
    user_data = hashlib.sha256(nonce + policy_hash).digest()
    report = _fake_report(user_data)
    return Evidence(raw=report, nonce=nonce, policy_hash=policy_hash)


def verify_snp_report(evidence: Evidence) -> bool:
    expected_tail = hashlib.sha256(
        evidence.nonce + evidence.policy_hash).digest()
    return evidence.raw.endswith(expected_tail)
