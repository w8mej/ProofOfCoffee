# -----------------------------------------------------------------------------
# File: common/mpc_provider.py
# What it does:
#   Defines the pluggable MPC engine interface and a placeholder implementation
#   used by the POC. Threshold is modeled as an approval quorum (engineers +
#   stewards). Once quorum is met, a single Ed25519 signature is emitted.
#
# Security & Ops notes:
#   - ❗Not real threshold crypto: no DKG, no FROST. Replace with a real engine
#     that never centralizes secrets and uses hardware-backed shares.
#   - Private key is ephemeral and lives only in RAM; new instance = new MPK.
#   - This module is not thread-safe; wrap with locks if accessed concurrently.
#
# Tunables:
#   - Quorum counts enforced by Coordinator, not here.
#   - Session TTL is recorded, not enforced, by this class.
# -----------------------------------------------------------------------------
from dataclasses import dataclass, field
from typing import Dict, List, Tuple
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import time
import binascii


@dataclass
class SessionState:
    repo: str
    branch: str
    commit: str
    artifact_digest: str
    expires_unix: int
    mpk_hex: str
    approvals: List[Tuple[str, str, str]] = field(
        default_factory=list)  # (name,email,role)
    partials: int = 0
    signature: bytes = b""
    cert_pem: bytes = b""


class MockThresholdEngine:
    """Placeholder MPC engine (approval-only -> one Ed25519 signature)."""

    def __init__(self):
        self._group_key = Ed25519PrivateKey.generate()
        self._sessions: Dict[str, SessionState] = {}

    def create_session(self, repo: str, branch: str, commit: str,
                       artifact_digest: str, ttl_s: int = 1800):
        sid = f"sess_{int(time.time_ns())}"
        pub = self._group_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        mpk_hex = "ed25519:" + binascii.hexlify(pub).decode()
        expires_unix = int(time.time()) + ttl_s
        self._sessions[sid] = SessionState(repo=repo, branch=branch, commit=commit,
                                           artifact_digest=artifact_digest, expires_unix=expires_unix,
                                           mpk_hex=mpk_hex)
        return sid, mpk_hex, expires_unix

    def approve(self, sid: str, name: str, email: str, role: str):
        self._sessions[sid].approvals.append((name, email, role))

    def submit_partial(self, sid: str, _wire: bytes):
        self._sessions[sid].partials += 1

    def sign_if_quorum(self, sid: str) -> bytes:
        st = self._sessions[sid]
        if st.signature:
            return st.signature
        msg = binascii.unhexlify(st.artifact_digest) if len(
            st.artifact_digest) == 64 else st.artifact_digest.encode()
        st.signature = self._group_key.sign(msg)
        return st.signature

    def get(self, sid: str) -> SessionState:
        return self._sessions[sid]

    def attach_cert(self, sid: str, cert_pem: bytes):
        self._sessions[sid].cert_pem = cert_pem
