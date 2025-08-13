# -----------------------------------------------------------------------------
# File: common/grpc_attest.py
# What it does:
#   gRPC client/server interceptors that attach and verify **TEE attestation**
#   (AMD SEV-SNP) on every RPC. This makes enclave state part of the trust model.
#
# Security & Ops notes:
#   - Bind a fresh NONCE and agreed POLICY hash into the attestation report_data.
#   - Enforce deadlines & size caps; reject if metadata absent/invalid.
#   - Replace POC verification with real SNP verification or a Verifier.
# Tunables:
#   - TEE_POLICY_HASH (hex) — expected policy/image hash, must match on both ends.
# -----------------------------------------------------------------------------
import os
import base64
import grpc
from .attestation_snp import get_snp_report, verify_snp_report, Evidence

TEE_POLICY_HASH_HEX = os.getenv("TEE_POLICY_HASH", "")
TEE_POLICY_HASH = bytes.fromhex(
    TEE_POLICY_HASH_HEX) if TEE_POLICY_HASH_HEX else b""

# Client-side: attach attestation metadata to each unary RPC


class AttestClientUnaryInterceptor(grpc.UnaryUnaryClientInterceptor):
    def __init__(self, policy_hash: bytes = TEE_POLICY_HASH):
        self._policy = policy_hash

    def intercept_unary_unary(self, continuation, client_call_details, request):
        nonce = os.urandom(32)
        ev = get_snp_report(nonce, self._policy)
        md = [] if client_call_details.metadata is None else list(
            client_call_details.metadata)
        md.append(("x-tee-nonce", base64.b64encode(nonce).decode()))
        md.append(("x-tee-policy", TEE_POLICY_HASH_HEX))
        md.append(("x-tee-attestation", base64.b64encode(ev.raw).decode()))
        new_details = grpc.ClientCallDetails(
            client_call_details.method, client_call_details.timeout,
            tuple(md), client_call_details.credentials,
            getattr(client_call_details, 'wait_for_ready', None),
            getattr(client_call_details, 'compression', None),
        )
        return continuation(new_details, request)


def intercept_channel(channel: grpc.Channel) -> grpc.Channel:
    return grpc.intercept_channel(channel, AttestClientUnaryInterceptor())

# Server-side: verify attestation metadata before handing request to handler


class AttestServerInterceptor(grpc.ServerInterceptor):
    def intercept_service(self, continuation, handler_call_details):
        meta = dict(handler_call_details.invocation_metadata or [])
        att = meta.get("x-tee-attestation")
        nonce = meta.get("x-tee-nonce")
        pol = meta.get("x-tee-policy")
        if not (att and nonce):
            def abort(request, context): context.abort(
                grpc.StatusCode.PERMISSION_DENIED, "missing TEE metadata")
            return grpc.unary_unary_rpc_method_handler(abort)
        try:
            ev = Evidence(raw=base64.b64decode(att), nonce=base64.b64decode(nonce),
                          policy_hash=bytes.fromhex(pol) if pol else b"")
        except Exception:
            def abort(request, context): context.abort(
                grpc.StatusCode.PERMISSION_DENIED, "invalid TEE metadata")
            return grpc.unary_unary_rpc_method_handler(abort)
        if not verify_snp_report(ev):
            def abort(request, context): context.abort(
                grpc.StatusCode.PERMISSION_DENIED, "TEE attestation verification failed")
            return grpc.unary_unary_rpc_method_handler(abort)
        return continuation(handler_call_details)
