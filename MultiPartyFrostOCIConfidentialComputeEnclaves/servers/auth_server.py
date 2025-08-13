# -----------------------------------------------------------------------------
# File: servers/auth_server.py
# What it does:
#   POC AuthN shim. Verifies a demo WebAuthn token. Adds **TEE attestation** and optional **mTLS**.
#
# Security & Ops notes:
#   - Not real WebAuthn; replace with spec-compliant validation and origin checks.
#   - In production, require mTLS and verify enclave evidence on every RPC.
# Tunables: AUTH_BIND, AUTH_THREADS, AUTH_DEMO_TOKEN, AUTH_TLS_CERT/KEY, TEE_POLICY_HASH
# -----------------------------------------------------------------------------
import os
from concurrent import futures
from typing import Optional
import grpc
from gen import mpc_pb2, mpc_pb2_grpc
from common.grpc_attest import AttestServerInterceptor

BIND_ADDR = os.getenv("AUTH_BIND", "[::]:50054")
MAX_WORKERS = int(os.getenv("AUTH_THREADS", "4"))
TLS_CERT = os.getenv("AUTH_TLS_CERT")
TLS_KEY = os.getenv("AUTH_TLS_KEY")
DEMO_TOKEN = os.getenv("AUTH_DEMO_TOKEN", "demo-token")


class AuthN(mpc_pb2_grpc.AuthNServicer):
    def VerifyWebAuthn(self, request, context):
        ok = (request.token.opaque == DEMO_TOKEN)
        return mpc_pb2.VerifyWebAuthnResponse(ok=ok, user="demo@local" if ok else "", groups=["dev"] if ok else [])


def _maybe_tls_creds() -> Optional[grpc.ServerCredentials]:
    if TLS_CERT and TLS_KEY:
        with open(TLS_CERT, 'rb') as c, open(TLS_KEY, 'rb') as k:
            return grpc.ssl_server_credentials([(k.read(), c.read())])
    return None


def serve(bind_addr: str = BIND_ADDR):
    server = grpc.server(futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS), interceptors=[AttestServerInterceptor()])
    mpc_pb2_grpc.add_AuthNServicer_to_server(AuthN(), server)
    creds = _maybe_tls_creds()
    if creds:
        server.add_secure_port(bind_addr, creds)
        mode = "TLS"
    else:
        server.add_insecure_port(bind_addr)
        mode = "PLAINTEXT"
    server.start()
    print(f"[auth] gRPC {mode} on {bind_addr}")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
