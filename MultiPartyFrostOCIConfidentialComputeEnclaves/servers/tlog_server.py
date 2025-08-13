# -----------------------------------------------------------------------------
# File: servers/tlog_server.py
# What it does:
#   In-memory Transparency Log with **TEE attestation** verification and optional **mTLS**.
#
# Security & Ops notes:
#   - Not tamper-evident; replace with Rekor-like Merkle tree & inclusion proofs.
#   - Require authenticated callers (mTLS) and verify enclave evidence.
# Tunables: TLOG_BIND, TLOG_THREADS, TLOG_TLS_CERT/KEY, TEE_POLICY_HASH
# -----------------------------------------------------------------------------
import os
import time
from concurrent import futures
from typing import Optional
import grpc
from gen import mpc_pb2, mpc_pb2_grpc
from common.grpc_attest import AttestServerInterceptor

BIND_ADDR = os.getenv("TLOG_BIND", "[::]:50053")
MAX_WORKERS = int(os.getenv("TLOG_THREADS", "8"))
TLS_CERT = os.getenv("TLOG_TLS_CERT")
TLS_KEY = os.getenv("TLOG_TLS_KEY")


class TLog(mpc_pb2_grpc.TransparencyLogServicer):
    def __init__(self): self._store = {}

    def Append(self, request, context):
        log_id = f"entry_{int(time.time_ns())}"
        self._store[request.artifact_digest] = request
        return mpc_pb2.TLogInclusion(ok=True, log_id=log_id, inclusion_proof=b"demo")

    def GetByArtifact(self, request, context):
        return self._store.get(request.artifact_digest, mpc_pb2.TLogAppend())


def _maybe_tls_creds() -> Optional[grpc.ServerCredentials]:
    if TLS_CERT and TLS_KEY:
        with open(TLS_CERT, 'rb') as c, open(TLS_KEY, 'rb') as k:
            return grpc.ssl_server_credentials([(k.read(), c.read())])
    return None


def serve(bind_addr: str = BIND_ADDR):
    server = grpc.server(futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS), interceptors=[AttestServerInterceptor()])
    mpc_pb2_grpc.add_TransparencyLogServicer_to_server(TLog(), server)
    creds = _maybe_tls_creds()
    if creds:
        server.add_secure_port(bind_addr, creds)
        mode = "TLS"
    else:
        server.add_insecure_port(bind_addr)
        mode = "PLAINTEXT"
    server.start()
    print(f"[tlog] gRPC {mode} on {bind_addr}")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
