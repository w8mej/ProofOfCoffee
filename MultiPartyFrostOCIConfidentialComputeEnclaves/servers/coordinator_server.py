# -----------------------------------------------------------------------------
# File: servers/coordinator_server.py
# What it does:
#   Coordinator service with **TEE attestation verification** and optional **mTLS**.
#   Orchestrates sessions, approvals, signatures, and transparency logging.
#
# Security & Ops notes:
#   - Replace MockThresholdEngine with real MPC/FROST (no centralized secrets).
#   - Enforce mTLS and TEE attestation before serving requests.
#   - Add rate limiting and structured audit logging via interceptors.
# Tunables: REQUIRED_ENGINEERS, REQUIRED_STEWARDS, CA_ADDR, TLOG_ADDR, AUTH_ADDR,
#           COORD_BIND, COORD_THREADS, COORD_TLS_CERT/KEY, TEE_POLICY_HASH
# -----------------------------------------------------------------------------
import os
import time
from concurrent import futures
import grpc
from google.protobuf import empty_pb2
from gen import mpc_pb2, mpc_pb2_grpc
from common.mpc_provider import MockThresholdEngine
from common.grpc_attest import AttestServerInterceptor, intercept_channel

REQUIRED_ENGINEERS = int(os.getenv("REQUIRED_ENGINEERS", "1"))
REQUIRED_STEWARDS = int(os.getenv("REQUIRED_STEWARDS",  "2"))
CA_ADDR = os.getenv("CA_ADDR",   "localhost:50052")
TLOG_ADDR = os.getenv("TLOG_ADDR", "localhost:50053")
AUTH_ADDR = os.getenv("AUTH_ADDR", "localhost:50054")
BIND_ADDR = os.getenv("COORD_BIND", "[::]:50051")
MAX_WORKERS = int(os.getenv("COORD_THREADS", "16"))
TLS_CERT = os.getenv("COORD_TLS_CERT")
TLS_KEY = os.getenv("COORD_TLS_KEY")


def _secure_channel(addr: str) -> grpc.Channel:
    # POC: plaintext + attestation to downstream. For production, use secure_channel with CA trust.
    return intercept_channel(grpc.insecure_channel(addr))


class CoordinatorServicer(mpc_pb2_grpc.CoordinatorServicer):
    def __init__(self):
        self.engine = MockThresholdEngine()
        self.ca = mpc_pb2_grpc.EphemeralCAStub(_secure_channel(CA_ADDR))
        self.tlog = mpc_pb2_grpc.TransparencyLogStub(
            _secure_channel(TLOG_ADDR))
        self.auth = mpc_pb2_grpc.AuthNStub(_secure_channel(AUTH_ADDR))

    def CreateSession(self, request, context):
        sid, mpk, exp = self.engine.create_session(
            request.repo, request.branch, request.commit, request.artifact_digest, 1800)
        return mpc_pb2.CreateSessionResponse(session_id=sid, mpk=mpk, expires_unix=exp,
                                             required_quorum=mpc_pb2.Quorum(engineers=REQUIRED_ENGINEERS, stewards=REQUIRED_STEWARDS))

    def Join(self, request, context):
        v = self.auth.VerifyWebAuthn(
            mpc_pb2.VerifyWebAuthnRequest(token=request.webauthn))
        if not v.ok:
            context.abort(grpc.StatusCode.PERMISSION_DENIED, "webauthn failed")
        st = self.engine.get(request.session_id)
        ecount = sum(1 for _, _, r in st.approvals if r == "engineer")
        role = "engineer" if ecount < REQUIRED_ENGINEERS else "steward"
        p = request.participant
        self.engine.approve(request.session_id, p.name, p.email, role)
        return mpc_pb2.JoinResponse(ok=True, role=role)

    def SubmitNonce(self, request, context): return empty_pb2.Empty()

    def SubmitShare(self, request, context):
        self.engine.submit_partial(request.session_id, request.wire_message)
        return empty_pb2.Empty()

    def GetSignature(self, request, context):
        st = self.engine.get(request.id)
        ecount = sum(1 for _, _, r in st.approvals if r == "engineer")
        scount = sum(1 for _, _, r in st.approvals if r == "steward")
        complete = False
        sig_bytes = b""
        if ecount >= REQUIRED_ENGINEERS and scount >= REQUIRED_STEWARDS and st.partials >= (REQUIRED_ENGINEERS+REQUIRED_STEWARDS):
            sig_bytes = self.engine.sign_if_quorum(request.id)
            complete = True
            if not st.cert_pem:
                cert = self.ca.Issue(mpc_pb2.IssueCertRequest(
                    mpk=st.mpk_hex, subject_email=(
                        st.approvals[0][1] if st.approvals else "unknown"),
                    ttl_seconds=1800, claims={"repo": st.repo, "branch": st.branch, "commit": st.commit}
                ))
                self.engine.attach_cert(request.id, cert.cert_pem)
                _ = self.tlog.Append(mpc_pb2.TLogAppend(
                    artifact_digest=st.artifact_digest, signature=sig_bytes, mpk=st.mpk_hex,
                    ts_unix=int(time.time()), policy_hash=b""))
        return mpc_pb2.SignatureResult(session_id=request.id, signature=sig_bytes, certificate_pem=st.cert_pem, complete=complete)

    def MPC(self, request_iterator, context):
        for msg in request_iterator:
            yield msg


def _maybe_tls_creds():
    if TLS_CERT and TLS_KEY:
        with open(TLS_CERT, 'rb') as c, open(TLS_KEY, 'rb') as k:
            return grpc.ssl_server_credentials([(k.read(), c.read())])
    return None


def serve(bind_addr: str = BIND_ADDR):
    server = grpc.server(futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS), interceptors=[AttestServerInterceptor()])
    mpc_pb2_grpc.add_CoordinatorServicer_to_server(
        CoordinatorServicer(), server)
    creds = _maybe_tls_creds()
    if creds:
        server.add_secure_port(bind_addr, creds)
        mode = "TLS"
    else:
        server.add_insecure_port(bind_addr)
        mode = "PLAINTEXT"
    server.start()
    print(f"[coordinator] gRPC {mode} on {bind_addr}")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
