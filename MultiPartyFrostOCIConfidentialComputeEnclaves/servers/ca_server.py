# -----------------------------------------------------------------------------
# File: servers/ca_server.py
# What it does:
#   Ephemeral CA with optional **mTLS** and **TEE attestation** verification.
#
# Security & Ops notes:
#   - Demo uses in-memory self-signed root; replace with org PKI/HSM in prod.
#   - Bind cert subjects/claims to identity and MPK; keep TTL short.
# Tunables: CA_BIND, CA_THREADS, CA_TTL_SECONDS, CA_TLS_CERT/KEY, CA_ORG_NAME, CA_ROOT_CN, TEE_POLICY_HASH
# -----------------------------------------------------------------------------
import os
from concurrent import futures
from datetime import datetime, timedelta
from typing import Optional
import grpc
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from gen import mpc_pb2, mpc_pb2_grpc
from common.grpc_attest import AttestServerInterceptor

BIND_ADDR = os.getenv("CA_BIND", "[::]:50052")
MAX_WORKERS = int(os.getenv("CA_THREADS", "8"))
TLS_CERT = os.getenv("CA_TLS_CERT")
TLS_KEY = os.getenv("CA_TLS_KEY")
ORG_NAME = os.getenv("CA_ORG_NAME", "Demo Org")
ROOT_CN = os.getenv("CA_ROOT_CN", "Demo Ephemeral Root")
DEFAULT_TTL = int(os.getenv("CA_TTL_SECONDS", "1800"))


class EphemeralCA(mpc_pb2_grpc.EphemeralCAServicer):
    def __init__(self):
        self._root_key = Ed25519PrivateKey.generate()
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG_NAME),
            x509.NameAttribute(NameOID.COMMON_NAME, ROOT_CN),
        ])
        self._root_cert = (x509.CertificateBuilder()
                           .subject_name(subject).issuer_name(issuer)
                           .public_key(self._root_key.public_key())
                           .serial_number(x509.random_serial_number())
                           .not_valid_before(datetime.utcnow())
                           .not_valid_after(datetime.utcnow()+timedelta(days=1))
                           .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                           .sign(self._root_key, hashes.SHA256())
                           )

    def Issue(self, request, context):
        ttl = int(request.ttl_seconds) if request.ttl_seconds > 0 else DEFAULT_TTL
        nb = datetime.utcnow()
        na = nb + timedelta(seconds=ttl)
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG_NAME),
            x509.NameAttribute(NameOID.COMMON_NAME,
                               request.subject_email or "unknown"),
        ])
        leaf = (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(self._root_cert.subject)
                .public_key(self._root_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(nb).not_valid_after(na)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=False)
                .sign(self._root_key, hashes.SHA256())
                )
        return mpc_pb2.IssueCertResponse(
            cert_pem=leaf.public_bytes(Encoding.PEM),
            chain_pem=self._root_cert.public_bytes(Encoding.PEM),
            expires_unix=int(na.timestamp())
        )


def _maybe_tls_creds() -> Optional[grpc.ServerCredentials]:
    if TLS_CERT and TLS_KEY:
        with open(TLS_CERT, 'rb') as c, open(TLS_KEY, 'rb') as k:
            return grpc.ssl_server_credentials([(k.read(), c.read())])
    return None


def serve(bind_addr: str = BIND_ADDR):
    server = grpc.server(futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS), interceptors=[AttestServerInterceptor()])
    mpc_pb2_grpc.add_EphemeralCAServicer_to_server(EphemeralCA(), server)
    creds = _maybe_tls_creds()
    if creds:
        server.add_secure_port(bind_addr, creds)
        mode = "TLS"
    else:
        server.add_insecure_port(bind_addr)
        mode = "PLAINTEXT"
    server.start()
    print(f"[ca] gRPC {mode} on {bind_addr}")
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
