# -----------------------------------------------------------------------------
# File: clients/cli.py
# What it does:
#   Engineer CLI with optional **mTLS** and **TEE attestation** metadata attached
#   on every RPC. Commands: request, join, verify.
#
# Security & Ops notes:
#   - In production, configure secure channels and verify server identities.
#   - Attestation ties calls to a measured/approved enclave policy.
# Tunables: COORDINATOR_ADDR, TLOG_ADDR, CLIENT_TLS_CA/CERT/KEY, TEE_POLICY_HASH
# -----------------------------------------------------------------------------
import os
import argparse
import sys
import time
import binascii
import grpc
from gen import mpc_pb2, mpc_pb2_grpc
from common.grpc_attest import intercept_channel


def _channel(addr: str) -> grpc.Channel:
    ca = os.getenv("CLIENT_TLS_CA")
    cert = os.getenv("CLIENT_TLS_CERT")
    key = os.getenv("CLIENT_TLS_KEY")
    if ca and cert and key:
        with open(ca, 'rb') as f:
            root = f.read()
        with open(cert, 'rb') as f:
            c = f.read()
        with open(key, 'rb') as f:
            k = f.read()
        creds = grpc.ssl_channel_credentials(
            root_certificates=root, private_key=k, certificate_chain=c)
        ch = grpc.secure_channel(addr, creds)
    else:
        ch = grpc.insecure_channel(addr)
    return intercept_channel(ch)


def coord_stub(addr: str): return mpc_pb2_grpc.CoordinatorStub(_channel(addr))


def tlog_stub(addr: str): return mpc_pb2_grpc.TransparencyLogStub(
    _channel(addr))


def cmd_request(args):
    c = coord_stub(args.coordinator)
    resp = c.CreateSession(mpc_pb2.CreateSessionRequest(
        repo=args.repo, branch=args.branch, commit=args.commit, artifact_digest=args.artifact_digest
    ), timeout=5)
    print(f"Session: {resp.session_id}\nMPK: {resp.mpk}\nExpires: {resp.expires_unix}\nQuorum: {resp.required_quorum.engineers}E/{resp.required_quorum.stewards}S")
    return 0


def cmd_join(args):
    c = coord_stub(args.coordinator)
    token = "demo-token"
    jr = mpc_pb2.JoinRequest(session_id=args.session,
                             participant=mpc_pb2.Participant(
                                 name=args.name, email=args.email),
                             webauthn=mpc_pb2.WebAuthnToken(opaque=token))
    out = c.Join(jr, timeout=5)
    print(f"Joined as role={out.role}")
    c.SubmitShare(mpc_pb2.SigShare(session_id=args.session,
                  wire_message=b"partial"), timeout=5)
    time.sleep(0.3)
    sig = c.GetSignature(mpc_pb2.SessionRef(id=args.session), timeout=5)
    if sig.complete:
        print(
            f"Signature (hex, head): {binascii.hexlify(sig.signature).decode()[:64]}…")
        print(f"Certificate (PEM head): {sig.certificate_pem[:60]}…")
    else:
        print("Not complete yet — need more participants.")
    return 0


def cmd_verify(args):
    t = tlog_stub(args.tlog)
    entry = t.GetByArtifact(mpc_pb2.GetByArtifactRequest(
        artifact_digest=args.artifact_digest), timeout=5)
    if not entry.artifact_digest:
        print("No transparency entry found")
        return 0
    print(
        f"TLog entry: digest={entry.artifact_digest} mpk={entry.mpk} ts={entry.ts_unix}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="mpc-cli", description="MPC signing demo CLI (gRPC, TEE-aware)")
    ap.add_argument("command", choices=["request", "join", "verify"])
    ap.add_argument("--coordinator",
                    default=os.getenv("COORDINATOR_ADDR", "localhost:50051"))
    ap.add_argument(
        "--tlog", default=os.getenv("TLOG_ADDR", "localhost:50053"))
    ap.add_argument("--repo", default="games/platform")
    ap.add_argument("--branch", default="main")
    ap.add_argument("--commit", default="HEAD")
    ap.add_argument("--artifact-digest", dest="artifact_digest", default="")
    ap.add_argument("--session", default="")
    ap.add_argument("--name", default="Participant")
    ap.add_argument("--email", default="participant@example.com")
    args = ap.parse_args(argv)

    if args.command == "request":
        if not args.artifact_digest:
            print("--artifact-digest required", file=sys.stderr)
            return 1
        return cmd_request(args)
    elif args.command == "join":
        if not args.session:
            print("--session required", file=sys.stderr)
            return 1
        return cmd_join(args)
    elif args.command == "verify":
        if not args.artifact_digest:
            print("--artifact-digest required", file=sys.stderr)
            return 1
        return cmd_verify(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
