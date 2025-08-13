# servers/interceptors.py
import grpc, base64, os
from common.attestation_snp import verify_snp_report

TEE_POLICY_HASH = os.getenv("TEE_POLICY_HASH", "")  # hex string

class AttestServerInterceptor(grpc.ServerInterceptor):
    def intercept_service(self, continuation, handler_call_details):
        meta = dict(handler_call_details.invocation_metadata or [])
        att_b64 = meta.get("x-tee-attestation")
        nonce_b64 = meta.get("x-tee-nonce")
        if not att_b64 or not nonce_b64:
            context = grpc.ServicerContext  # not used; just schematic
        try:
            att = base64.b64decode(att_b64)
            nonce = base64.b64decode(nonce_b64)
            ok = verify_snp_report(att, bytes.fromhex(TEE_POLICY_HASH) if TEE_POLICY_HASH else b"", nonce + bytes.fromhex(TEE_POLICY_HASH or ""))
            if not ok:
                # Reject before handler runs
                def abort(request, context):
                    context.abort(grpc.StatusCode.PERMISSION_DENIED, "TEE attestation failed")
                return grpc.unary_unary_rpc_method_handler(abort)
        except Exception:
            def abort(request, context):
                context.abort(grpc.StatusCode.PERMISSION_DENIED, "invalid TEE metadata")
            return grpc.unary_unary_rpc_method_handler(abort)
        return continuation(handler_call_details)
