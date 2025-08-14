/**
 * kms-receipt.js — Express middleware to enforce OCI KMS co-sign receipts (documented)
 *
 * Overview
 * --------
 * This module verifies the **KMS co-sign receipt** that the mint service embeds in JWT headers:
 *   - `x-kms-sig`: Base64 RSA signature produced by OCI KMS over a canonical "challenge" document
 *   - `x-kms-key`: OCI Key OCID that created the signature (optional allowlist enforcement)
 *
 * The middleware complements your normal auth (mTLS / JWT EdDSA) by requiring a **second,
 * HSM-backed attestation** at the service perimeter. Put it in front of protected routes.
 *
 * Security & Ops
 * --------------
 * - Trust anchor: `kmsPubPem` must be the PEM public key fetched from OCI KMS (Management API)
 *   for the specific key OCID. Store/distribute it via a secure config or a secret store.
 * - What is verified: We verify an **RSA/SHA-256** PKCS#1 v1.5 signature over the **original
 *   challenge bytes**. In the PoC, the signer calls KMS with `message_type="DIGEST"` using
 *   `SHA-256(challenge)`, which is compatible with verifying by hashing the *original* challenge
 *   once here (i.e., do **not** double-hash).
 * - Deterministic challenge: `getChallenge(req)` must reproduce **exactly** the byte sequence
 *   that the mint API signed (e.g., JSON with sorted keys and no extra whitespace).
 * - Hardening:
 *     • Also enforce `x-kms-key` against an allowlist (env or config map) for your env/tenant.
 *     • Rate-limit failures and log with request IDs for forensics.
 *     • Add mTLS between Envoy ↔ service and validate JWT separately.
 *
 * Tunable / Config
 * ----------------
 * - `kmsReceiptMiddleware(kmsPubPem, getChallenge, opts?)`
 *     • `kmsPubPem`    : string PEM of the KMS public key (RSA).
 *     • `getChallenge` : (req) => Buffer | string that reconstructs the challenge.
 *     • `opts`         : { allowKeyOcids?: string[] } (optional x-kms-key allowlist)
 *
 * Production Considerations
 * -------------------------
 * - Key rotation: Support multiple active public keys (map key OCID → PEM), select by `x-kms-key`.
 * - Algorithms: If you switch the mint service to RSA-PSS, update verification padding here.
 * - Headers: Treat `x-kms-sig` and `x-kms-key` as sensitive; avoid logging full values.
 * - Errors: Return generic 401 to clients; emit detailed logs server-side.
 */

const crypto = require('crypto');
const express = require('express');

/**
 * Verify the KMS receipt using RSA/SHA-256 PKCS#1 v1.5.
 *
 * IMPORTANT: Do NOT double-hash. The mint service asked KMS to sign SHA-256(challenge)
 * (message_type="DIGEST"). Verifying with RSA-SHA256 over the ORIGINAL challenge bytes
 * results in the verifier computing SHA-256(challenge) internally, which matches the
 * digest KMS signed.
 *
 * @param {Buffer} challengeBuf - Original challenge bytes (not pre-hashed)
 * @param {string} sigB64       - Base64-encoded signature from header x-kms-sig
 * @param {string} kmsPubPem    - RSA public key in PEM (from OCI KMS Management get_public_key)
 * @returns {boolean} true if valid
 */
function verifyKmsReceipt(challengeBuf, sigB64, kmsPubPem) {
  const verify = crypto.createVerify('RSA-SHA256');
  verify.update(challengeBuf);
  verify.end();
  return verify.verify(kmsPubPem, Buffer.from(sigB64, 'base64'));
}

/**
 * Minimal Express middleware that enforces presence and validity of the KMS receipt.
 * Assumes JWT auth (EdDSA) and mTLS are handled elsewhere in the stack.
 *
 * @param {string|Record<string,string>} keyMaterial - Either a single PEM string, or a map
 *   from allowed key OCID → PEM to support rotation (recommended).
 * @param {(req: import('http').IncomingMessage) => (Buffer|string)} getChallenge - Deterministic builder
 * @param {{ allowKeyOcids?: string[] }} [opts] - Optional allowlist for `x-kms-key`
 */
function kmsReceiptMiddleware(keyMaterial, getChallenge, opts = {}) {
  /** @type {(ocid: string) => string|undefined} */
  const pemForKey = (ocid) => {
    if (typeof keyMaterial === 'string') return keyMaterial;
    return keyMaterial[ocid];
  };

  const allowed = Array.isArray(opts.allowKeyOcids) ? new Set(opts.allowKeyOcids) : null;

  return (req, res, next) => {
    try {
      const sig = req.headers['x-kms-sig'];
      const key = req.headers['x-kms-key'];

      if (!sig || !key) {
        return res.status(401).send('missing kms receipt');
      }

      if (allowed && !allowed.has(String(key))) {
        return res.status(401).send('kms key ocid not allowed');
      }

      const kmsPubPem = pemForKey(String(key));
      if (!kmsPubPem) {
        return res.status(401).send('unknown kms key');
      }

      const ch = getChallenge(req);
      const challengeBuf = Buffer.isBuffer(ch) ? ch : Buffer.from(String(ch));

      if (!verifyKmsReceipt(challengeBuf, String(sig), kmsPubPem)) {
        return res.status(401).send('invalid kms receipt');
      }

      return next();
    } catch {
      // Fail closed on any parsing/verification error
      return res.status(401).send('kms verification error');
    }
  };
}

module.exports = { kmsReceiptMiddleware, verifyKmsReceipt };

/* ----------------------------------------------------------------------------
Example usage (standalone)
-------------------------------------------------------------------------------
const fs = require('fs');
const app = express();

// Support one active key (simple) or multiple by OCID (recommended)
const kmsPubPem = fs.readFileSync(process.env.KMS_PUB_PEM_PATH || './kms_pub.pem', 'utf8');
// const kmsKeys = { "ocid1.key.oc1..abcd...": kmsPubPem, "ocid1.key.oc1..efgh...": otherPem };

app.use(
  kmsReceiptMiddleware(kmsPubPem, (req) => {
    // Recreate the exact challenge the mint API signed (must match producer):
    // Example PoC JSON (sorted keys, compact):
    // {"policy_hash":"...","role":"engineer","scopes":["read:logs"],"ttl":900,"user":"alice@example.com"}
    return Buffer.from('{"demo":"challenge"}'); // replace with your canonical JSON
  }, {
    // allowKeyOcids: ["ocid1.key.oc1..abcd..."], // optional allowlist
  })
);

app.get('/protected', (req, res) => res.json({ ok: true }));
app.listen(process.env.BIND || 8081, () => console.log('listening'));
*/