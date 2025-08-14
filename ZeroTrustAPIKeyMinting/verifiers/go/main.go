// cmd/kms-gate/main.go
//
// A tiny Gin middleware that enforces an OCI KMS-backed receipt on inbound requests.
// It verifies the JWT’s companion headers `x-kms-sig` and `x-kms-key` by checking
// the signature over a server-defined `challenge` structure using the KMS key’s
// public key (PEM). This is intended to be placed in front of protected routes
// as an additional control-plane gate (separate from the JWT’s EdDSA signature).
//
// ──────────────────────────────────────────────────────────────────────────────
// Security & Ops
// ──────────────────────────────────────────────────────────────────────────────
//
//   - Trust Anchor: `kmsPubPem` must be the public key fetched from OCI KMS Management
//     for the key OCID that co-signed the mint challenge. Treat it like configuration
//     blessed by security (ship via secure config/Vault/Secrets, not inline).
//
//   - What is verified: This middleware recomputes SHA-256(challenge) and verifies the
//     RSA signature in header `x-kms-sig` using that digest. By default we use
//     PKCS#1 v1.5 (to match the PoC signer). If you change the signing algorithm in
//     your mint service to RSA-PSS, set env KMS_ALG=PSS here.
//
//   - Challenge reconstruction: `getChallenge(r *http.Request)` must deterministically
//     reproduce the exact byte sequence that the mint API signed with KMS (e.g., the
//     compact JSON with sorted keys {"user": "...", "scopes":[...], "ttl":..., "policy_hash":"..."}).
//     If the service perimeter needs different context, update this function consistently
//     across producers and verifiers.
//
//   - Failure mode: Missing/invalid receipt results in HTTP 401 with a minimal body.
//     Log details server-side (not shown here) to preserve privacy and avoid info leaks.
//
// ──────────────────────────────────────────────────────────────────────────────
// Tunable / Config
// ──────────────────────────────────────────────────────────────────────────────
// • KMS_ALG          : "PKCS1v15" (default) or "PSS" to select RSA padding.
// • KMS_PUB_PEM_PATH : Path to the KMS public key PEM (default: ./kms_pub.pem).
// • BIND             : Listen address (default: :8081).
//
// ──────────────────────────────────────────────────────────────────────────────
// Production Considerations
// ──────────────────────────────────────────────────────────────────────────────
//   - Pin by key OCID: Besides verifying the signature, also check that `x-kms-key`
//     matches an allowlist of expected OCIDs for this environment/tenant.
//   - Observability: Emit counters for allow/deny, and structured logs containing
//     request ID, claimed key OCID, and verification outcome.
//   - mTLS / JWT: This gate complements, not replaces, your mTLS and JWT verification.
//   - Timeouts: Add server read/write timeouts and body size limits (omitted for brevity).
//   - Key rotation: Support multiple active KMS public keys (kid→PEM map) and prefer
//     kid selection based on `x-kms-key` header.
//   - Error handling: This PoC returns minimal errors; in prod, wrap with consistent
//     error pages and correlation IDs.
//
// Build & Run
// -----------
// go mod init example.com/kms-gate
// go get github.com/gin-gonic/gin
// go build -o kms-gate ./cmd/kms-gate
// KMS_PUB_PEM_PATH=/path/to/kms_pub.pem ./kms-gate
//
// Test locally with:
//
//	curl -H "x-kms-key: ocid1.key.oc1..abc" -H "x-kms-sig: <base64sig>" http://127.0.0.1:8081/
package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

// verifyKmsReceipt checks that `sigB64` is a valid RSA signature over SHA-256(challenge)
// using the provided PEM public key. Padding scheme is selected via alg:
//
//   alg == "PSS"      → RSA-PSS with SHA-256
//   alg == "PKCS1v15" → RSA PKCS#1 v1.5 with SHA-256 (default)
//
// NOTE: The mint service (Python, kms_approval.py) signs the SHA-256 digest of the
//       challenge with message_type="DIGEST". Do NOT double-hash here.
func verifyKmsReceipt(challenge []byte, sigB64, kmsPubPem, alg string) (bool, error) {
	block, _ := pem.Decode([]byte(kmsPubPem))
	if block == nil {
		return false, errors.New("invalid PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse public key: %w", err)
	}
	rsaPub, ok := pubAny.(*rsa.PublicKey)
	if !ok {
		return false, errors.New("public key is not RSA")
	}

	// Compute digest over the exact challenge bytes
	digest := sha256.Sum256(challenge)

	// Decode base64 signature
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return false, fmt.Errorf("decode signature b64: %w", err)
	}

	switch alg {
	case "PSS":
		if err := rsa.VerifyPSS(rsaPub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}); err != nil {
			return false, fmt.Errorf("verify PSS failed: %w", err)
		}
	default: // "PKCS1v15"
		if err := rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig); err != nil {
			return false, fmt.Errorf("verify PKCS1v15 failed: %w", err)
		}
	}
	return true, nil
}

// kmsMiddleware enforces presence and validity of x-kms-sig/x-kms-key.
// getChallenge must reconstruct the exact bytes signed by the mint API.
func kmsMiddleware(kmsPubPem, alg string, getChallenge func(*http.Request) ([]byte, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		sig := c.GetHeader("x-kms-sig")
		key := c.GetHeader("x-kms-key")

		// Fail closed on missing receipt
		if sig == "" || key == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing kms receipt"})
			return
		}

		challenge, err := getChallenge(c.Request)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "bad challenge"})
			return
		}

		ok, err := verifyKmsReceipt(challenge, sig, kmsPubPem, alg)
		if !ok || err != nil {
			// In production, log `err` with request ID & claimed key OCID for forensics
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid kms receipt"})
			return
		}

		// (Optional) also enforce an allowlist on x-kms-key → environment mapping here.

		c.Next()
	}
}

func mustReadFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		panic(fmt.Errorf("read %s: %w", path, err))
	}
	return string(b)
}

func main() {
	gin.SetMode(gin.ReleaseMode)

	// Config
	bind := os.Getenv("BIND")
	if bind == "" {
		bind = ":8081"
	}
	pubPath := os.Getenv("KMS_PUB_PEM_PATH")
	if pubPath == "" {
		pubPath = "./kms_pub.pem"
	}
	alg := os.Getenv("KMS_ALG")
	if alg == "" {
		alg = "PKCS1v15"
	}

	kmsPubPem := mustReadFile(pubPath)

	// Example challenge builder: must match the mint service.
	// In the PoC we used a canonical JSON with sorted keys; replace below accordingly.
	getChallenge := func(r *http.Request) ([]byte, error) {
		// Derive the same challenge the mint API signed. For example:
		// {"user":"alice@example.com","role":"engineer","scopes":["read:logs"],"ttl":900,"policy_hash":"..."}
		// Here we show a static challenge for simplicity.
		return []byte(`{"demo":"challenge"}`), nil
	}

	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(kmsMiddleware(kmsPubPem, alg, getChallenge))

	// Protected route
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	if err := r.Run(bind); err != nil {
		panic(err)
	}
}