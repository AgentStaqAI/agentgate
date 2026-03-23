package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// jwtHeader is the decoded first segment of a JWT.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// jwtClaims contains the standard claims we validate plus the MCP-relevant ones.
type jwtClaims struct {
	Issuer    string      `json:"iss"`
	Subject   string      `json:"sub"`
	Audience  interface{} `json:"aud"` // Can be string or []string per spec
	ExpiresAt int64       `json:"exp"`
	NotBefore int64       `json:"nbf"`
	Scope     string      `json:"scope"` // Space-delimited per RFC 8693
}

// ValidateJWT fully validates an RS256 or ES256 JWT and returns the subject and scopes.
//
// Steps performed (all with stdlib only):
//  1. Split the token into header.payload.signature
//  2. Decode and parse the JOSE header to extract kid and alg
//  3. Fetch the matching public key from the JWKSCache
//  4. Verify the signature based on key type (RSA or ECDSA)
//  5. Validate standard claims: exp, nbf, iss, aud
//  6. Return sub and scope (as []string)
func ValidateJWT(tokenString string, cache *JWKSCache, issuer, audience string) (sub string, scopes []string, err error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", nil, fmt.Errorf("malformed JWT: expected 3 segments, got %d", len(parts))
	}

	// ── 1. Decode header ─────────────────────────────────────────────────────
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", nil, fmt.Errorf("decode header: %w", err)
	}
	var header jwtHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", nil, fmt.Errorf("parse header: %w", err)
	}
	if header.Alg != "RS256" && header.Alg != "ES256" {
		return "", nil, fmt.Errorf("unsupported algorithm %q: AgentGate requires RS256 or ES256", header.Alg)
	}

	// ── 2. Fetch public key ──────────────────────────────────────────────────
	pubKey, err := cache.GetKey(header.Kid)
	if err != nil {
		return "", nil, fmt.Errorf("get signing key: %w", err)
	}

	// ── 3. Verify signature ──────────────────────────────────────────────────
	// The signing input is exactly: base64url(header) + "." + base64url(payload)
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", nil, fmt.Errorf("decode signature: %w", err)
	}

	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		if header.Alg != "RS256" {
			return "", nil, fmt.Errorf("key is RSA but alg is %q", header.Alg)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sigBytes); err != nil {
			return "", nil, fmt.Errorf("RSA signature verification failed: %w", err)
		}
	case *ecdsa.PublicKey:
		if header.Alg != "ES256" {
			return "", nil, fmt.Errorf("key is EC but alg is %q", header.Alg)
		}
		// ECDSA signatures in JWT are R || S, where R and S are 32 bytes each for P-256
		if len(sigBytes) != 64 {
			return "", nil, fmt.Errorf("invalid ECDSA signature length: expected 64, got %d", len(sigBytes))
		}
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return "", nil, fmt.Errorf("ECDSA signature verification failed")
		}
	default:
		return "", nil, fmt.Errorf("unsupported key type: %T", pubKey)
	}

	// ── 4. Decode claims ─────────────────────────────────────────────────────
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims jwtClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", nil, fmt.Errorf("parse claims: %w", err)
	}

	// ── 5. Validate standard claims ──────────────────────────────────────────
	now := time.Now().Unix()

	if claims.ExpiresAt != 0 && now > claims.ExpiresAt {
		return "", nil, fmt.Errorf("token expired at %d (now %d)", claims.ExpiresAt, now)
	}
	if claims.NotBefore != 0 && now < claims.NotBefore {
		return "", nil, fmt.Errorf("token not yet valid (nbf=%d, now=%d)", claims.NotBefore, now)
	}
	if issuer != "" && claims.Issuer != issuer {
		return "", nil, fmt.Errorf("issuer mismatch: got %q, expected %q", claims.Issuer, issuer)
	}
	if audience != "" && !audienceContains(claims.Audience, audience) {
		return "", nil, fmt.Errorf("audience mismatch: token does not contain %q", audience)
	}

	// ── 6. Extract sub and scope ──────────────────────────────────────────────
	scopeList := []string{}
	if claims.Scope != "" {
		scopeList = strings.Fields(claims.Scope) // "read write admin" → ["read","write","admin"]
	}

	return claims.Subject, scopeList, nil
}

// audienceContains handles both string and []string aud claims per the JWT spec.
func audienceContains(aud interface{}, target string) bool {
	switch v := aud.(type) {
	case string:
		return v == target
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok && s == target {
				return true
			}
		}
	}
	return false
}
