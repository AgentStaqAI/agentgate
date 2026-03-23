package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// jwksResponse is the raw JSON structure from the /.well-known/jwks.json endpoint.
type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

// jwk represents a single JSON Web Key (RSA or EC public key fields).
type jwk struct {
	Kid string `json:"kid"` // Key ID
	Kty string `json:"kty"` // Key type ("RSA" or "EC")
	Alg string `json:"alg"` // Algorithm (e.g. "RS256", "ES256")
	
	// RSA fields:
	N   string `json:"n"`   // RSA modulus (base64url encoded)
	E   string `json:"e"`   // RSA exponent (base64url encoded)
	
	// EC fields:
	Crv string `json:"crv"` // Curve (e.g. "P-256")
	X   string `json:"x"`   // EC X coordinate
	Y   string `json:"y"`   // EC Y coordinate
}

// JWKSCache fetches and caches public keys from a JWKS endpoint.
// It refreshes the cache periodically to handle key rotation.
type JWKSCache struct {
	jwksURL string
	mu      sync.RWMutex
	keys    map[string]crypto.PublicKey // kid → public key
}

// NewJWKSCache creates a JWKSCache and performs an initial key fetch.
// It also spawns a background goroutine that refreshes the cache every
// refreshInterval to transparently handle key rotation at the IdP.
func NewJWKSCache(jwksURL string, refreshInterval time.Duration) (*JWKSCache, error) {
	c := &JWKSCache{
		jwksURL: jwksURL,
		keys:    make(map[string]crypto.PublicKey),
	}

	// Perform the initial fetch synchronously so we fail fast on misconfiguration.
	if err := c.refresh(); err != nil {
		return nil, fmt.Errorf("initial JWKS fetch from %s failed: %w", jwksURL, err)
	}

	// Background refresh goroutine — handles key rotation.
	go func() {
		ticker := time.NewTicker(refreshInterval)
		defer ticker.Stop()
		for range ticker.C {
			if err := c.refresh(); err != nil {
				log.Printf("[JWKS] Background refresh failed (will retry): %v", err)
			} else {
				log.Printf("[JWKS] Key cache refreshed from %s", jwksURL)
			}
		}
	}()

	return c, nil
}

// GetKey returns the public key for the given key ID (kid).
// Returns an error if the kid is not found in the cache.
func (c *JWKSCache) GetKey(kid string) (crypto.PublicKey, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	c.mu.RUnlock()

	if !ok {
		// Kid not found — try one eager refresh in case the IdP just rotated keys.
		log.Printf("[JWKS] kid %q not in cache — attempting eager refresh", kid)
		if err := c.refresh(); err != nil {
			return nil, fmt.Errorf("kid %q not found and refresh failed: %w", kid, err)
		}
		c.mu.RLock()
		key, ok = c.keys[kid]
		c.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("kid %q not found in JWKS after refresh", kid)
		}
	}
	return key, nil
}

// refresh fetches the JWKS endpoint and atomically replaces the key cache.
func (c *JWKSCache) refresh() error {
	resp, err := http.Get(c.jwksURL) //nolint:noctx
	if err != nil {
		return fmt.Errorf("GET %s: %w", c.jwksURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: unexpected HTTP %d", c.jwksURL, resp.StatusCode)
	}

	var jwks jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("decode JWKS: %w", err)
	}

	newKeys := make(map[string]crypto.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty == "RSA" {
			pub, err := parseRSAPublicKey(k)
			if err != nil {
				log.Printf("[JWKS] Skipping RSA key kid=%q: %v", k.Kid, err)
				continue
			}
			newKeys[k.Kid] = pub
		} else if k.Kty == "EC" && k.Crv == "P-256" {
			pub, err := parseECPublicKey(k)
			if err != nil {
				log.Printf("[JWKS] Skipping EC key kid=%q: %v", k.Kid, err)
				continue
			}
			newKeys[k.Kid] = pub
		} else {
			continue // Skip unsupported key types/curves
		}
	}

	if len(newKeys) == 0 {
		return fmt.Errorf("JWKS response contained no supported RSA or EC keys")
	}

	c.mu.Lock()
	c.keys = newKeys
	c.mu.Unlock()

	log.Printf("[JWKS] Loaded %d key(s) from %s", len(newKeys), c.jwksURL)
	return nil
}

// parseECPublicKey converts a JSON Web Key into a Go *ecdsa.PublicKey
// using only the standard library.
func parseECPublicKey(k jwk) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decode X: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decode Y: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// parseRSAPublicKey converts a JSON Web Key into a Go *rsa.PublicKey
// using only the standard library (no external JWT packages).
func parseRSAPublicKey(k jwk) (*rsa.PublicKey, error) {
	// Decode the base64url-encoded modulus (N)
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode N: %w", err)
	}

	// Decode the base64url-encoded exponent (E)
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode E: %w", err)
	}

	// Convert E bytes to int
	var eInt int
	for _, b := range eBytes {
		eInt = eInt<<8 | int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}, nil
}
