// Package jwks fetches and caches JSON Web Key Sets (JWKS) so that
// RSA-signed ID tokens (from Google, Apple, etc.) can be verified without
// hardcoding their signing keys, which rotate periodically.
package jwks

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// Cache fetches a provider's JWKS endpoint and caches the parsed RSA public
// keys in memory, refreshing them after ttl has elapsed.
type Cache struct {
	url        string
	ttl        time.Duration
	httpClient *http.Client

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time
}

// NewCache creates a JWKS cache for the given endpoint URL (e.g.
// "https://www.googleapis.com/oauth2/v3/certs" or
// "https://appleid.apple.com/auth/keys").
func NewCache(url string, ttl time.Duration) *Cache {
	return &Cache{
		url:        url,
		ttl:        ttl,
		keys:       make(map[string]*rsa.PublicKey),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// GetKey returns the RSA public key for the given key id (kid), refreshing
// the cache from the network if the key is unknown or the cache is stale.
func (c *Cache) GetKey(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	key, ok := c.keys[kid]
	fresh := time.Since(c.lastFetch) < c.ttl
	c.mu.RUnlock()

	if ok && fresh {
		return key, nil
	}

	if err := c.refresh(); err != nil {
		// If we already had a (possibly stale) key for this kid, prefer
		// using it over failing outright on a transient network error.
		if ok {
			return key, nil
		}
		return nil, err
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok = c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("jwks: key id %q not found at %s", kid, c.url)
	}
	return key, nil
}

func (c *Cache) refresh() error {
	resp, err := c.httpClient.Get(c.url)
	if err != nil {
		return fmt.Errorf("jwks: fetch %s: %w", c.url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: unexpected status %d from %s", resp.StatusCode, c.url)
	}

	var set jwkSet
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("jwks: decode %s: %w", c.url, err)
	}

	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := jwkToRSAPublicKey(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}

	c.mu.Lock()
	c.keys = keys
	c.lastFetch = time.Now()
	c.mu.Unlock()

	return nil
}

func jwkToRSAPublicKey(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}
