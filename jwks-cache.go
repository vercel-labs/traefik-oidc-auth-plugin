package traefik_auth_plugin

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

const (
	// Minimum interval for refreshing the JWKS
	minRefreshInterval = 10 * time.Minute
	// Timeout for network requests
	requestTimeout = 10 * time.Second
	// User agent for network requests
	userAgent = "traefik-vercel-auth/1"
)

var ErrRefreshTooSoon = errors.New("last refresh was too soon")

type JWKSCache struct {
	log      *slog.Logger
	client   *http.Client
	endpoint string

	cache       map[string]*rsa.PublicKey
	mu          sync.RWMutex
	lastRefresh time.Time
	refreshMu   sync.Mutex
	refreshing  bool
	refreshCh   chan struct{}
}

func (c *JWKSCache) GetPublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("kid is empty")
	}

	// Check if we have a cached value
	c.mu.RLock()
	pk, ok := c.cache[kid]
	c.mu.RUnlock()
	if ok && pk != nil {
		return pk, nil
	}

	// Try refreshing - ensure only one refresh is in flight
	err := c.Refresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh JWKS: %w", err)
	}

	// Check cache again after refresh
	c.mu.RLock()
	pk, ok = c.cache[kid]
	c.mu.RUnlock()
	if ok && pk != nil {
		return pk, nil
	}

	return nil, fmt.Errorf("key with kid %s not found after refresh", kid)
}

// Refresh the cached data, ensuring only one operation is in flight at a time
// Multiple callers will wait for the same Refresh to complete
func (c *JWKSCache) Refresh(ctx context.Context) error {
	c.refreshMu.Lock()

	// If a refresh is already in progress, wait for it
	if c.refreshing {
		refreshCh := c.refreshCh
		c.refreshMu.Unlock()

		// Wait for the in-flight refresh to complete or context to be cancelled
		select {
		case <-refreshCh:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// Start a new refresh
	c.refreshing = true
	c.refreshCh = make(chan struct{})
	refreshCh := c.refreshCh
	c.refreshMu.Unlock()

	// Perform the actual refresh
	err := c.doRefresh(ctx)

	// Mark refresh as complete and notify all waiters
	c.refreshMu.Lock()
	c.refreshing = false
	close(refreshCh)
	c.refreshMu.Unlock()

	return err
}

func (c *JWKSCache) doRefresh(ctx context.Context) error {
	// If the last refresh's too recent, return
	c.refreshMu.Lock()
	lastRefresh := c.lastRefresh
	c.refreshMu.Unlock()
	if !lastRefresh.IsZero() && time.Since(lastRefresh) < minRefreshInterval {
		return ErrRefreshTooSoon
	}

	// Fetch the latest keys
	keys, err := c.fetchJWKS(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve JWKS: %w", err)
	}

	// Update cache with write lock
	c.mu.Lock()
	c.cache = keys
	c.mu.Unlock()

	c.refreshMu.Lock()
	c.lastRefresh = time.Now()
	c.refreshMu.Unlock()

	c.log.Info("Updated cached JWKS")
	return nil
}

// fetchJWKS fetches the JWKS from the configured endpoint
func (c *JWKSCache) fetchJWKS(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, c.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for JWKS: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)

	res, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", res.StatusCode)
	}

	var jwks JWKS
	err = json.NewDecoder(res.Body).Decode(&jwks)
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kid == "" {
			c.log.Warn("Skipping key without kid")
			continue
		}
		if k.Kty != "RSA" {
			c.log.Warn("Skipping key with kty not 'RSA'", slog.String("kid", k.Kid), slog.String("kty", k.Kty))
			continue
		}
		if k.Alg != "RS256" {
			c.log.Warn("Skipping key with alg not 'RS256'", slog.String("kid", k.Kid), slog.String("alg", k.Alg))
			continue
		}
		if k.Use != "sig" {
			c.log.Warn("Skipping key with use not 'sig'", slog.String("kid", k.Kid), slog.String("use", k.Use))
			continue
		}

		pk, err := k.ToRSAPublicKey()
		if err != nil {
			c.log.Warn("Error parsing public key: skipping it", slog.String("kid", k.Kid), slog.Any("error", err))
			continue
		}

		keys[k.Kid] = pk
	}

	return keys, nil
}
