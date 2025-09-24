package traefik_auth_plugin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var (
	testRSAKey *rsa.PrivateKey
	testJWK    JWK
)

func init() {
	// Generate a test RSA key once for all tests
	var err error
	testRSAKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate test RSA key: %v", err))
	}

	// Encode modulus as base64url
	nBytes := testRSAKey.PublicKey.N.Bytes()
	n := base64.RawURLEncoding.EncodeToString(nBytes)

	// Encode exponent as base64url
	eBytes := big.NewInt(int64(testRSAKey.PublicKey.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	testJWK = JWK{
		Kid: "test-kid",
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		N:   n,
		E:   e,
	}
}

func TestJWKSCache_GetPublicKey_CacheHit(t *testing.T) {
	// Mock JWKS response
	jwks := JWKS{
		Keys: []JWK{testJWK},
	}

	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	cache := &JWKSCache{
		log:      slog.Default(),
		client:   server.Client(),
		endpoint: server.URL,
		cache:    make(map[string]*rsa.PublicKey),
	}

	// First call should trigger a refresh
	pk1, err := cache.GetPublicKey(t.Context(), "test-kid")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if pk1 == nil {
		t.Fatal("Expected public key, got nil")
	}
	if calls.Load() != 1 {
		t.Fatalf("Expected server to be called once, but got %d calls", calls.Load())
	}

	// Second call should use cache (no HTTP request)
	pk2, err := cache.GetPublicKey(t.Context(), "test-kid")
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if pk2 == nil {
		t.Fatal("Expected public key, got nil")
	}
	if calls.Load() != 1 {
		t.Fatalf("Expected server to be called once, but got %d calls", calls.Load())
	}

	// Should be the same key
	if pk1.N.Cmp(pk2.N) != 0 || pk1.E != pk2.E {
		t.Error("Expected same public key from cache")
	}
}

func TestJWKSCache_GetPublicKey_KeyNotFound(t *testing.T) {
	// Mock JWKS response with different kid
	differentJWK := testJWK
	differentJWK.Kid = "different-kid"
	jwks := JWKS{
		Keys: []JWK{differentJWK},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	cache := &JWKSCache{
		log:      slog.Default(),
		client:   server.Client(),
		endpoint: server.URL,
		cache:    make(map[string]*rsa.PublicKey),
	}

	// Should trigger refresh but not find the requested key
	pk, err := cache.GetPublicKey(t.Context(), "test-kid")
	if err == nil {
		t.Fatal("Expected error for key not found")
	}
	if pk != nil {
		t.Error("Expected nil public key")
	}
}

func TestJWKSCache_GetPublicKey_EmptyKid(t *testing.T) {
	cache := &JWKSCache{
		log:      slog.Default(),
		client:   &http.Client{},
		endpoint: "http://example.com",
		cache:    make(map[string]*rsa.PublicKey),
	}

	_, err := cache.GetPublicKey(t.Context(), "")
	if err == nil {
		t.Fatal("Expected error for empty kid")
	}
}

func TestJWKSCache_GetPublicKey_ContextCancellation(t *testing.T) {
	// Mock server with delay
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(JWKS{Keys: []JWK{}})
	}))
	defer server.Close()

	cache := &JWKSCache{
		log:      slog.Default(),
		client:   server.Client(),
		endpoint: server.URL,
		cache:    make(map[string]*rsa.PublicKey),
	}

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	_, err := cache.GetPublicKey(ctx, "test-kid")
	if err == nil {
		t.Fatal("Expected error due to context cancellation")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Unexpected error: %v", err)
	}
}

func TestJWKSCache_SingleInFlightRefresh(t *testing.T) {

	// Mock JWKS response
	jwks := JWKS{
		Keys: []JWK{testJWK},
	}

	requestCount := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)

		// Add delay to simulate network latency
		time.Sleep(50 * time.Millisecond)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	cache := &JWKSCache{
		log:      slog.Default(),
		client:   server.Client(),
		endpoint: server.URL,
		cache:    make(map[string]*rsa.PublicKey),
	}

	const numGoroutines = 10

	// Start multiple concurrent requests for the same key
	var wg sync.WaitGroup
	results := make([]*rsa.PublicKey, numGoroutines)
	errors := make([]error, numGoroutines)

	for i := range numGoroutines {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			pk, err := cache.GetPublicKey(t.Context(), "test-kid")
			results[index] = pk
			errors[index] = err
		}(i)
	}

	wg.Wait()

	// Verify all requests succeeded
	for i, err := range errors {
		if err != nil {
			t.Errorf("Goroutine %d got error: %v", i, err)
		}
	}

	// Verify all got the same key
	for i, pk := range results {
		if pk == nil {
			t.Errorf("Goroutine %d got nil key", i)
			continue
		}
		if i > 0 && (pk.N.Cmp(results[0].N) != 0 || pk.E != results[0].E) {
			t.Errorf("Goroutine %d got different key", i)
		}
	}

	// Verify only ONE HTTP request was made
	if requestCount.Load() != 1 {
		t.Errorf("Expected exactly 1 HTTP request, got: %d", requestCount.Load())
	}
}

func TestJWKSCache_RefreshTooSoon(t *testing.T) {
	jwks := JWKS{
		Keys: []JWK{testJWK},
	}

	requestCount := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	cache := &JWKSCache{
		log:      slog.Default(),
		client:   server.Client(),
		endpoint: server.URL,
		cache:    make(map[string]*rsa.PublicKey),
	}

	// First request should trigger refresh
	pk1, err := cache.GetPublicKey(t.Context(), "test-kid")
	if err != nil {
		t.Fatalf("First request failed: %v", err)
	}
	if pk1 == nil {
		t.Fatal("Expected public key")
	}

	// Clear cache to force refresh attempt
	cache.mu.Lock()
	cache.cache = make(map[string]*rsa.PublicKey)
	cache.mu.Unlock()

	// Second request immediately after should not trigger refresh (too soon)
	pk2, err := cache.GetPublicKey(t.Context(), "test-kid")
	if err == nil {
		t.Error("Expected error due to refresh too soon")
	}
	if pk2 != nil {
		t.Error("Expected nil key")
	}

	// Should still be only 1 request
	if requestCount.Load() != 1 {
		t.Errorf("Expected exactly 1 HTTP request, got: %d", requestCount.Load())
	}
}

func TestJWKSCache_ConcurrentRefreshWithCancellation(t *testing.T) {
	jwks := JWKS{
		Keys: []JWK{testJWK},
	}

	requestCount := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)

		// Simulate slow response
		time.Sleep(500 * time.Millisecond)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}))
	defer server.Close()

	cache := &JWKSCache{
		log:      slog.Default(),
		client:   server.Client(),
		endpoint: server.URL,
		cache:    make(map[string]*rsa.PublicKey),
	}

	const numGoroutines = 5
	var wg sync.WaitGroup
	results := make([]*rsa.PublicKey, numGoroutines)
	errors := make([]error, numGoroutines)

	// Start multiple concurrent requests, some with cancellation
	for i := range numGoroutines {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()

			var ctx context.Context
			var cancel context.CancelFunc

			if index < 2 {
				// First two goroutines get cancelled
				ctx, cancel = context.WithTimeout(t.Context(), 500*time.Millisecond)
				defer cancel()
			} else {
				// Rest wait for completion
				ctx = t.Context()
			}

			pk, err := cache.GetPublicKey(ctx, "test-kid")
			results[index] = pk
			errors[index] = err
		}(i)
	}

	wg.Wait()

	// First two should have context-related errors
	for i := range 2 {
		if errors[i] == nil {
			t.Errorf("Goroutine %d should have an error due to context cancellation", i)
		}
		if results[i] != nil {
			t.Errorf("Goroutine %d should have nil result", i)
		}
	}

	// Rest should succeed
	for i := 2; i < numGoroutines; i++ {
		if errors[i] != nil {
			t.Errorf("Goroutine %d should succeed, got error: %v", i, errors[i])
		}
		if results[i] == nil {
			t.Errorf("Goroutine %d should have non-nil result", i)
		}
	}

	// Should still be only 1 HTTP request
	if requestCount.Load() != 1 {
		t.Errorf("Expected exactly 1 HTTP request, got: %d", requestCount.Load())
	}
}

func TestJWKSCache_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	cache := &JWKSCache{
		log:      slog.Default(),
		client:   server.Client(),
		endpoint: server.URL,
		cache:    make(map[string]*rsa.PublicKey),
	}

	_, err := cache.GetPublicKey(t.Context(), "test-kid")
	if err == nil {
		t.Fatal("Expected error for HTTP 500")
	}
}

func TestJWKSCache_InvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "invalid json")
	}))
	defer server.Close()

	cache := &JWKSCache{
		log:      slog.Default(),
		client:   server.Client(),
		endpoint: server.URL,
		cache:    make(map[string]*rsa.PublicKey),
	}

	_, err := cache.GetPublicKey(t.Context(), "test-kid")
	if err == nil {
		t.Fatal("Expected error for invalid JSON")
	}
}
