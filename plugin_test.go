package traefik_oidc_auth_plugin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// mockJWKSCache implements JWKSCache interface for testing
type mockJWKSCache struct {
	keys           map[string]*rsa.PublicKey
	refreshed      bool
	errorOnGet     error
	errorOnRefresh error
	getCalls       atomic.Int32
}

func newMockJWKSCache() *mockJWKSCache {
	return &mockJWKSCache{
		keys: make(map[string]*rsa.PublicKey),
	}
}

func (m *mockJWKSCache) GetPublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	m.getCalls.Add(1)

	if m.errorOnGet != nil {
		return nil, m.errorOnGet
	}

	key, exists := m.keys[kid]
	if !exists {
		return nil, fmt.Errorf("key with kid %s not found", kid)
	}
	return key, nil
}

func (m *mockJWKSCache) Refresh(ctx context.Context) error {
	if m.errorOnRefresh != nil {
		return m.errorOnRefresh
	}
	m.refreshed = true
	return nil
}

func (m *mockJWKSCache) AddKey(kid string, publicKey *rsa.PublicKey) {
	m.keys[kid] = publicKey
}

func (m *mockJWKSCache) GetCalls() int32 {
	return m.getCalls.Load()
}

// testKeyPair holds RSA key pair for testing
type testKeyPair struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	kid        string
}

// generateTestKeyPair generates an RSA key pair for testing
func generateTestKeyPair(kid string) (*testKeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &testKeyPair{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		kid:        kid,
	}, nil
}

// generateToken creates a JWT token with the given claims
func (kp *testKeyPair) generateToken(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kp.kid
	return token.SignedString(kp.privateKey)
}

// mockNextHandler is a simple HTTP handler for testing
type mockNextHandler struct {
	called    atomic.Bool
	callCount atomic.Int32
}

func (m *mockNextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.called.Store(true)
	m.callCount.Add(1)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("success"))
}

func TestVercelAuth_ServeHTTP(t *testing.T) {
	// Setup test key pair
	keyPair, err := generateTestKeyPair("test-kid")
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	// Setup mock dependencies
	mockJWKS := newMockJWKSCache()
	mockJWKS.AddKey(keyPair.kid, keyPair.publicKey)

	config := &Config{
		Issuer:      "https://oidc.vercel.com/test-team",
		TeamSlug:    "test-team",
		ProjectName: "test-project",
		Environment: "production",
		TokenHeader: "Authorization",
	}

	t.Run("Valid token", func(t *testing.T) {
		nextHandler := &mockNextHandler{}

		plugin := &VercelAuth{
			next:       nextHandler,
			name:       "test-plugin",
			log:        slog.New(slog.DiscardHandler),
			config:     config,
			jwks:       mockJWKS,
			tokenCache: make(map[string]tokenValidationCacheEntry),
		}

		// Create valid token
		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{config.TokenAudience()},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		}

		tokenString, err := keyPair.generateToken(claims)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Create request with valid token
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		w := httptest.NewRecorder()

		// Execute
		plugin.ServeHTTP(w, req)

		// Assert
		if !nextHandler.called.Load() {
			t.Error("Next handler was not called")
		}

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}

		body := w.Body.String()
		if body != "success" {
			t.Errorf("Expected body 'success', got %q", body)
		}
	})

	t.Run("Missing token", func(t *testing.T) {
		nextHandler := &mockNextHandler{}

		plugin := &VercelAuth{
			next:       nextHandler,
			name:       "test-plugin",
			log:        slog.New(slog.DiscardHandler),
			config:     config,
			jwks:       mockJWKS,
			tokenCache: make(map[string]tokenValidationCacheEntry),
		}

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		plugin.ServeHTTP(w, req)

		if nextHandler.called.Load() {
			t.Error("Next handler should not have been called")
		}

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}

		body := w.Body.String()
		if body != "Missing token" {
			t.Errorf("Expected body 'Missing token', got %q", body)
		}
	})

	t.Run("Invalid token", func(t *testing.T) {
		nextHandler := &mockNextHandler{}

		plugin := &VercelAuth{
			next:       nextHandler,
			name:       "test-plugin",
			log:        slog.New(slog.DiscardHandler),
			config:     config,
			jwks:       mockJWKS,
			tokenCache: make(map[string]tokenValidationCacheEntry),
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")
		w := httptest.NewRecorder()

		plugin.ServeHTTP(w, req)

		if nextHandler.called.Load() {
			t.Error("Next handler should not have been called")
		}

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", w.Code)
		}

		body := w.Body.String()
		if body != "Invalid token" {
			t.Errorf("Expected body 'Invalid token', got %q", body)
		}
	})

	t.Run("With clock skew", func(t *testing.T) {
		nextHandler := &mockNextHandler{}

		plugin := &VercelAuth{
			next:       nextHandler,
			name:       "test-plugin",
			log:        slog.New(slog.DiscardHandler),
			config:     config,
			jwks:       mockJWKS,
			tokenCache: make(map[string]tokenValidationCacheEntry),
		}

		// Create token that's slightly in the future (within clock skew tolerance)
		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{config.TokenAudience()},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now.Add(2 * time.Minute)), // 2 minutes in future
		}

		tokenString, err := keyPair.generateToken(claims)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+tokenString)

		w := httptest.NewRecorder()
		plugin.ServeHTTP(w, req)

		// Should succeed due to clock skew tolerance
		if !nextHandler.called.Load() {
			t.Error("Next handler was not called")
		}

		if w.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d", w.Code)
		}
	})

	t.Run("Concurrent requests", func(t *testing.T) {
		nextHandler := &mockNextHandler{}

		plugin := &VercelAuth{
			name:       "test-plugin",
			log:        slog.New(slog.DiscardHandler),
			config:     config,
			jwks:       mockJWKS,
			next:       nextHandler,
			tokenCache: make(map[string]tokenValidationCacheEntry),
		}

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{config.TokenAudience()},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		}

		tokenString, err := keyPair.generateToken(claims)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		// Test multiple concurrent requests
		const numGoroutines = 5
		var wg sync.WaitGroup
		statusCodes := make([]int, numGoroutines)
		for i := range numGoroutines {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("Authorization", "Bearer "+tokenString)

				w := httptest.NewRecorder()
				plugin.ServeHTTP(w, req)

				statusCodes[i] = w.Code
			}(i)
		}
		wg.Wait()

		// Handler should have been called multiple times
		if nextHandler.callCount.Load() != numGoroutines {
			t.Errorf("Expected handler to be called %d times, but was called %d", numGoroutines, nextHandler.callCount.Load())
		}

		// Ensure all requests ended with status 200
		for i, code := range statusCodes {
			if code != http.StatusOK {
				t.Errorf("Request %d failed with code %d", i, code)
			}
		}
	})

}

func TestVercelAuth_validateToken_ExpiredToken(t *testing.T) {
	keyPair, err := generateTestKeyPair("test-kid")
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	mockJWKS := newMockJWKSCache()
	mockJWKS.AddKey(keyPair.kid, keyPair.publicKey)

	config := &Config{
		Issuer:      "https://oidc.vercel.com/test-team",
		TeamSlug:    "test-team",
		ProjectName: "test-project",
		Environment: "production",
	}

	t.Run("Expired token", func(t *testing.T) {
		plugin := &VercelAuth{
			config:     config,
			jwks:       mockJWKS,
			tokenCache: make(map[string]tokenValidationCacheEntry),
		}

		// Create expired token
		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{config.TokenAudience()},
			ExpiresAt: jwt.NewNumericDate(now.Add(-time.Hour)), // Expired 1 hour ago
			IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
		}

		tokenString, err := keyPair.generateToken(claims)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		err = plugin.validateToken(t.Context(), tokenString)
		if err == nil {
			t.Error("Expected error for expired token, got nil")
		}

		if !strings.Contains(err.Error(), "expired") {
			t.Errorf("Expected error to contain 'expired', got: %v", err)
		}
	})

	t.Run("Wrong issuer", func(t *testing.T) {
		plugin := &VercelAuth{
			config:     config,
			jwks:       mockJWKS,
			tokenCache: make(map[string]tokenValidationCacheEntry),
		}

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    "https://wrong-issuer.com", // Wrong issuer
			Subject:   config.Subject(),
			Audience:  []string{config.TokenAudience()},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		}

		tokenString, err := keyPair.generateToken(claims)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		err = plugin.validateToken(t.Context(), tokenString)
		if err == nil {
			t.Error("Expected error for wrong issuer, got nil")
		}
	})

	t.Run("Wrong audience", func(t *testing.T) {
		plugin := &VercelAuth{
			config:     config,
			jwks:       mockJWKS,
			tokenCache: make(map[string]tokenValidationCacheEntry),
		}

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{"https://wrong-audience.com"}, // Wrong audience
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		}

		tokenString, err := keyPair.generateToken(claims)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		err = plugin.validateToken(t.Context(), tokenString)
		if err == nil {
			t.Error("Expected error for wrong audience, got nil")
		}
	})

	t.Run("Custom audience", func(t *testing.T) {
		customConfig := &Config{
			Issuer:      config.Issuer,
			TeamSlug:    config.TeamSlug,
			ProjectName: config.ProjectName,
			Environment: config.Environment,
			TokenHeader: config.TokenHeader,
			Audience:    "sts.amazonaws.com",
		}

		plugin := &VercelAuth{
			config:     customConfig,
			jwks:       mockJWKS,
			tokenCache: make(map[string]tokenValidationCacheEntry),
		}

		now := time.Now()

		// A token carrying the custom audience is accepted
		validClaims := jwt.RegisteredClaims{
			Issuer:    customConfig.Issuer,
			Subject:   customConfig.Subject(),
			Audience:  []string{customConfig.TokenAudience()},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		}
		validToken, err := keyPair.generateToken(validClaims)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}
		if err = plugin.validateToken(t.Context(), validToken); err != nil {
			t.Errorf("Expected custom audience token to be valid, got: %v", err)
		}

		// A token carrying the default audience is rejected
		defaultClaims := jwt.RegisteredClaims{
			Issuer:    customConfig.Issuer,
			Subject:   customConfig.Subject(),
			Audience:  []string{"https://vercel.com/" + customConfig.TeamSlug},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		}
		defaultToken, err := keyPair.generateToken(defaultClaims)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}
		if err = plugin.validateToken(t.Context(), defaultToken); err == nil {
			t.Error("Expected default audience token to be rejected when a custom audience is configured, got nil")
		}
	})

	t.Run("Wrong subject", func(t *testing.T) {
		plugin := &VercelAuth{
			config:     config,
			jwks:       mockJWKS,
			tokenCache: make(map[string]tokenValidationCacheEntry),
		}

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   "wrong-subject", // Wrong subject
			Audience:  []string{config.TokenAudience()},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		}

		tokenString, err := keyPair.generateToken(claims)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		err = plugin.validateToken(t.Context(), tokenString)
		if err == nil {
			t.Error("Expected error for wrong subject, got nil")
		}
	})

	t.Run("Missing key id", func(t *testing.T) {
		plugin := &VercelAuth{
			config:     config,
			jwks:       mockJWKS,
			tokenCache: make(map[string]tokenValidationCacheEntry),
		}

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{config.TokenAudience()},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		// Don't set kid in header
		tokenString, err := token.SignedString(keyPair.privateKey)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		err = plugin.validateToken(t.Context(), tokenString)
		if err == nil {
			t.Error("Expected error for missing kid, got nil")
		}

		if !strings.Contains(err.Error(), "missing kid") {
			t.Errorf("Expected error to contain 'missing kid', got: %v", err)
		}
	})

	t.Run("Key not found", func(t *testing.T) {
		plugin := &VercelAuth{
			config:     config,
			tokenCache: make(map[string]tokenValidationCacheEntry),
			// Use a new mock JWKSCache without the key
			jwks: newMockJWKSCache(),
		}

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{config.TokenAudience()},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		}

		tokenString, err := keyPair.generateToken(claims)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		err = plugin.validateToken(t.Context(), tokenString)
		if err == nil {
			t.Error("Expected error for key not found, got nil")
		}

		if !strings.Contains(err.Error(), "not found") {
			t.Errorf("Expected error to contain 'not found', got: %v", err)
		}
	})

	t.Run("JWKSCache error", func(t *testing.T) {
		// Init a new mock JWKSCache that returns an error
		mockJWKS := newMockJWKSCache()
		mockJWKS.errorOnGet = errors.New("JWKS cache error")

		plugin := &VercelAuth{
			config:     config,
			jwks:       mockJWKS,
			tokenCache: make(map[string]tokenValidationCacheEntry),
		}

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{config.TokenAudience()},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		}

		tokenString, err := keyPair.generateToken(claims)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		err = plugin.validateToken(t.Context(), tokenString)
		if err == nil {
			t.Error("Expected error from JWKS cache, got nil")
		}

		if !strings.Contains(err.Error(), "failed to get public key") {
			t.Errorf("Expected error to contain 'failed to get public key', got: %v", err)
		}
	})
}

func TestPatternMatches(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		{
			name:    "exact match",
			pattern: "test-project",
			value:   "test-project",
			want:    true,
		},
		{
			name:    "exact mismatch",
			pattern: "test-project",
			value:   "other-project",
			want:    false,
		},
		{
			name:    "full wildcard",
			pattern: "*",
			value:   "any-project",
			want:    true,
		},
		{
			name:    "prefix match",
			pattern: "test-*",
			value:   "test-project",
			want:    true,
		},
		{
			name:    "prefix mismatch",
			pattern: "test-*",
			value:   "prod-project",
			want:    false,
		},
		{
			name:    "alternative first match",
			pattern: "foo|bar",
			value:   "foo",
			want:    true,
		},
		{
			name:    "alternative second match",
			pattern: "foo|bar",
			value:   "bar",
			want:    true,
		},
		{
			name:    "alternative mismatch",
			pattern: "foo|bar",
			value:   "baz",
			want:    false,
		},
		{
			name:    "alternative prefix match",
			pattern: "fo*|ba*",
			value:   "basket",
			want:    true,
		},
		{
			name:    "alternative prefix mismatch",
			pattern: "fo*|ba*",
			value:   "qux",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := patternMatches(tt.pattern, tt.value)
			if got != tt.want {
				t.Fatalf("patternMatches(%q, %q) = %v, want %v", tt.pattern, tt.value, got, tt.want)
			}
		})
	}
}

func TestConfig_Audience(t *testing.T) {
	t.Run("default audience", func(t *testing.T) {
		config := Config{TeamSlug: "test-team"}

		if got := config.TokenAudience(); got != "https://vercel.com/test-team" {
			t.Errorf("Expected default audience, got %q", got)
		}
		if config.HasCustomAudience() {
			t.Error("Expected HasCustomAudience to be false")
		}
	})

	t.Run("custom audience", func(t *testing.T) {
		config := Config{TeamSlug: "test-team", Audience: "sts.amazonaws.com"}

		if got := config.TokenAudience(); got != "sts.amazonaws.com" {
			t.Errorf("Expected custom audience, got %q", got)
		}
		if !config.HasCustomAudience() {
			t.Error("Expected HasCustomAudience to be true")
		}
	})
}

func TestConfig_Validate_Issuer(t *testing.T) {
	newConfig := func(issuer string) *Config {
		return &Config{
			Issuer:      issuer,
			TeamSlug:    "test-team",
			ProjectName: "test-project",
			Environment: "production",
		}
	}

	tests := []struct {
		name       string
		issuer     string
		wantIssuer string
	}{
		{"unset defaults to team issuer", "", "https://oidc.vercel.com/test-team"},
		{"global alias", "global", "https://oidc.vercel.com"},
		{"team alias", "team", "https://oidc.vercel.com/test-team"},
		{"explicit issuer", "https://oidc.vercel.com/other", "https://oidc.vercel.com/other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := newConfig(tt.issuer)
			if err := config.Validate(); err != nil {
				t.Fatalf("Validate() returned error: %v", err)
			}
			if config.Issuer != tt.wantIssuer {
				t.Errorf("Expected issuer %q, got %q", tt.wantIssuer, config.Issuer)
			}
			wantJWKS := tt.wantIssuer + "/.well-known/jwks"
			if config.JWKSEndpoint != wantJWKS {
				t.Errorf("Expected JWKS endpoint %q, got %q", wantJWKS, config.JWKSEndpoint)
			}
		})
	}
}

func TestConfig_subjectMatches(t *testing.T) {
	subject := func(teamSlug, projectName, environment string) string {
		return fmt.Sprintf("owner:%s:project:%s:environment:%s", teamSlug, projectName, environment)
	}

	config := Config{
		TeamSlug:    "test-team",
		ProjectName: "web*|api",
		Environment: "prod*|preview",
	}

	tests := []struct {
		name    string
		subject string
		want    bool
	}{
		{
			name:    "project prefix and environment prefix match",
			subject: subject("test-team", "web-dashboard", "production"),
			want:    true,
		},
		{
			name:    "project alternative and environment exact match",
			subject: subject("test-team", "api", "preview"),
			want:    true,
		},
		{
			name:    "team slug stays exact",
			subject: subject("test-team-preview", "web-dashboard", "production"),
			want:    false,
		},
		{
			name:    "project mismatch",
			subject: subject("test-team", "admin", "production"),
			want:    false,
		},
		{
			name:    "environment mismatch",
			subject: subject("test-team", "web-dashboard", "development"),
			want:    false,
		},
		{
			name:    "malformed subject",
			subject: "wrong-subject",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := config.subjectMatches(tt.subject)
			if got != tt.want {
				t.Fatalf("subjectMatches(%q) = %v, want %v", tt.subject, got, tt.want)
			}
		})
	}
}

func TestVercelAuth_validateToken_SubjectPatterns(t *testing.T) {
	keyPair, err := generateTestKeyPair("test-kid")
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	mockJWKS := newMockJWKSCache()
	mockJWKS.AddKey(keyPair.kid, keyPair.publicKey)

	subject := func(teamSlug, projectName, environment string) string {
		return fmt.Sprintf("owner:%s:project:%s:environment:%s", teamSlug, projectName, environment)
	}

	tests := []struct {
		name          string
		projectName   string
		environment   string
		tokenProject  string
		tokenEnv      string
		shouldSucceed bool
	}{
		{
			name:          "full environment wildcard",
			projectName:   "test-*",
			environment:   "*",
			tokenProject:  "test-project",
			tokenEnv:      "staging",
			shouldSucceed: true,
		},
		{
			name:          "exact alternatives",
			projectName:   "foo|bar",
			environment:   "production|preview",
			tokenProject:  "bar",
			tokenEnv:      "preview",
			shouldSucceed: true,
		},
		{
			name:          "prefix alternatives",
			projectName:   "fo*|ba*",
			environment:   "prod*",
			tokenProject:  "basket",
			tokenEnv:      "production",
			shouldSucceed: true,
		},
		{
			name:          "project pattern mismatch",
			projectName:   "fo*|ba*",
			environment:   "prod*",
			tokenProject:  "qux",
			tokenEnv:      "production",
			shouldSucceed: false,
		},
		{
			name:          "environment pattern mismatch",
			projectName:   "*",
			environment:   "prod*",
			tokenProject:  "any-project",
			tokenEnv:      "development",
			shouldSucceed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Issuer:      "https://oidc.vercel.com/test-team",
				TeamSlug:    "test-team",
				ProjectName: tt.projectName,
				Environment: tt.environment,
			}

			plugin := &VercelAuth{
				config:     config,
				jwks:       mockJWKS,
				tokenCache: make(map[string]tokenValidationCacheEntry),
			}

			now := time.Now()
			claims := jwt.RegisteredClaims{
				Issuer:    config.Issuer,
				Subject:   subject(config.TeamSlug, tt.tokenProject, tt.tokenEnv),
				Audience:  []string{config.TokenAudience()},
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now),
			}

			tokenString, err := keyPair.generateToken(claims)
			if err != nil {
				t.Fatalf("Failed to generate token: %v", err)
			}

			err = plugin.validateToken(t.Context(), tokenString)
			if tt.shouldSucceed && err != nil {
				t.Fatalf("Expected validation to succeed, got error: %v", err)
			}
			if !tt.shouldSucceed && err == nil {
				t.Fatal("Expected validation to fail, got nil")
			}
		})
	}
}

func TestVercelAuth_validateToken_Cache(t *testing.T) {
	keyPair, err := generateTestKeyPair("test-kid")
	if err != nil {
		t.Fatalf("Failed to generate test key pair: %v", err)
	}

	config := &Config{
		Issuer:      "https://oidc.vercel.com/test-team",
		TeamSlug:    "test-team",
		ProjectName: "test-project",
		Environment: "production",
	}

	newToken := func(ttl time.Duration) string {
		t.Helper()

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{config.TokenAudience()},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
		}

		tokenString, err := keyPair.generateToken(claims)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		return tokenString
	}

	t.Run("cache hit skips revalidation", func(t *testing.T) {
		mockJWKS := newMockJWKSCache()
		mockJWKS.AddKey(keyPair.kid, keyPair.publicKey)

		plugin := &VercelAuth{
			config:     config,
			jwks:       mockJWKS,
			tokenCache: make(map[string]tokenValidationCacheEntry),
		}

		tokenString := newToken(time.Hour)

		err := plugin.validateToken(t.Context(), tokenString)
		if err != nil {
			t.Fatalf("Expected first validation to succeed, got error: %v", err)
		}

		if mockJWKS.GetCalls() != 1 {
			t.Fatalf("Expected 1 JWKS key lookup after first validation, got %d", mockJWKS.GetCalls())
		}

		mockJWKS.errorOnGet = errors.New("JWKS cache error")

		err = plugin.validateToken(t.Context(), tokenString)
		if err != nil {
			t.Fatalf("Expected cached validation to succeed, got error: %v", err)
		}

		if mockJWKS.GetCalls() != 1 {
			t.Fatalf("Expected cached validation to avoid JWKS lookup, got %d calls", mockJWKS.GetCalls())
		}
	})

	t.Run("expired cache entry revalidates token", func(t *testing.T) {
		mockJWKS := newMockJWKSCache()
		mockJWKS.AddKey(keyPair.kid, keyPair.publicKey)

		plugin := &VercelAuth{
			config:     config,
			jwks:       mockJWKS,
			tokenCache: make(map[string]tokenValidationCacheEntry),
		}

		tokenString := newToken(time.Hour)

		err := plugin.validateToken(t.Context(), tokenString)
		if err != nil {
			t.Fatalf("Expected first validation to succeed, got error: %v", err)
		}

		tokenHash := validatedTokenCacheKey(tokenString)
		plugin.tokenCacheMu.Lock()
		plugin.tokenCache[tokenHash] = tokenValidationCacheEntry{
			expiresAt: time.Now().Add(-time.Second),
		}
		plugin.tokenCacheMu.Unlock()

		mockJWKS.errorOnGet = errors.New("JWKS cache error")

		err = plugin.validateToken(t.Context(), tokenString)
		if err == nil {
			t.Fatal("Expected validation to fail after cache expiry, got nil")
		}
		if !strings.Contains(err.Error(), "failed to get public key") {
			t.Fatalf("Expected public key fetch error, got: %v", err)
		}
		if mockJWKS.GetCalls() != 2 {
			t.Fatalf("Expected second validation attempt after cache expiry, got %d JWKS calls", mockJWKS.GetCalls())
		}
	})

	t.Run("cache ttl is min(token ttl, 5 minutes)", func(t *testing.T) {
		tests := []struct {
			name     string
			tokenTTL time.Duration
			wantTTL  time.Duration
		}{
			{
				name:     "long-lived token uses 5 minute cap",
				tokenTTL: 30 * time.Minute,
				wantTTL:  maxValidatedTokenCacheTTL,
			},
			{
				name:     "short-lived token uses token ttl",
				tokenTTL: 2 * time.Minute,
				wantTTL:  2 * time.Minute,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				mockJWKS := newMockJWKSCache()
				mockJWKS.AddKey(keyPair.kid, keyPair.publicKey)

				plugin := &VercelAuth{
					config:     config,
					jwks:       mockJWKS,
					tokenCache: make(map[string]tokenValidationCacheEntry),
				}

				tokenString := newToken(tt.tokenTTL)
				before := time.Now()

				err := plugin.validateToken(t.Context(), tokenString)
				if err != nil {
					t.Fatalf("Expected validation to succeed, got error: %v", err)
				}

				after := time.Now()
				tokenHash := validatedTokenCacheKey(tokenString)
				plugin.tokenCacheMu.RLock()
				entry, ok := plugin.tokenCache[tokenHash]
				plugin.tokenCacheMu.RUnlock()

				if !ok {
					t.Fatal("Expected token to be cached after successful validation")
				}

				minExpected := before.Add(tt.wantTTL).Add(-2 * time.Second)
				maxExpected := after.Add(tt.wantTTL).Add(2 * time.Second)
				if entry.expiresAt.Before(minExpected) || entry.expiresAt.After(maxExpected) {
					t.Fatalf("Expected cache expiry around %v from now, got %v", tt.wantTTL, entry.expiresAt)
				}
			})
		}
	})

	t.Run("invalid token is cached for max ttl", func(t *testing.T) {
		mockJWKS := newMockJWKSCache()
		mockJWKS.AddKey(keyPair.kid, keyPair.publicKey)

		plugin := &VercelAuth{
			config:     config,
			jwks:       mockJWKS,
			tokenCache: make(map[string]tokenValidationCacheEntry),
		}

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   "wrong-subject",
			Audience:  []string{config.TokenAudience()},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		}

		tokenString, err := keyPair.generateToken(claims)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		before := time.Now()
		err = plugin.validateToken(t.Context(), tokenString)
		if err == nil {
			t.Fatal("Expected invalid token error, got nil")
		}
		after := time.Now()

		tokenHash := validatedTokenCacheKey(tokenString)
		plugin.tokenCacheMu.RLock()
		entry, ok := plugin.tokenCache[tokenHash]
		plugin.tokenCacheMu.RUnlock()

		if !ok {
			t.Fatal("Expected invalid token to be cached")
		}
		if entry.errMessage == nil {
			t.Fatal("Expected cached invalid token entry to include an error message")
		}

		minExpected := before.Add(maxValidatedTokenCacheTTL).Add(-2 * time.Second)
		maxExpected := after.Add(maxValidatedTokenCacheTTL).Add(2 * time.Second)
		if entry.expiresAt.Before(minExpected) || entry.expiresAt.After(maxExpected) {
			t.Fatalf("Expected invalid token cache expiry around %v from now, got %v", maxValidatedTokenCacheTTL, entry.expiresAt)
		}

		if mockJWKS.GetCalls() != 1 {
			t.Fatalf("Expected 1 JWKS lookup after first invalid validation, got %d", mockJWKS.GetCalls())
		}

		mockJWKS.errorOnGet = errors.New("JWKS cache error")

		err = plugin.validateToken(t.Context(), tokenString)
		if err == nil {
			t.Fatal("Expected cached invalid token error, got nil")
		}

		if mockJWKS.GetCalls() != 1 {
			t.Fatalf("Expected cached invalid token to avoid new JWKS lookup, got %d calls", mockJWKS.GetCalls())
		}
	})
}

func TestVercelAuth_purgeExpiredValidatedTokens(t *testing.T) {
	now := time.Now()
	plugin := &VercelAuth{
		tokenCache: map[string]tokenValidationCacheEntry{
			"expired-a": {expiresAt: now.Add(-2 * time.Minute)},
			"expired-b": {expiresAt: now},
			"fresh":     {expiresAt: now.Add(2 * time.Minute)},
		},
	}

	purged := plugin.purgeExpiredValidatedTokens(now)
	if purged != 2 {
		t.Fatalf("Expected to purge 2 entries, got %d", purged)
	}

	plugin.tokenCacheMu.RLock()
	defer plugin.tokenCacheMu.RUnlock()

	if len(plugin.tokenCache) != 1 {
		t.Fatalf("Expected 1 entry after purge, got %d", len(plugin.tokenCache))
	}
	if _, ok := plugin.tokenCache["fresh"]; !ok {
		t.Fatal("Expected fresh entry to remain in cache")
	}
}

func TestVercelAuth_startTokenCachePurger(t *testing.T) {
	now := time.Now()
	plugin := &VercelAuth{
		tokenCache: map[string]tokenValidationCacheEntry{
			"expired": {expiresAt: now.Add(-time.Minute)},
			"fresh":   {expiresAt: now.Add(time.Minute)},
		},
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	go plugin.startTokenCachePurger(ctx, 10*time.Millisecond)

	deadline := time.Now().Add(500 * time.Millisecond)
	purged := false
	for time.Now().Before(deadline) {
		plugin.tokenCacheMu.RLock()
		_, expiredExists := plugin.tokenCache["expired"]
		_, freshExists := plugin.tokenCache["fresh"]
		plugin.tokenCacheMu.RUnlock()

		if !expiredExists && freshExists {
			purged = true
			break
		}

		time.Sleep(10 * time.Millisecond)
	}

	if !purged {
		t.Fatal("Expected background purger to remove expired entries")
	}
}

func TestVercelAuth_unauthorized(t *testing.T) {
	plugin := &VercelAuth{}

	tests := []struct {
		name    string
		message string
	}{
		{
			name:    "missing token message",
			message: "Missing token",
		},
		{
			name:    "invalid token message",
			message: "Invalid token",
		},
		{
			name:    "custom message",
			message: "Custom error message",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			plugin.unauthorized(w, tt.message)

			if w.Code != http.StatusUnauthorized {
				t.Errorf("Expected status 401, got %d", w.Code)
			}

			contentType := w.Header().Get("Content-Type")
			if contentType != "text/plain; charset=UTF-8" {
				t.Errorf("Expected Content-Type 'text/plain; charset=UTF-8', got %q", contentType)
			}

			body := w.Body.String()
			if body != tt.message {
				t.Errorf("Expected body %q, got %q", tt.message, body)
			}
		})
	}
}

func TestJWTValidation(t *testing.T) {
	config := &Config{
		Issuer:       "https://oidc.vercel.com/test",
		TeamSlug:     "test-team",
		ProjectName:  "test-project",
		Environment:  "test",
		TokenHeader:  "Authorization",
		JWKSEndpoint: "https://oidc.vercel.com/test/.well-known/jwks",
	}

	plugin := &VercelAuth{
		config:     config,
		tokenCache: make(map[string]tokenValidationCacheEntry),
	}

	tests := []struct {
		name        string
		token       string
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "empty token",
			token:       "",
			shouldError: true,
			errorMsg:    "empty token",
		},
		{
			name:        "malformed token - not enough parts",
			token:       "invalid.token",
			shouldError: true,
			errorMsg:    "token is malformed",
		},
		{
			name:        "malformed token - invalid JSON in header",
			token:       "invalid.header.signature",
			shouldError: true,
			errorMsg:    "token is malformed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := plugin.validateToken(t.Context(), tt.token)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				// Just check that we got an error, not the exact message
				// since error messages can vary
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestVercelAuth_extractToken(t *testing.T) {
	tests := []struct {
		name          string
		tokenHeader   string
		headers       map[string]string
		expectedToken string
	}{
		{
			name:        "valid token with Bearer prefix",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "Bearer testoken123",
			},
			expectedToken: "testoken123",
		},
		{
			name:        "valid token with bearer prefix (lowercase)",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "bearer testoken123",
			},
			expectedToken: "testoken123",
		},
		{
			name:        "valid token with mixed case bearer prefix",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "BeArEr testoken123",
			},
			expectedToken: "testoken123",
		},
		{
			name:        "valid token without Bearer prefix",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "testoken123",
			},
			expectedToken: "testoken123",
		},
		{
			name:        "custom token header",
			tokenHeader: "X-Vercel-Oidc-Token",
			headers: map[string]string{
				"X-Vercel-Oidc-Token": "Bearer testoken123",
			},
			expectedToken: "testoken123",
		},
		{
			name:        "custom token header without Bearer prefix",
			tokenHeader: "X-Custom-Token",
			headers: map[string]string{
				"X-Custom-Token": "testoken123",
			},
			expectedToken: "testoken123",
		},
		{
			name:          "missing token header",
			tokenHeader:   "Authorization",
			headers:       map[string]string{},
			expectedToken: "",
		},
		{
			name:        "empty token header",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "",
			},
			expectedToken: "",
		},
		{
			name:        "token with only Bearer prefix (no space)",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "Bearer",
			},
			expectedToken: "Bearer",
		},
		{
			name:        "token with Bearer prefix and space but no token",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "Bearer ",
			},
			expectedToken: "",
		},
		{
			name:        "token that starts with 'bearer' but is not a prefix",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "bearertoken123",
			},
			expectedToken: "bearertoken123",
		},
		{
			name:        "wrong header present",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"X-Custom-Header": "Bearer testoken123",
			},
			expectedToken: "",
		},
		{
			name:        "multiple headers present, correct one with Bearer",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer testoken123",
				"X-Custom":      "other-value",
			},
			expectedToken: "testoken123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a VercelAuth instance with the test configuration
			config := &Config{
				TokenHeader: tt.tokenHeader,
			}
			v := &VercelAuth{
				config: config,
			}

			// Create HTTP headers from the test case
			headers := http.Header{}
			for key, value := range tt.headers {
				headers.Set(key, value)
			}

			// Call the extractToken function
			result := v.extractToken(headers)

			// Assert the result
			if result != tt.expectedToken {
				t.Errorf("extractToken() = %q, want %q", result, tt.expectedToken)
			}
		})
	}
}
