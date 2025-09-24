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
}

func newMockJWKSCache() *mockJWKSCache {
	return &mockJWKSCache{
		keys: make(map[string]*rsa.PublicKey),
	}
}

func (m *mockJWKSCache) GetPublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
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
	w.Write([]byte("success"))
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
			next:   nextHandler,
			name:   "test-plugin",
			log:    slog.New(slog.DiscardHandler),
			config: config,
			jwks:   mockJWKS,
		}

		// Create valid token
		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{config.Audience()},
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
			next:   nextHandler,
			name:   "test-plugin",
			log:    slog.New(slog.DiscardHandler),
			config: config,
			jwks:   mockJWKS,
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
			next:   nextHandler,
			name:   "test-plugin",
			log:    slog.New(slog.DiscardHandler),
			config: config,
			jwks:   mockJWKS,
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
			next:   nextHandler,
			name:   "test-plugin",
			log:    slog.New(slog.DiscardHandler),
			config: config,
			jwks:   mockJWKS,
		}

		// Create token that's slightly in the future (within clock skew tolerance)
		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{config.Audience()},
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
			name:   "test-plugin",
			log:    slog.New(slog.DiscardHandler),
			config: config,
			jwks:   mockJWKS,
			next:   nextHandler,
		}

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{config.Audience()},
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
			config: config,
			jwks:   mockJWKS,
		}

		// Create expired token
		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{config.Audience()},
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
			config: config,
			jwks:   mockJWKS,
		}

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    "https://wrong-issuer.com", // Wrong issuer
			Subject:   config.Subject(),
			Audience:  []string{config.Audience()},
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
			config: config,
			jwks:   mockJWKS,
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

	t.Run("Wrong subject", func(t *testing.T) {
		plugin := &VercelAuth{
			config: config,
			jwks:   mockJWKS,
		}

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   "wrong-subject", // Wrong subject
			Audience:  []string{config.Audience()},
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
			config: config,
			jwks:   mockJWKS,
		}

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{config.Audience()},
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
			config: config,
			// Use a new mock JWKSCache without the key
			jwks: newMockJWKSCache(),
		}

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{config.Audience()},
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
			config: config,
			jwks:   mockJWKS,
		}

		now := time.Now()
		claims := jwt.RegisteredClaims{
			Issuer:    config.Issuer,
			Subject:   config.Subject(),
			Audience:  []string{config.Audience()},
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
		config: config,
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
