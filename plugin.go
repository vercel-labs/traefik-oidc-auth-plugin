package traefik_oidc_auth_plugin

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

// Allowed clock skew
const clockSkew = 5 * time.Minute

const tokenCachePurgeInterval = time.Hour

// VercelAuth is the plugin struct.
type VercelAuth struct {
	next   http.Handler
	name   string
	log    *slog.Logger
	config *Config
	jwks   JWKSCache

	tokenCache   map[string]tokenValidationCacheEntry
	tokenCacheMu sync.RWMutex
}

// New creates a new VercelAuth plugin instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Init the HTTP client with custom TLS options
	transport := http.DefaultTransport.(*http.Transport)
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12

	client := &http.Client{
		Transport: transport,
	}

	// Return the plugin
	return newWithClient(ctx, next, config, name, client)
}

func newWithClient(ctx context.Context, next http.Handler, config *Config, name string, client *http.Client) (http.Handler, error) {
	log := slog.
		New(slog.NewJSONHandler(os.Stdout, nil)).
		With(
			slog.String("scope", "VercelAuthPlugin"),
			slog.String("plugin", name),
		)
	log.Info("Initializing Vercel Auth plugin")

	// Validate the config
	err := config.Validate()
	if err != nil {
		return nil, fmt.Errorf("configuration error: %w", err)
	}

	// Warn when not using a custom audience
	if !config.HasCustomAudience() {
		log.Warn(
			"No custom audience configured; using the default audience. Configuring a custom audience is recommended for security reasons to prevent token replay attacks. See https://vercel.com/changelog/custom-oidc-token-audiences",
			slog.String("audience", config.TokenAudience()),
		)
	}

	plugin := &VercelAuth{
		next:       next,
		name:       name,
		log:        log,
		config:     config,
		tokenCache: make(map[string]tokenValidationCacheEntry),
	}

	// Init JWKS cache
	plugin.jwks = &jwksCache{
		client:   client,
		log:      log,
		endpoint: config.JWKSEndpoint,
	}

	// Do an initial refresh
	err = plugin.jwks.Refresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS from '%s': %w", config.JWKSEndpoint, err)
	}

	go plugin.startTokenCachePurger(ctx, tokenCachePurgeInterval)

	return plugin, nil
}

func (v *VercelAuth) startTokenCachePurger(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = tokenCachePurgeInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			v.purgeExpiredValidatedTokens(now)
		}
	}
}

// ServeHTTP implements the middleware logic.
func (v *VercelAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := v.extractToken(r.Header)
	if token == "" {
		v.unauthorized(w, "Missing token")
		return
	}

	err := v.validateToken(r.Context(), token)
	if err != nil {
		v.log.Warn("Vercel auth token is invalid", slog.Any("error", err))
		v.unauthorized(w, "Invalid token")
		return
	}

	v.next.ServeHTTP(w, r)
}

// unauthorized sends an unauthorized response.
func (v *VercelAuth) unauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.WriteHeader(http.StatusUnauthorized)

	// Ignore errors here, headers already sent
	_, _ = fmt.Fprint(w, message)
}
