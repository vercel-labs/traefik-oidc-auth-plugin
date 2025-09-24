package traefik_oidc_auth_plugin

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Allowed clock skew
const clockSkew = 5 * time.Minute

// VercelAuth is the plugin struct.
type VercelAuth struct {
	next   http.Handler
	name   string
	log    *slog.Logger
	config *Config
	jwks   JWKSCache
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

	plugin := &VercelAuth{
		next:   next,
		name:   name,
		log:    log,
		config: config,
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

	return plugin, nil
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

// extractToken extracts the JWT token from the request.
func (v *VercelAuth) extractToken(h http.Header) string {
	token := h.Get(v.config.TokenHeader)
	if token == "" {
		return ""
	}

	// Trim the Bearer prefix (case-insensitive) if found
	const (
		bearerPrefix = "bearer "
		prefixLen    = len(bearerPrefix)
	)
	if len(token) >= prefixLen && strings.ToLower(token[:prefixLen]) == bearerPrefix {
		return token[prefixLen:]
	}

	return token
}

// validateToken validates the JWT token.
func (v *VercelAuth) validateToken(ctx context.Context, tokenString string) error {
	if tokenString == "" {
		return fmt.Errorf("token is empty")
	}

	// Parse the token without validation first to get the header
	token, err := jwt.Parse(tokenString,
		func(token *jwt.Token) (any, error) {
			// Get the kid from the token header
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, errors.New("missing kid in token header")
			}

			// Find the corresponding public key in JWKS
			publicKey, err := v.jwks.GetPublicKey(ctx, kid)
			if err != nil {
				return nil, fmt.Errorf("failed to get public key: %w", err)
			}

			return publicKey, nil
		},
		jwt.WithAudience(v.config.Audience()),
		jwt.WithIssuer(v.config.Issuer),
		jwt.WithSubject(v.config.Subject()),
		jwt.WithLeeway(clockSkew),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
	)
	if err != nil {
		return err
	} else if !token.Valid {
		return errors.New("token is not valid")
	}

	return nil
}

// unauthorized sends an unauthorized response.
func (v *VercelAuth) unauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.WriteHeader(http.StatusUnauthorized)

	// Ignore errors here, headers already sent
	_, _ = fmt.Fprint(w, message)
}
