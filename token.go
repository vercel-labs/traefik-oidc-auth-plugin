package traefik_oidc_auth_plugin

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const maxValidatedTokenCacheTTL = 5 * time.Minute

type tokenValidationCacheEntry struct {
	expiresAt  time.Time
	errMessage error
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

func validatedTokenCacheKey(tokenString string) string {
	hash := sha256.Sum256([]byte(tokenString))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func (v *VercelAuth) purgeExpiredValidatedTokens(now time.Time) int {
	v.tokenCacheMu.Lock()
	defer v.tokenCacheMu.Unlock()

	var purged int
	for tokenHash, entry := range v.tokenCache {
		if !now.Before(entry.expiresAt) {
			delete(v.tokenCache, tokenHash)
			purged++
		}
	}

	return purged
}

// validateToken validates the JWT token.
func (v *VercelAuth) validateToken(ctx context.Context, tokenString string) error {
	if tokenString == "" {
		return fmt.Errorf("token is empty")
	}

	tokenHash := validatedTokenCacheKey(tokenString)
	now := time.Now()

	// Check if we already validated this token recently
	v.tokenCacheMu.RLock()
	entry, ok := v.tokenCache[tokenHash]
	v.tokenCacheMu.RUnlock()
	if ok {
		// Return the cached result if present
		if now.Before(entry.expiresAt) {
			// We cache invalid tokens too to prevent flooding
			return entry.errMessage
		}

		// Best-effort cleanup for stale entries
		v.tokenCacheMu.Lock()
		entry, ok = v.tokenCache[tokenHash]
		if ok && !now.Before(entry.expiresAt) {
			delete(v.tokenCache, tokenHash)
		}
		v.tokenCacheMu.Unlock()
	}

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
		if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			// Cache validation failure up to the max cache TTL
			v.tokenCacheMu.Lock()
			v.tokenCache[tokenHash] = tokenValidationCacheEntry{
				expiresAt:  now.Add(maxValidatedTokenCacheTTL),
				errMessage: err,
			}
			v.tokenCacheMu.Unlock()
		}
		return err
	} else if !token.Valid {
		err = errors.New("token is not valid")

		// Cache validation failure up to the max cache TTL
		v.tokenCacheMu.Lock()
		v.tokenCache[tokenHash] = tokenValidationCacheEntry{
			expiresAt:  now.Add(maxValidatedTokenCacheTTL),
			errMessage: err,
		}
		v.tokenCacheMu.Unlock()

		return err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if ok {
		exp, expErr := claims.GetExpirationTime()
		if expErr == nil && exp != nil {
			cacheTTL := exp.Sub(now)
			if cacheTTL > maxValidatedTokenCacheTTL {
				cacheTTL = maxValidatedTokenCacheTTL
			}
			if cacheTTL > 0 {
				v.tokenCacheMu.Lock()
				v.tokenCache[tokenHash] = tokenValidationCacheEntry{
					expiresAt: now.Add(cacheTTL),
				}
				v.tokenCacheMu.Unlock()
			}
		}
	}

	return nil
}
