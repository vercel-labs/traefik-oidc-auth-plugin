package traefik_oidc_auth_plugin

import (
	"errors"
	"strings"
)

// Config holds the plugin configuration.
type Config struct {
	// JWT issuer (optional)
	// - "https://oidc.vercel.com" or "global" (global issuer mode)
	// - "https://oidc.vercel.com/team-name" or "team" (team issuer mode)
	// If unset, defaults to the team issuer "https://oidc.vercel.com/[TEAM_SLUG]".
	Issuer string `json:"issuer,omitempty"`
	// Vercel team slug (required)
	TeamSlug string `json:"teamSlug"`
	// Vercel project name (required)
	ProjectName string `json:"projectName"`
	// Environment name, e.g. "production" or "preview" (required)
	Environment string `json:"environment"`
	// Custom audience expected in the token's "aud" claim (optional)
	// If unset, defaults to "https://vercel.com/[TEAM_SLUG]".
	// Using a custom audience is recommended for security reasons
	// See also: https://vercel.com/changelog/custom-oidc-token-audiences
	Audience string `json:"audience,omitempty"`
	// Name of the header containing the token, e.g. "Authorization" or "X-Vercel-Oidc-Token"
	// Defaults to "Authorization"
	TokenHeader string `json:"tokenHeader,omitempty"`
	// JWKS endpoint URL; most users should not alter this
	// Defaults to issuer + "/.well-known/jwks"
	JWKSEndpoint string `json:"jwksEndpoint,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		TokenHeader: "Authorization",
	}
}

// Validate the configuration
func (c *Config) Validate() error {
	// Enforce required fields
	if c.TeamSlug == "" {
		return errors.New("property teamSlug is required")
	}
	if c.ProjectName == "" {
		return errors.New("property projectName is required")
	}
	if c.Environment == "" {
		return errors.New("property environment is required")
	}

	// Resolve the issuer, including aliases and the default.
	// This depends on teamSlug, so it must run after that is validated.
	switch c.Issuer {
	case "global":
		c.Issuer = "https://oidc.vercel.com"
	case "", "team":
		c.Issuer = "https://oidc.vercel.com/" + c.TeamSlug
	}

	// Set default JWKS endpoint if not provided
	if c.JWKSEndpoint == "" {
		c.JWKSEndpoint = strings.TrimSuffix(c.Issuer, "/") + "/.well-known/jwks"
	}

	return nil
}

// TokenAudience returns the expected aud claim value.
// If a custom audience is not configure the default "https://vercel.com/[TEAM_SLUG]" is returned.
func (c Config) TokenAudience() string {
	if c.Audience == "" {
		// https://vercel.com/[TEAM_SLUG]
		return "https://vercel.com/" + c.TeamSlug
	}

	return c.Audience
}

// HasCustomAudience reports whether a custom audience has been configured.
func (c Config) HasCustomAudience() bool {
	return c.Audience != ""
}

// Subject returns the configured sub claim value or pattern.
func (c Config) Subject() string {
	// owner:[TEAM_SLUG]:project:[PROJECT_NAME]:environment:[ENVIRONMENT]
	return "owner:" + c.TeamSlug + ":project:" + c.ProjectName + ":environment:" + c.Environment
}

func (c Config) subjectMatches(subject string) bool {
	teamSlug, projectName, environment, ok := parseSubject(subject)
	if !ok {
		return false
	}

	return teamSlug == c.TeamSlug &&
		patternMatches(c.ProjectName, projectName) &&
		patternMatches(c.Environment, environment)
}

func parseSubject(subject string) (teamSlug string, projectName string, environment string, ok bool) {
	const ownerPrefix = "owner:"

	remaining, ok := strings.CutPrefix(subject, ownerPrefix)
	if !ok {
		return "", "", "", false
	}

	teamSlug, remaining, ok = strings.Cut(remaining, ":project:")
	if !ok {
		return "", "", "", false
	}

	projectName, environment, ok = strings.Cut(remaining, ":environment:")
	if !ok {
		return "", "", "", false
	}

	return teamSlug, projectName, environment, true
}

func patternMatches(pattern string, value string) bool {
	// Note that strings.SplitSeq isn't available in Yaegi
	for _, alternative := range strings.Split(pattern, "|") {
		// Wildcard matches everything
		if alternative == "*" {
			return true
		}

		// Match prefix
		if strings.HasSuffix(alternative, "*") && strings.HasPrefix(value, alternative[:len(alternative)-1]) {
			return true
		}

		// Exact match
		if value == alternative {
			return true
		}
	}

	return false
}
