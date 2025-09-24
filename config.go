package traefik_oidc_auth_plugin

import (
	"errors"
	"strings"
)

// Config holds the plugin configuration.
type Config struct {
	// JWT issuer (required)
	// - "https://oidc.vercel.com" (global issuer mode)
	// - "https://oidc.vercel.com/team-name" (team issuer mode)
	Issuer string `json:"issuer"`
	// Vercel team slug (required)
	TeamSlug string `json:"teamSlug"`
	// Vercel project name (required)
	ProjectName string `json:"projectName"`
	// Environment name, e.g. "production" or "preview" (required)
	Environment string `json:"environment"`
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
	// Validate the issuer and trim the ending slash if present
	if c.Issuer == "" {
		return errors.New("property issuer is required")
	}
	c.Issuer = strings.TrimRight(c.Issuer, "/")

	// Enforce other required fields
	if c.TeamSlug == "" {
		return errors.New("property teamSlug is required")
	}
	if c.ProjectName == "" {
		return errors.New("property projectName is required")
	}
	if c.Environment == "" {
		return errors.New("property environment is required")
	}

	// Set default JWKS endpoint if not provided
	if c.JWKSEndpoint == "" {
		c.JWKSEndpoint = c.Issuer + "/.well-known/jwks"
	}

	return nil
}

// Audience returns the expected aud claim value
func (c Config) Audience() string {
	// https://vercel.com/[TEAM_SLUG]
	return "https://vercel.com/" + c.TeamSlug
}

// Subject returns the expected sub claim value
func (c Config) Subject() string {
	// owner:[TEAM_SLUG]:project:[PROJECT_NAME]:environment:[ENVIRONMENT]
	return "owner:" + c.TeamSlug + ":project:" + c.ProjectName + ":environment:" + c.Environment
}
