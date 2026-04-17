# Vercel OIDC Plugin for Traefik

A Traefik middleware plugin that validates [Vercel OpenID Connect (OIDC) tokens](https://vercel.com/docs/oidc) for authenticating requests to your services.

This plugin integrates with Vercel's OIDC authentication system to protect your services hosted outside of Vercel and served behind Traefik. It validates JWT tokens issued by Vercel, ensuring that only authorized requests from your Vercel deployments can access your backend services.

## Configuration

### Traefik startup configuration

> Also known as "install configuration"; formerly known as the "static configuration".

Include in your your Traefik's startup configuration (usually `traefik.yaml`) the following to load the plugin:

```yaml
# traefik.yml
experimental:
  plugins:
    vercel-oidc-auth:
      moduleName: github.com/vercel-labs/traefik-oidc-auth-plugin
      version: v0.1.0
```

### Define the middleware

Once the plugin is defined, you can define middlewares of kind "vercel-oidc-auth" in the routing configuration (formerly known as _dynamic configuration_).

Using the YAML format for the routing configuration, this looks similar to:

```yaml
http:
  middlewares:
    vercel-oidc-auth:
      plugin:
        vercel-oidc-auth:
          # If using the global issuer, set this to "https://oidc.vercel.com"
          issuer: "https://oidc.vercel.com/your-team"
          teamSlug: "your-team"
          projectName: "your-project"
          environment: "production"
          # Optional, defaults to "Authorization"
          # tokenHeader: "Authorization"
```

## Docker Compose Example

```yaml
version: '3.7'
services:
  traefik:
    image: traefik:v3.5
    command:
      - --api.insecure=true
      - --providers.docker=true
      - --entrypoints.web.address=:80
      - --experimental.plugins.vercel-oidc-auth.modulename=github.com/vercel-labs/traefik-oidc-auth-plugin
      - --experimental.plugins.vercel-oidc-auth.version=v0.1.0
    ports:
      - "80:80"
      - "8080:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  app:
    image: your-app:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.app.rule=Host(`your-domain.com`)"
      - "traefik.http.routers.app.middlewares=vercel-oidc-auth"
      - "traefik.http.middlewares.vercel-oidc-auth.plugin.vercel-oidc-auth.issuer=https://oidc.vercel.com/your-team"
      - "traefik.http.middlewares.vercel-oidc-auth.plugin.vercel-oidc-auth.teamSlug=your-team"
      - "traefik.http.middlewares.vercel-oidc-auth.plugin.vercel-oidc-auth.projectName=your-project"
      - "traefik.http.middlewares.vercel-oidc-auth.plugin.vercel-oidc-auth.environment=production"
```

## Configuration Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `issuer` | ✓ | - | JWT issuer URL. Use `https://oidc.vercel.com` for global or `https://oidc.vercel.com/team-name` for team-specific |
| `teamSlug` | ✓ | - | Your Vercel team slug |
| `projectName` | ✓ | - | The name of your Vercel project |
| `environment` | ✓ | - | Environment name (e.g., "production", "preview") |
| `tokenHeader` | - | "Authorization" | HTTP header containing the JWT token |
| `jwksEndpoint` | - | `{issuer}/.well-known/jwks` | JWKS endpoint URL for key retrieval |

## Usage with Vercel

### 1. Configure OIDC in your Vercel project

In your Vercel project settings, OIDC is enabled with team-specific issuers by default.

You can refer to the [official documentation](https://vercel.com/docs/oidc) for more information.

### 2. Make requests from Vercel Functions

You can obtain the OIDC token by invoking `getVercelOidcToken` from any Vercel Function.  
The result is a string that can be used as header in `fetch` requests.

```js
import { getVercelOidcToken } from '@vercel/functions/oidc'

// Get the OIDC token
const token = await getVercelOidcToken()

// Make the fetch request
const response = await fetch('https://example.com/api/data', {
  headers: {
    // Note the "Bearer" prefix is optional
    'Authorization': 'Bearer '+token,
  }
})
```
