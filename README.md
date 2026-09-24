# Refactored PowerShell OIDC API

This repository contains a PowerShell-based OIDC API for browser login and authenticated API access.

## Included files

- `API` - HTTPS OIDC authentication API
- `auth-demo.html` - minimal frontend demo for login, profile, and logout
- `.env.example` - sample environment configuration

## Supported providers

- Okta
- Microsoft Entra ID (Azure AD)

## Quick start

1. Configure HTTPS certificate binding on Windows:

```powershell
netsh http add sslcert ipport=0.0.0.0:8443 certhash=CERT_THUMBPRINT appid={00112233-4455-6677-8899-aabbccddeeff}
```

2. Copy `.env.example` to your shell environment or set the variables in PowerShell.

3. Start the API:

```powershell
pwsh ./API
```

4. Open the demo page in a browser:

```text
https://localhost:8443/
```

## Okta configuration

Required settings:

```powershell
$env:OIDC_PROVIDER = 'okta'
$env:OKTA_ISSUER = 'https://your-org.okta.com/oauth2/default'
$env:OKTA_CLIENT_ID = 'your-client-id'
$env:OKTA_REDIRECT_URI = 'https://localhost:8443/auth/callback'
$env:OKTA_CLIENT_SECRET = 'your-client-secret'   # for confidential apps
```

## Microsoft Entra configuration

Required settings:

```powershell
$env:OIDC_PROVIDER = 'azure'
$env:AZURE_TENANT_ID = 'tenant-id'
$env:AZURE_CLIENT_ID = 'app-registration-client-id'
$env:AZURE_REDIRECT_URI = 'https://localhost:8443/auth/callback'
$env:AZURE_CLIENT_SECRET = 'your-client-secret'   # optional for public apps
```

## Session backend

By default, sessions are stored in memory. To use Redis instead:

```powershell
$env:REDIS_URL = 'redis://localhost:6379/0'
```

The API automatically uses Redis-backed session storage when this environment variable is present.

## Routes

- `GET /health` - returns service status
- `GET /auth/login` - redirects to the IdP login page
- `GET /auth/callback` - exchanges code for tokens and creates session
- `GET /auth/me` - returns current user claims
- `POST /auth/logout` - clears session and revokes tokens

## Security overview

- HTTPS-only enforcement
- PKCE verification on all login requests
- Opaque session cookie with HttpOnly + Secure + SameSite=Lax
- State validation to protect against CSRF
- Optional token revocation on logout
- No password handling in the API itself

## Browser demo

The included `auth-demo.html` page can log in and display the authenticated user profile using the browser cookies created by the API.
