# Changelog

All notable changes to `laravel-oidc` will be documented in this file.

## v1.0.0 - 2026-04-25

First public release of **laravel-oidc** — OpenID Connect for Laravel via a custom Socialite driver.

### Highlights

- 🔌 **Socialite driver** named `oidc` registered automatically by the package's service provider.
- 🌐 **OIDC discovery** — fetches and caches `.well-known/openid-configuration` (1h TTL) and JWKS (6h TTL).
- 🪪 **`id_token` validation** — `iss`, `aud`, `exp`, `iat`, `nonce` checks with configurable clock-skew leeway and an algorithm allow-list (RS256/RS384/RS512/ES256/ES384). Symmetric algorithms intentionally rejected.
- 🛡️ **Replay protection** — random `nonce` is generated, stored in the session and verified against the `nonce` claim of the returned `id_token`.
- 🔐 **PKCE (S256)** — enabled by default; opt-out per request via `OidcConfig(usePkce: false)`.
- 🏢 **Multi-tenant first** — runtime configuration via `Socialite::driver('oidc')->setConfig($oidcConfig)`. `HasOidcConfig` trait wires Eloquent tenant models to the driver.
- 🧰 **Direct discovery API** — `Oidc::discover($issuer)` facade for non-Socialite use cases.

### Tested with

- PHP 8.2, 8.3, 8.4
- Laravel 11.x, 12.x, 13.x

### Installation

```bash
composer require jeffersongoncalves/laravel-oidc

```
See the [README](https://github.com/jeffersongoncalves/laravel-oidc#readme) for single-tenant and multi-tenant usage examples, and the supported-IdP table (Azure AD/Entra ID, Google Workspace, Okta, Auth0, Keycloak, Ping Identity, …).
