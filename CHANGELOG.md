# Changelog

All notable changes to `laravel-oidc` will be documented in this file.

## v1.2.0 - 2026-09-02

### What's Changed

#### Added

- Custom user field mappings for providers using non-standard claims (#3, #4). Map any of `id`, `nickname`, `name`, `email`, `avatar` to the claim that holds it:

```php
// config/oidc.php, "default" block
'user_field_mappings' => [
    'email' => 'mail',
],

```
Also available at runtime via `new OidcConfig(..., userFieldMappings: ['email' => 'mail'])` and through an optional `user_field_mappings` JSON column on models using `HasOidcConfig`. Unmapped fields keep the standard OIDC claims (`sub`, `preferred_username`, `name`, `email`, `picture`).

**Full Changelog**: https://github.com/jeffersongoncalves/laravel-oidc/compare/v1.1.1...v1.2.0

## v1.1.1 - 2026-08-16

### Security

- fix: require `firebase/php-jwt` ^7.0, patches weak encryption (GHSA-2x45-7fc3-mxwq / CVE-2025-45769)

### Chore

- Add `dependabot.yml` with weekly grouped updates and 7-day cooldown for composer and github-actions

## v1.1.0 - 2026-08-05

### What's Changed

* Pass default algorithm to JWK::parseKeySet by @giorgio93p in https://github.com/jeffersongoncalves/laravel-oidc/pull/1

### New Contributors

* @giorgio93p made their first contribution in https://github.com/jeffersongoncalves/laravel-oidc/pull/1

**Full Changelog**: https://github.com/jeffersongoncalves/laravel-oidc/compare/v1.0.1...v1.1.0

## v1.0.1 - 2026-04-26

**Full Changelog**: https://github.com/jeffersongoncalves/laravel-oidc/compare/v1.0.0...v1.0.1

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
