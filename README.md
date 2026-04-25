<div class="filament-hidden">

![Laravel OIDC](https://raw.githubusercontent.com/jeffersongoncalves/laravel-oidc/master/art/jeffersongoncalves-laravel-oidc.jpg)

</div>

# Laravel OIDC

[![Latest Version on Packagist](https://img.shields.io/packagist/v/jeffersongoncalves/laravel-oidc.svg?style=flat-square)](https://packagist.org/packages/jeffersongoncalves/laravel-oidc)
[![Total Downloads](https://img.shields.io/packagist/dt/jeffersongoncalves/laravel-oidc.svg?style=flat-square)](https://packagist.org/packages/jeffersongoncalves/laravel-oidc)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/jeffersongoncalves/laravel-oidc/tests.yml?branch=master&label=tests&style=flat-square)](https://github.com/jeffersongoncalves/laravel-oidc/actions?query=workflow%3Atests+branch%3Amaster)
[![GitHub Code Style Action Status](https://img.shields.io/github/actions/workflow/status/jeffersongoncalves/laravel-oidc/pint.yml?branch=master&label=code%20style&style=flat-square)](https://github.com/jeffersongoncalves/laravel-oidc/actions?query=workflow%3A"Fix+PHP+code+style+issues"+branch%3Amaster)
[![License](https://img.shields.io/packagist/l/jeffersongoncalves/laravel-oidc.svg?style=flat-square)](LICENSE.md)

Laravel OIDC adds first-class **OpenID Connect** support to Laravel by registering a custom
[Laravel Socialite](https://laravel.com/docs/socialite) driver named `oidc`. Unlike vanilla
Socialite — which covers OAuth 2.0 but stops at the userinfo step — this package implements
the OIDC pieces Socialite leaves out: discovery (`/.well-known/openid-configuration`),
JWKS-based `id_token` validation, nonce-based replay protection, and PKCE.

It is designed for **multi-tenant SaaS**: configuration is supplied at runtime, so each tenant
can connect its own Azure AD, Okta, Auth0, Google Workspace, Keycloak, or any other
spec-compliant OpenID Provider.

## Compatibility

| Package | Laravel        | PHP        |
|---------|----------------|------------|
| 1.x     | 11.x, 12.x, 13.x | 8.2, 8.3, 8.4 |

## Why?

Laravel Socialite ships drivers for fixed providers (GitHub, Google, etc.) and a small set of
OAuth 2.0 helpers. It does not:

- Read the IdP's `.well-known/openid-configuration` discovery document.
- Validate the `id_token` JWT against the IdP's JWKS.
- Send and verify a `nonce` to mitigate replay attacks.
- Make per-request configuration easy in multi-tenant scenarios.

This package adds those pieces while staying inside the Socialite mental model: you still
call `Socialite::driver('oidc')->redirect()` and `->user()`.

## Installation

```bash
composer require jeffersongoncalves/laravel-oidc
```

Optionally publish the config file:

```bash
php artisan vendor:publish --tag="oidc-config"
```

## Configuration

The package works out of the box. For single-tenant apps, set the default IdP in `.env`:

```env
OIDC_ISSUER_URL=https://login.microsoftonline.com/{tenant-id}/v2.0
OIDC_CLIENT_ID=your-app-client-id
OIDC_CLIENT_SECRET=your-app-secret
OIDC_REDIRECT_URI=https://your-app.test/sso/callback
```

For multi-tenant apps, leave the `default` block empty and supply an `OidcConfig` at runtime
(see below).

## Usage

### Single-tenant (config from `.env`)

```php
use Laravel\Socialite\Facades\Socialite;

Route::get('/sso/redirect', fn () => Socialite::driver('oidc')->redirect());

Route::get('/sso/callback', function () {
    $user = Socialite::driver('oidc')->user();

    // $user->id            // sub claim
    // $user->email
    // $user->name
    // $user->token         // access_token
    // $user->idToken       // raw id_token JWT
    // $user->idTokenClaims // decoded + validated claims
});
```

### Multi-tenant (runtime config)

```php
use Laravel\Socialite\Facades\Socialite;
use JeffersonGoncalves\LaravelOidc\Data\OidcConfig;

$config = new OidcConfig(
    issuerUrl: $tenant->issuer_url,
    clientId: $tenant->client_id,
    clientSecret: $tenant->client_secret,
    redirectUri: route('sso.callback'),
    scopes: ['openid', 'email', 'profile'],
);

return Socialite::driver('oidc')
    ->setConfig($config)
    ->redirect();
```

On callback:

```php
$oidcUser = Socialite::driver('oidc')
    ->setConfig($config)
    ->user();
```

### `HasOidcConfig` trait for tenant models

If you store IdP configuration on a model (a typical multi-tenant pattern), drop in the
trait. It expects columns `issuer_url`, `client_id`, `client_secret` (cast to `encrypted`),
`redirect_uri`, and an optional `scopes` JSON column.

```php
use JeffersonGoncalves\LaravelOidc\Concerns\HasOidcConfig;

class SsoConnection extends Model
{
    use HasOidcConfig;
}

Socialite::driver('oidc')
    ->setConfig($ssoConnection->toOidcConfig())
    ->redirect();
```

### Discovery without Socialite

```php
use JeffersonGoncalves\LaravelOidc\Facades\Oidc;

$discovery = Oidc::discover('https://login.microsoftonline.com/{tenant-id}/v2.0');

$discovery->authorizationEndpoint;
$discovery->tokenEndpoint;
$discovery->userinfoEndpoint;
$discovery->jwksUri;
$discovery->issuer;
```

## Supported Identity Providers

Any IdP that publishes a `.well-known/openid-configuration` discovery document and signs
`id_token`s with one of the allowed algorithms (`RS256`, `RS384`, `RS512`, `ES256`, `ES384`)
will work. Examples:

| IdP                  | Issuer URL example                                           |
|----------------------|--------------------------------------------------------------|
| Azure AD / Entra ID  | `https://login.microsoftonline.com/{tenant-id}/v2.0`         |
| Google Workspace     | `https://accounts.google.com`                                |
| Okta                 | `https://{your-org}.okta.com`                                |
| Auth0                | `https://{your-tenant}.auth0.com/`                           |
| Keycloak             | `https://{host}/realms/{realm}`                              |
| Ping Identity        | `https://{environment}.pingone.com/{environment-id}/as`      |

## Security

- **`id_token` validation.** Every `id_token` is decoded against the IdP's JWKS using
  [`firebase/php-jwt`](https://github.com/firebase/php-jwt). The `iss`, `aud`, `exp`, and
  `iat` claims are checked, with a configurable clock-skew window.
- **Algorithm allow-list.** Only the algorithms in `oidc.jwt.allowed_algorithms` are
  accepted. Symmetric algorithms (`HS256` & friends) are intentionally absent — accepting
  them with a JWKS would enable trivial key-confusion attacks.
- **Replay protection.** A random `nonce` is generated, stored in the session, and verified
  against the `nonce` claim in the returned `id_token`.
- **PKCE.** Enabled by default with `S256`. Disable per request with
  `new OidcConfig(..., usePkce: false)`.
- **Caching.** The discovery document is cached for 1 hour and the JWKS for 6 hours by
  default; both TTLs are configurable. Use `Oidc::clearCache($issuer)` to invalidate after
  a key rotation.

## Testing

```bash
composer test
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information on what has changed recently.

## Contributing

Pull requests are welcome. Please make sure tests, PHPStan and Pint all pass before
opening a PR:

```bash
composer test
composer analyse
composer format
```

## Security Vulnerabilities

Please review [our security policy](../../security/policy) on how to report security
vulnerabilities.

## Credits

- [Jefferson Gonçalves](https://github.com/jeffersongoncalves)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
