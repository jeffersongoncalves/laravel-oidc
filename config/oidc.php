<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Cache configuration
    |--------------------------------------------------------------------------
    |
    | The discovery document and JWKS responses are cached to avoid hitting
    | the IdP on every request. Set "store" to null to use the default cache
    | store, or to a specific store name defined in config/cache.php.
    |
    */

    'cache' => [
        'discovery_ttl' => 3600,
        'jwks_ttl' => 21600,
        'store' => null,
    ],

    /*
    |--------------------------------------------------------------------------
    | HTTP client configuration
    |--------------------------------------------------------------------------
    */

    'http' => [
        'timeout' => 5,
        'connect_timeout' => 3,
    ],

    /*
    |--------------------------------------------------------------------------
    | JWT validation
    |--------------------------------------------------------------------------
    |
    | Clock skew is the maximum allowed difference (in seconds) between the
    | server clock and the IdP clock when validating exp/iat. Symmetric
    | algorithms such as HS256 are intentionally not allowed by default.
    |
    */

    'jwt' => [
        'leeway_seconds' => 60,
        'allowed_algorithms' => ['RS256', 'RS384', 'RS512', 'ES256', 'ES384'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Default (single-tenant) configuration
    |--------------------------------------------------------------------------
    |
    | This block is used as a fallback when no OidcConfig is supplied through
    | setConfig() at runtime. Fine for single-tenant apps; for multi-tenant
    | apps, prefer building OidcConfig from your tenant model.
    |
    */

    'default' => [
        'issuer_url' => env('OIDC_ISSUER_URL'),
        'client_id' => env('OIDC_CLIENT_ID'),
        'client_secret' => env('OIDC_CLIENT_SECRET'),
        'redirect_uri' => env('OIDC_REDIRECT_URI'),
        'scopes' => ['openid', 'email', 'profile'],
    ],

];
