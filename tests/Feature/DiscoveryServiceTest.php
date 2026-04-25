<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use JeffersonGoncalves\LaravelOidc\Data\OidcDiscoveryDocument;
use JeffersonGoncalves\LaravelOidc\Exceptions\DiscoveryFailedException;
use JeffersonGoncalves\LaravelOidc\Exceptions\JwksFetchException;
use JeffersonGoncalves\LaravelOidc\Services\OidcDiscoveryService;

function discoveryPayload(): array
{
    return [
        'issuer' => 'https://idp.example.com',
        'authorization_endpoint' => 'https://idp.example.com/oauth2/authorize',
        'token_endpoint' => 'https://idp.example.com/oauth2/token',
        'userinfo_endpoint' => 'https://idp.example.com/oauth2/userinfo',
        'jwks_uri' => 'https://idp.example.com/.well-known/jwks.json',
        'end_session_endpoint' => 'https://idp.example.com/oauth2/logout',
        'scopes_supported' => ['openid', 'email', 'profile'],
        'claims_supported' => ['sub', 'email', 'name'],
        'id_token_signing_alg_values_supported' => ['RS256'],
    ];
}

it('fetches and parses discovery document', function () {
    Http::fake([
        'https://idp.example.com/.well-known/openid-configuration' => Http::response(discoveryPayload()),
    ]);

    $document = app(OidcDiscoveryService::class)->discover('https://idp.example.com');

    expect($document)
        ->toBeInstanceOf(OidcDiscoveryDocument::class)
        ->and($document->issuer)->toBe('https://idp.example.com')
        ->and($document->authorizationEndpoint)->toBe('https://idp.example.com/oauth2/authorize')
        ->and($document->jwksUri)->toBe('https://idp.example.com/.well-known/jwks.json')
        ->and($document->endSessionEndpoint)->toBe('https://idp.example.com/oauth2/logout')
        ->and($document->supportedScopes)->toBe(['openid', 'email', 'profile']);
});

it('caches the discovery document', function () {
    Http::fake([
        'https://idp.example.com/.well-known/openid-configuration' => Http::response(discoveryPayload()),
    ]);

    $service = app(OidcDiscoveryService::class);
    $service->discover('https://idp.example.com');
    $service->discover('https://idp.example.com');

    Http::assertSentCount(1);
});

it('throws DiscoveryFailedException on http error', function () {
    Http::fake([
        'https://idp.example.com/.well-known/openid-configuration' => Http::response('boom', 500),
    ]);

    app(OidcDiscoveryService::class)->discover('https://idp.example.com');
})->throws(DiscoveryFailedException::class);

it('throws DiscoveryFailedException on non-array payload', function () {
    Http::fake([
        'https://idp.example.com/.well-known/openid-configuration' => Http::response('not-json', 200, ['Content-Type' => 'text/plain']),
    ]);

    app(OidcDiscoveryService::class)->discover('https://idp.example.com');
})->throws(DiscoveryFailedException::class);

it('throws DiscoveryFailedException when required fields are missing', function () {
    Http::fake([
        'https://idp.example.com/.well-known/openid-configuration' => Http::response(['issuer' => 'https://idp.example.com']),
    ]);

    app(OidcDiscoveryService::class)->discover('https://idp.example.com');
})->throws(DiscoveryFailedException::class);

it('caches and fetches jwks', function () {
    Http::fake([
        'https://idp.example.com/.well-known/jwks.json' => Http::response(['keys' => [['kty' => 'RSA', 'kid' => 'k1']]]),
    ]);

    $service = app(OidcDiscoveryService::class);
    $first = $service->getJwks('https://idp.example.com/.well-known/jwks.json');
    $second = $service->getJwks('https://idp.example.com/.well-known/jwks.json');

    expect($first)->toBe($second);
    Http::assertSentCount(1);
});

it('throws JwksFetchException on empty keys', function () {
    Http::fake([
        'https://idp.example.com/.well-known/jwks.json' => Http::response([]),
    ]);

    app(OidcDiscoveryService::class)->getJwks('https://idp.example.com/.well-known/jwks.json');
})->throws(JwksFetchException::class);

it('clears the discovery cache on demand', function () {
    Http::fake([
        'https://idp.example.com/.well-known/openid-configuration' => Http::response(discoveryPayload()),
        'https://idp.example.com/.well-known/jwks.json' => Http::response(['keys' => [['kty' => 'RSA', 'kid' => 'k1']]]),
    ]);

    $service = app(OidcDiscoveryService::class);
    $service->discover('https://idp.example.com');

    expect(Cache::has('oidc:discovery:'.hash('sha256', 'https://idp.example.com')))->toBeTrue();

    $service->clearCache('https://idp.example.com');

    expect(Cache::has('oidc:discovery:'.hash('sha256', 'https://idp.example.com')))->toBeFalse();
});
