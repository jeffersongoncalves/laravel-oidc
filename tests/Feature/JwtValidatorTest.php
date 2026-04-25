<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Http;
use JeffersonGoncalves\LaravelOidc\Data\OidcDiscoveryDocument;
use JeffersonGoncalves\LaravelOidc\Exceptions\InvalidIdTokenException;
use JeffersonGoncalves\LaravelOidc\Services\JwtValidator;
use JeffersonGoncalves\LaravelOidc\Tests\Support\RsaKeyset;

function makeDiscovery(string $issuer = 'https://idp.example.com'): OidcDiscoveryDocument
{
    return new OidcDiscoveryDocument(
        issuer: $issuer,
        authorizationEndpoint: $issuer.'/auth',
        tokenEndpoint: $issuer.'/token',
        userinfoEndpoint: $issuer.'/userinfo',
        jwksUri: $issuer.'/.well-known/jwks.json',
    );
}

beforeEach(function () {
    $this->keyset = RsaKeyset::generate('test-key');
    $this->discovery = makeDiscovery();

    Http::fake([
        $this->discovery->jwksUri => Http::response($this->keyset->jwks()),
    ]);
});

it('validates a well-formed RS256 token', function () {
    $now = time();
    $token = $this->keyset->sign([
        'iss' => $this->discovery->issuer,
        'aud' => 'client-abc',
        'sub' => 'user-1',
        'iat' => $now,
        'exp' => $now + 600,
        'email' => 'jane@example.com',
    ]);

    $claims = app(JwtValidator::class)->validate(
        $token,
        $this->discovery,
        'client-abc',
    );

    expect($claims['sub'])->toBe('user-1')
        ->and($claims['email'])->toBe('jane@example.com');
});

it('rejects a token whose audience does not match', function () {
    $now = time();
    $token = $this->keyset->sign([
        'iss' => $this->discovery->issuer,
        'aud' => 'someone-else',
        'sub' => 'user-1',
        'iat' => $now,
        'exp' => $now + 600,
    ]);

    app(JwtValidator::class)->validate($token, $this->discovery, 'client-abc');
})->throws(InvalidIdTokenException::class, 'aud');

it('rejects a token whose issuer does not match', function () {
    $now = time();
    $token = $this->keyset->sign([
        'iss' => 'https://attacker.example.com',
        'aud' => 'client-abc',
        'sub' => 'user-1',
        'iat' => $now,
        'exp' => $now + 600,
    ]);

    app(JwtValidator::class)->validate($token, $this->discovery, 'client-abc');
})->throws(InvalidIdTokenException::class, 'iss');

it('rejects an expired token (outside leeway)', function () {
    $now = time();
    $token = $this->keyset->sign([
        'iss' => $this->discovery->issuer,
        'aud' => 'client-abc',
        'sub' => 'user-1',
        'iat' => $now - 7200,
        'exp' => $now - 3600,
    ]);

    app(JwtValidator::class)->validate($token, $this->discovery, 'client-abc', null, 60);
})->throws(InvalidIdTokenException::class);

it('rejects a token signed with a disallowed algorithm', function () {
    config()->set('oidc.jwt.allowed_algorithms', ['ES256']);

    $now = time();
    $token = $this->keyset->sign([
        'iss' => $this->discovery->issuer,
        'aud' => 'client-abc',
        'sub' => 'user-1',
        'iat' => $now,
        'exp' => $now + 600,
    ]);

    app(JwtValidator::class)->validate($token, $this->discovery, 'client-abc');
})->throws(InvalidIdTokenException::class, 'disallowed algorithm');

it('accepts the correct nonce', function () {
    $now = time();
    $token = $this->keyset->sign([
        'iss' => $this->discovery->issuer,
        'aud' => 'client-abc',
        'sub' => 'user-1',
        'iat' => $now,
        'exp' => $now + 600,
        'nonce' => 'expected-nonce',
    ]);

    $claims = app(JwtValidator::class)->validate(
        $token,
        $this->discovery,
        'client-abc',
        'expected-nonce',
    );

    expect($claims['nonce'])->toBe('expected-nonce');
});

it('rejects a token with an incorrect nonce', function () {
    $now = time();
    $token = $this->keyset->sign([
        'iss' => $this->discovery->issuer,
        'aud' => 'client-abc',
        'sub' => 'user-1',
        'iat' => $now,
        'exp' => $now + 600,
        'nonce' => 'wrong-nonce',
    ]);

    app(JwtValidator::class)->validate(
        $token,
        $this->discovery,
        'client-abc',
        'expected-nonce',
    );
})->throws(InvalidIdTokenException::class, 'nonce');
