<?php

declare(strict_types=1);

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Http;
use JeffersonGoncalves\LaravelOidc\Data\OidcConfig;
use JeffersonGoncalves\LaravelOidc\Data\OidcUser;
use JeffersonGoncalves\LaravelOidc\Providers\GenericOidcProvider;
use JeffersonGoncalves\LaravelOidc\Tests\Support\RsaKeyset;

function callbackRequestWithStateAndNonce(string $state, string $nonce, string $verifier): Request
{
    $request = Request::create('http://localhost/sso/callback', 'GET', [
        'code' => 'auth-code-123',
        'state' => $state,
    ]);

    $session = new Store('test', new ArraySessionHandler(120));
    $session->start();
    $session->put('state', $state);
    $session->put('oidc.nonce', $nonce);
    $session->put('oidc.code_verifier', $verifier);
    $request->setLaravelSession($session);

    return $request;
}

it('runs the full OIDC flow end to end', function () {
    $issuer = 'https://idp.example.com';
    $keyset = RsaKeyset::generate('rotating-key');

    $discoveryPayload = [
        'issuer' => $issuer,
        'authorization_endpoint' => $issuer.'/oauth2/authorize',
        'token_endpoint' => $issuer.'/oauth2/token',
        'userinfo_endpoint' => $issuer.'/oauth2/userinfo',
        'jwks_uri' => $issuer.'/.well-known/jwks.json',
    ];

    Http::fake([
        $issuer.'/.well-known/openid-configuration' => Http::response($discoveryPayload),
        $issuer.'/.well-known/jwks.json' => Http::response($keyset->jwks()),
    ]);

    $now = time();
    $idToken = $keyset->sign([
        'iss' => $issuer,
        'aud' => 'client-abc',
        'sub' => 'user-42',
        'iat' => $now,
        'exp' => $now + 600,
        'nonce' => 'flow-nonce',
        'email' => 'jane@example.com',
        'name' => 'Jane Doe',
    ]);

    $tokenResponseBody = json_encode([
        'access_token' => 'access-xyz',
        'refresh_token' => 'refresh-xyz',
        'id_token' => $idToken,
        'token_type' => 'Bearer',
        'expires_in' => 3600,
        'scope' => 'openid email profile',
    ]);

    $userinfoResponseBody = json_encode([
        'sub' => 'user-42',
        'email' => 'jane@example.com',
        'email_verified' => true,
        'name' => 'Jane Doe',
        'preferred_username' => 'jane',
        'picture' => 'https://idp.example.com/avatars/jane.png',
    ]);

    $mock = new MockHandler([
        new Response(200, ['Content-Type' => 'application/json'], $tokenResponseBody),
        new Response(200, ['Content-Type' => 'application/json'], $userinfoResponseBody),
    ]);

    $guzzle = new Client(['handler' => HandlerStack::create($mock)]);

    $request = callbackRequestWithStateAndNonce('persisted-state', 'flow-nonce', 'persisted-verifier');

    $provider = new GenericOidcProvider($request, '', '', '');
    $provider->setHttpClient($guzzle);
    $provider->setConfig(new OidcConfig(
        issuerUrl: $issuer,
        clientId: 'client-abc',
        clientSecret: 'secret',
        redirectUri: 'http://localhost/sso/callback',
        scopes: ['openid', 'email', 'profile'],
    ));

    /** @var OidcUser $user */
    $user = $provider->user();

    expect($user)->toBeInstanceOf(OidcUser::class)
        ->and($user->getId())->toBe('user-42')
        ->and($user->getEmail())->toBe('jane@example.com')
        ->and($user->getName())->toBe('Jane Doe')
        ->and($user->getNickname())->toBe('jane')
        ->and($user->getAvatar())->toBe('https://idp.example.com/avatars/jane.png')
        ->and($user->token)->toBe('access-xyz')
        ->and($user->refreshToken)->toBe('refresh-xyz')
        ->and($user->idToken)->toBe($idToken)
        ->and($user->idTokenClaims['sub'])->toBe('user-42')
        ->and($user->idTokenClaims['nonce'])->toBe('flow-nonce');
});
