<?php

declare(strict_types=1);

use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;
use JeffersonGoncalves\LaravelOidc\Data\OidcConfig;
use JeffersonGoncalves\LaravelOidc\Data\OidcDiscoveryDocument;
use JeffersonGoncalves\LaravelOidc\Exceptions\OidcException;
use JeffersonGoncalves\LaravelOidc\Providers\GenericOidcProvider;
use JeffersonGoncalves\LaravelOidc\Services\OidcDiscoveryService;
use Laravel\Socialite\Facades\Socialite;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\User as SocialiteUser;

function bootRequestWithSession(array $query = []): Request
{
    $request = Request::create('http://localhost/sso/callback', 'GET', $query);
    $session = new Store('test', new ArraySessionHandler(120));
    $session->start();
    $request->setLaravelSession($session);

    return $request;
}

function makeConfig(): OidcConfig
{
    return new OidcConfig(
        issuerUrl: 'https://idp.example.com',
        clientId: 'client-abc',
        clientSecret: 'secret',
        redirectUri: 'http://localhost/sso/callback',
        scopes: ['openid', 'email', 'profile'],
        usePkce: true,
    );
}

function makeProviderDiscovery(): OidcDiscoveryDocument
{
    return new OidcDiscoveryDocument(
        issuer: 'https://idp.example.com',
        authorizationEndpoint: 'https://idp.example.com/oauth2/authorize',
        tokenEndpoint: 'https://idp.example.com/oauth2/token',
        userinfoEndpoint: 'https://idp.example.com/oauth2/userinfo',
        jwksUri: 'https://idp.example.com/.well-known/jwks.json',
    );
}

it('registers the oidc driver with Socialite', function () {
    $provider = Socialite::driver('oidc');

    expect($provider)->toBeInstanceOf(GenericOidcProvider::class);
});

it('stores the runtime config and propagates credentials', function () {
    $request = bootRequestWithSession();
    $provider = new GenericOidcProvider($request, '', '', '');
    $provider->setConfig(makeConfig());

    expect($provider->getConfig()->clientId)->toBe('client-abc');

    $reflect = new ReflectionObject($provider);
    expect($reflect->getProperty('clientId')->getValue($provider))->toBe('client-abc')
        ->and($reflect->getProperty('clientSecret')->getValue($provider))->toBe('secret')
        ->and($reflect->getProperty('redirectUrl')->getValue($provider))->toBe('http://localhost/sso/callback');
});

it('builds the redirect URL using discovery, nonce and PKCE', function () {
    $discoveryService = Mockery::mock(OidcDiscoveryService::class);
    $discoveryService->shouldReceive('discover')->andReturn(makeProviderDiscovery());

    $request = bootRequestWithSession();
    $provider = new GenericOidcProvider($request, '', '', '');
    $provider->setDiscoveryService($discoveryService)
        ->setConfig(makeConfig());

    $response = $provider->redirect();
    $location = $response->getTargetUrl();

    parse_str(parse_url($location, PHP_URL_QUERY) ?: '', $params);

    expect($location)->toStartWith('https://idp.example.com/oauth2/authorize')
        ->and($params)->toHaveKey('client_id', 'client-abc')
        ->and($params)->toHaveKey('redirect_uri', 'http://localhost/sso/callback')
        ->and($params)->toHaveKey('response_type', 'code')
        ->and($params)->toHaveKey('state')
        ->and($params)->toHaveKey('nonce')
        ->and($params)->toHaveKey('code_challenge')
        ->and($params['code_challenge_method'])->toBe('S256')
        ->and(strpos($params['scope'], 'openid'))->not->toBeFalse();

    expect($request->session()->get('oidc.nonce'))->toBe($params['nonce']);
    expect($request->session()->has('oidc.code_verifier'))->toBeTrue();
});

it('omits PKCE parameters when usePkce is false', function () {
    $discoveryService = Mockery::mock(OidcDiscoveryService::class);
    $discoveryService->shouldReceive('discover')->andReturn(makeProviderDiscovery());

    $config = new OidcConfig(
        issuerUrl: 'https://idp.example.com',
        clientId: 'client-abc',
        clientSecret: 'secret',
        redirectUri: 'http://localhost/sso/callback',
        usePkce: false,
    );

    $request = bootRequestWithSession();
    $provider = new GenericOidcProvider($request, '', '', '');
    $provider->setDiscoveryService($discoveryService)->setConfig($config);

    $location = $provider->redirect()->getTargetUrl();
    parse_str(parse_url($location, PHP_URL_QUERY) ?: '', $params);

    expect($params)->not->toHaveKey('code_challenge')
        ->and($params)->not->toHaveKey('code_challenge_method')
        ->and($params)->toHaveKey('nonce');
});

it('throws when getConfig is called before setConfig', function () {
    $provider = new GenericOidcProvider(bootRequestWithSession(), '', '', '');

    $provider->getConfig();
})->throws(OidcException::class);

it('throws InvalidStateException when the callback state does not match the session', function () {
    $request = Request::create('http://localhost/sso/callback', 'GET', [
        'code' => 'auth-code-123',
        'state' => 'request-state',
    ]);
    $session = new Store('test', new ArraySessionHandler(120));
    $session->start();
    $session->put('state', 'a-different-session-state');
    $request->setLaravelSession($session);

    $provider = new GenericOidcProvider($request, '', '', '');
    $provider->setConfig(makeConfig());

    $provider->user();
})->throws(InvalidStateException::class);

it('builds the RP-initiated logout URL from the end_session_endpoint', function () {
    $discovery = new OidcDiscoveryDocument(
        issuer: 'https://idp.example.com',
        authorizationEndpoint: 'https://idp.example.com/oauth2/authorize',
        tokenEndpoint: 'https://idp.example.com/oauth2/token',
        userinfoEndpoint: 'https://idp.example.com/oauth2/userinfo',
        jwksUri: 'https://idp.example.com/.well-known/jwks.json',
        endSessionEndpoint: 'https://idp.example.com/oauth2/logout',
    );

    $discoveryService = Mockery::mock(OidcDiscoveryService::class);
    $discoveryService->shouldReceive('discover')->andReturn($discovery);

    $provider = new GenericOidcProvider(bootRequestWithSession(), '', '', '');
    $provider->setDiscoveryService($discoveryService)->setConfig(makeConfig());

    $url = $provider->logoutUrl('the-id-token', 'https://app.example.com/logged-out');

    parse_str(parse_url($url, PHP_URL_QUERY) ?: '', $params);

    expect($url)->toStartWith('https://idp.example.com/oauth2/logout')
        ->and($params)->toHaveKey('id_token_hint', 'the-id-token')
        ->and($params)->toHaveKey('post_logout_redirect_uri', 'https://app.example.com/logged-out')
        ->and($params)->toHaveKey('client_id', 'client-abc');
});

it('throws when the provider does not advertise an end_session_endpoint', function () {
    $discoveryService = Mockery::mock(OidcDiscoveryService::class);
    $discoveryService->shouldReceive('discover')->andReturn(makeProviderDiscovery());

    $provider = new GenericOidcProvider(bootRequestWithSession(), '', '', '');
    $provider->setDiscoveryService($discoveryService)->setConfig(makeConfig());

    $provider->logoutUrl();
})->throws(OidcException::class, 'end_session_endpoint');

function mapClaims(array $claims, array $mappings = []): SocialiteUser
{
    $provider = new GenericOidcProvider(bootRequestWithSession(), '', '', '');

    $provider->setConfig(new OidcConfig(
        issuerUrl: 'https://idp.example.com',
        clientId: 'client-abc',
        clientSecret: 'secret',
        redirectUri: 'http://localhost/sso/callback',
        userFieldMappings: $mappings,
    ));

    $method = (new ReflectionObject($provider))->getMethod('mapUserToObject');
    $method->setAccessible(true);

    return $method->invoke($provider, $claims);
}

it('maps the standard OIDC claims when no mapping is configured', function () {
    $user = mapClaims([
        'sub' => 'user-1',
        'preferred_username' => 'jdoe',
        'given_name' => 'John',
        'family_name' => 'Doe',
        'email' => 'john@example.com',
        'picture' => 'https://idp.example.com/avatar.png',
    ]);

    expect($user->getId())->toBe('user-1')
        ->and($user->getNickname())->toBe('jdoe')
        ->and($user->getName())->toBe('John Doe')
        ->and($user->getEmail())->toBe('john@example.com')
        ->and($user->getAvatar())->toBe('https://idp.example.com/avatar.png');
});

it('reads user fields from custom claims when mapped', function () {
    $user = mapClaims([
        'sub' => 'user-1',
        'uid' => 'jdoe',
        'displayName' => 'John Doe',
        'mail' => 'john@example.com',
        'thumbnail' => 'https://idp.example.com/avatar.png',
    ], [
        'nickname' => 'uid',
        'name' => 'displayName',
        'email' => 'mail',
        'avatar' => 'thumbnail',
    ]);

    expect($user->getId())->toBe('user-1')
        ->and($user->getNickname())->toBe('jdoe')
        ->and($user->getName())->toBe('John Doe')
        ->and($user->getEmail())->toBe('john@example.com')
        ->and($user->getAvatar())->toBe('https://idp.example.com/avatar.png');
});
