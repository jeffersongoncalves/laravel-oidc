<?php

declare(strict_types=1);

namespace JeffersonGoncalves\LaravelOidc\Providers;

use GuzzleHttp\RequestOptions;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use JeffersonGoncalves\LaravelOidc\Data\OidcConfig;
use JeffersonGoncalves\LaravelOidc\Data\OidcDiscoveryDocument;
use JeffersonGoncalves\LaravelOidc\Data\OidcUser;
use JeffersonGoncalves\LaravelOidc\Exceptions\OidcException;
use JeffersonGoncalves\LaravelOidc\Services\JwtValidator;
use JeffersonGoncalves\LaravelOidc\Services\OidcDiscoveryService;
use Laravel\Socialite\Two\AbstractProvider;
use Laravel\Socialite\Two\InvalidStateException;
use Laravel\Socialite\Two\ProviderInterface;
use Laravel\Socialite\Two\User as SocialiteUser;

class GenericOidcProvider extends AbstractProvider implements ProviderInterface
{
    /**
     * @var array<int, string>
     */
    protected $scopes = ['openid', 'email', 'profile'];

    protected $scopeSeparator = ' ';

    protected ?OidcConfig $oidcConfig = null;

    protected ?OidcDiscoveryDocument $cachedDiscovery = null;

    protected ?OidcDiscoveryService $discoveryService = null;

    protected ?JwtValidator $jwtValidator = null;

    public function setConfig(OidcConfig $config): self
    {
        $this->oidcConfig = $config;
        $this->cachedDiscovery = null;

        $this->clientId = $config->clientId;
        $this->clientSecret = $config->clientSecret;
        $this->redirectUrl = $config->redirectUri;
        $this->scopes = $config->scopes;

        return $this;
    }

    public function getConfig(): OidcConfig
    {
        if ($this->oidcConfig === null) {
            throw new OidcException(
                'OIDC config is not set. Call setConfig() before using the driver.'
            );
        }

        return $this->oidcConfig;
    }

    public function setDiscoveryService(OidcDiscoveryService $service): self
    {
        $this->discoveryService = $service;

        return $this;
    }

    public function setJwtValidator(JwtValidator $validator): self
    {
        $this->jwtValidator = $validator;

        return $this;
    }

    /**
     * Build the authorization URL using the discovered endpoint plus
     * OIDC-specific parameters (nonce, PKCE).
     */
    protected function getAuthUrl($state): string
    {
        $discovery = $this->resolveDiscovery();
        $config = $this->getConfig();

        $nonce = $this->generateNonce();
        $this->storeNonce($nonce);

        $extra = ['nonce' => $nonce];

        if ($config->usePkce) {
            $verifier = $this->generateCodeVerifier();
            $this->storeCodeVerifier($verifier);

            $extra['code_challenge'] = $this->codeChallengeFromVerifier($verifier);
            $extra['code_challenge_method'] = 'S256';
        }

        return $this->buildAuthUrlFromBase(
            $discovery->authorizationEndpoint,
            $state
        ).'&'.http_build_query($extra, '', '&', $this->encodingType);
    }

    protected function getTokenUrl(): string
    {
        return $this->resolveDiscovery()->tokenEndpoint;
    }

    /**
     * @param  string  $token
     * @return array<string, mixed>
     */
    protected function getUserByToken($token): array
    {
        $response = $this->getHttpClient()->get(
            $this->resolveDiscovery()->userinfoEndpoint,
            [
                RequestOptions::HEADERS => [
                    'Authorization' => 'Bearer '.$token,
                    'Accept' => 'application/json',
                ],
            ]
        );

        $body = (string) $response->getBody();
        $decoded = json_decode($body, true);

        return is_array($decoded) ? $decoded : [];
    }

    /**
     * @param  array<string, mixed>  $user
     */
    protected function mapUserToObject(array $user): SocialiteUser
    {
        return (new OidcUser)->setRaw($user)->map([
            'id' => $user['sub'] ?? null,
            'nickname' => $user['preferred_username'] ?? null,
            'name' => $this->resolveName($user),
            'email' => $user['email'] ?? null,
            'avatar' => $user['picture'] ?? null,
        ]);
    }

    public function user()
    {
        if ($this->user) {
            return $this->user;
        }

        if ($this->hasInvalidState()) {
            throw new InvalidStateException;
        }

        $tokenResponse = $this->getAccessTokenResponse($this->getCode());

        $accessToken = Arr::get($tokenResponse, 'access_token');
        $idToken = Arr::get($tokenResponse, 'id_token');

        if (! is_string($accessToken) || $accessToken === '') {
            throw new OidcException('Token endpoint did not return an access_token.');
        }

        if (! is_string($idToken) || $idToken === '') {
            throw new OidcException('Token endpoint did not return an id_token.');
        }

        $discovery = $this->resolveDiscovery();
        $config = $this->getConfig();
        $expectedNonce = $this->pullStoredNonce();

        $claims = $this->resolveJwtValidator()->validate(
            $idToken,
            $discovery,
            $config->clientId,
            $expectedNonce,
            $config->clockSkewSeconds,
        );

        $userinfo = $this->getUserByToken($accessToken);

        $merged = array_merge($claims, $userinfo);

        /** @var OidcUser $user */
        $user = $this->mapUserToObject($merged);

        $separator = $this->scopeSeparator !== '' ? $this->scopeSeparator : ' ';
        $scopeString = (string) Arr::get(
            $tokenResponse,
            'scope',
            implode($separator, $this->scopes)
        );

        $user->setToken($accessToken)
            ->setRefreshToken(Arr::get($tokenResponse, 'refresh_token'))
            ->setExpiresIn(Arr::get($tokenResponse, 'expires_in'))
            ->setApprovedScopes(explode($separator, $scopeString));

        $user->setIdToken($idToken)->setIdTokenClaims($claims);

        return $this->user = $user;
    }

    /**
     * @param  string  $code
     * @return array<string, mixed>
     */
    public function getAccessTokenResponse($code)
    {
        $fields = $this->getTokenFields($code);

        if ($this->getConfig()->usePkce) {
            $verifier = $this->pullStoredCodeVerifier();

            if ($verifier !== null) {
                $fields['code_verifier'] = $verifier;
            }
        }

        $response = $this->getHttpClient()->post($this->getTokenUrl(), [
            RequestOptions::HEADERS => [
                'Accept' => 'application/json',
            ],
            RequestOptions::FORM_PARAMS => $fields,
        ]);

        $body = (string) $response->getBody();
        $decoded = json_decode($body, true);

        return is_array($decoded) ? $decoded : [];
    }

    protected function resolveDiscovery(): OidcDiscoveryDocument
    {
        if ($this->cachedDiscovery !== null) {
            return $this->cachedDiscovery;
        }

        return $this->cachedDiscovery = $this->resolveDiscoveryService()
            ->discover($this->getConfig()->issuerUrl);
    }

    protected function resolveDiscoveryService(): OidcDiscoveryService
    {
        return $this->discoveryService ??= app(OidcDiscoveryService::class);
    }

    protected function resolveJwtValidator(): JwtValidator
    {
        return $this->jwtValidator ??= app(JwtValidator::class);
    }

    /**
     * @param  array<string, mixed>  $user
     */
    protected function resolveName(array $user): ?string
    {
        if (! empty($user['name']) && is_string($user['name'])) {
            return $user['name'];
        }

        $given = isset($user['given_name']) && is_string($user['given_name']) ? $user['given_name'] : '';
        $family = isset($user['family_name']) && is_string($user['family_name']) ? $user['family_name'] : '';
        $name = trim($given.' '.$family);

        return $name === '' ? null : $name;
    }

    protected function generateNonce(): string
    {
        return Str::random(32);
    }

    protected function generateCodeVerifier(): string
    {
        return rtrim(
            strtr(base64_encode(random_bytes(64)), '+/', '-_'),
            '='
        );
    }

    protected function codeChallengeFromVerifier(string $verifier): string
    {
        return rtrim(
            strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'),
            '='
        );
    }

    protected function storeNonce(string $nonce): void
    {
        $this->request->session()->put($this->nonceSessionKey(), $nonce);
    }

    protected function pullStoredNonce(): ?string
    {
        $value = $this->request->session()->pull($this->nonceSessionKey());

        return is_string($value) ? $value : null;
    }

    protected function storeCodeVerifier(string $verifier): void
    {
        $this->request->session()->put($this->verifierSessionKey(), $verifier);
    }

    protected function pullStoredCodeVerifier(): ?string
    {
        $value = $this->request->session()->pull($this->verifierSessionKey());

        return is_string($value) ? $value : null;
    }

    protected function nonceSessionKey(): string
    {
        return 'oidc.nonce';
    }

    protected function verifierSessionKey(): string
    {
        return 'oidc.code_verifier';
    }
}
