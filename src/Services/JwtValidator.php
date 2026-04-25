<?php

declare(strict_types=1);

namespace JeffersonGoncalves\LaravelOidc\Services;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use JeffersonGoncalves\LaravelOidc\Data\OidcDiscoveryDocument;
use JeffersonGoncalves\LaravelOidc\Exceptions\InvalidIdTokenException;
use Throwable;

class JwtValidator
{
    public function __construct(
        protected OidcDiscoveryService $discovery,
        protected ConfigRepository $config,
    ) {}

    /**
     * Validate an OIDC id_token against the discovery document and JWKS.
     *
     * @return array<string, mixed>
     *
     * @throws InvalidIdTokenException
     */
    public function validate(
        string $idToken,
        OidcDiscoveryDocument $discovery,
        string $clientId,
        ?string $expectedNonce = null,
        ?int $clockSkew = null,
    ): array {
        $allowed = $this->allowedAlgorithms();
        $leeway = $clockSkew ?? (int) $this->config->get('oidc.jwt.leeway_seconds', 60);

        $this->guardAlgorithm($idToken, $allowed);

        try {
            $jwks = $this->discovery->getJwks($discovery->jwksUri);
            $keys = JWK::parseKeySet($jwks);
        } catch (Throwable $e) {
            throw new InvalidIdTokenException(
                "Unable to load JWKS for token validation: {$e->getMessage()}",
                previous: $e,
            );
        }

        JWT::$leeway = $leeway;

        try {
            $decoded = JWT::decode($idToken, $keys);
        } catch (Throwable $e) {
            throw new InvalidIdTokenException(
                "Failed to decode id_token: {$e->getMessage()}",
                previous: $e,
            );
        }

        $claims = (array) $decoded;

        $this->assertIssuer($claims, $discovery->issuer);
        $this->assertAudience($claims, $clientId);
        $this->assertNonce($claims, $expectedNonce);

        return $claims;
    }

    /**
     * @return array<int, string>
     */
    protected function allowedAlgorithms(): array
    {
        $allowed = $this->config->get('oidc.jwt.allowed_algorithms', ['RS256']);

        if (! is_array($allowed) || $allowed === []) {
            return ['RS256'];
        }

        return array_values(array_map('strval', $allowed));
    }

    /**
     * @param  array<int, string>  $allowed
     *
     * @throws InvalidIdTokenException
     */
    protected function guardAlgorithm(string $idToken, array $allowed): void
    {
        $segments = explode('.', $idToken);

        if (count($segments) !== 3) {
            throw new InvalidIdTokenException('Malformed id_token (expected 3 segments).');
        }

        $headerJson = $this->urlsafeBase64Decode($segments[0]);

        if ($headerJson === '') {
            throw new InvalidIdTokenException('Unable to decode id_token header.');
        }

        $header = json_decode($headerJson, true);

        if (! is_array($header) || empty($header['alg']) || ! is_string($header['alg'])) {
            throw new InvalidIdTokenException('id_token header is missing the "alg" field.');
        }

        if (! in_array($header['alg'], $allowed, true)) {
            throw new InvalidIdTokenException(
                "id_token uses disallowed algorithm '{$header['alg']}'."
            );
        }
    }

    protected function urlsafeBase64Decode(string $segment): string
    {
        $remainder = strlen($segment) % 4;

        if ($remainder !== 0) {
            $segment .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($segment, '-_', '+/'), true);

        return $decoded === false ? '' : $decoded;
    }

    /**
     * @param  array<string, mixed>  $claims
     *
     * @throws InvalidIdTokenException
     */
    protected function assertIssuer(array $claims, string $expectedIssuer): void
    {
        if (empty($claims['iss']) || $claims['iss'] !== $expectedIssuer) {
            throw new InvalidIdTokenException(
                'id_token "iss" claim does not match the discovery issuer.'
            );
        }
    }

    /**
     * @param  array<string, mixed>  $claims
     *
     * @throws InvalidIdTokenException
     */
    protected function assertAudience(array $claims, string $clientId): void
    {
        $aud = $claims['aud'] ?? null;

        if (is_string($aud)) {
            $aud = [$aud];
        }

        if (! is_array($aud) || ! in_array($clientId, $aud, true)) {
            throw new InvalidIdTokenException(
                'id_token "aud" claim does not include the configured client_id.'
            );
        }

        if (isset($claims['azp']) && is_string($claims['azp']) && $claims['azp'] !== $clientId) {
            throw new InvalidIdTokenException(
                'id_token "azp" claim does not match the configured client_id.'
            );
        }
    }

    /**
     * @param  array<string, mixed>  $claims
     *
     * @throws InvalidIdTokenException
     */
    protected function assertNonce(array $claims, ?string $expectedNonce): void
    {
        if ($expectedNonce === null) {
            return;
        }

        if (empty($claims['nonce']) || $claims['nonce'] !== $expectedNonce) {
            throw new InvalidIdTokenException(
                'id_token "nonce" claim does not match the value sent in the auth request.'
            );
        }
    }
}
