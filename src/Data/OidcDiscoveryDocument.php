<?php

declare(strict_types=1);

namespace JeffersonGoncalves\LaravelOidc\Data;

use JeffersonGoncalves\LaravelOidc\Exceptions\DiscoveryFailedException;

final readonly class OidcDiscoveryDocument
{
    /**
     * @param  array<int, string>  $supportedScopes
     * @param  array<int, string>  $supportedClaims
     * @param  array<int, string>  $idTokenSigningAlgValuesSupported
     */
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $userinfoEndpoint,
        public string $jwksUri,
        public ?string $endSessionEndpoint = null,
        public array $supportedScopes = [],
        public array $supportedClaims = [],
        public array $idTokenSigningAlgValuesSupported = [],
    ) {}

    /**
     * @param  array<string, mixed>  $payload
     *
     * @throws DiscoveryFailedException
     */
    public static function fromArray(array $payload): self
    {
        $required = [
            'issuer',
            'authorization_endpoint',
            'token_endpoint',
            'userinfo_endpoint',
            'jwks_uri',
        ];

        foreach ($required as $field) {
            if (empty($payload[$field]) || ! is_string($payload[$field])) {
                throw new DiscoveryFailedException(
                    "Discovery document is missing required field: {$field}"
                );
            }
        }

        return new self(
            issuer: $payload['issuer'],
            authorizationEndpoint: $payload['authorization_endpoint'],
            tokenEndpoint: $payload['token_endpoint'],
            userinfoEndpoint: $payload['userinfo_endpoint'],
            jwksUri: $payload['jwks_uri'],
            endSessionEndpoint: isset($payload['end_session_endpoint']) && is_string($payload['end_session_endpoint'])
                ? $payload['end_session_endpoint']
                : null,
            supportedScopes: self::asStringList($payload['scopes_supported'] ?? []),
            supportedClaims: self::asStringList($payload['claims_supported'] ?? []),
            idTokenSigningAlgValuesSupported: self::asStringList(
                $payload['id_token_signing_alg_values_supported'] ?? []
            ),
        );
    }

    /**
     * @param  mixed  $value
     * @return array<int, string>
     */
    private static function asStringList($value): array
    {
        if (! is_array($value)) {
            return [];
        }

        return array_values(array_map('strval', $value));
    }
}
