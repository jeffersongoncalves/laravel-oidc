<?php

declare(strict_types=1);

namespace JeffersonGoncalves\LaravelOidc\Data;

final readonly class OidcConfig
{
    /**
     * @param  array<int, string>  $scopes
     */
    public function __construct(
        public string $issuerUrl,
        public string $clientId,
        public string $clientSecret,
        public string $redirectUri,
        public array $scopes = ['openid', 'email', 'profile'],
        public bool $usePkce = true,
        public int $clockSkewSeconds = 60,
    ) {}

    /**
     * @param  array<string, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        $scopes = $data['scopes'] ?? ['openid', 'email', 'profile'];

        if (! is_array($scopes)) {
            $scopes = ['openid', 'email', 'profile'];
        }

        return new self(
            issuerUrl: (string) ($data['issuer_url'] ?? ''),
            clientId: (string) ($data['client_id'] ?? ''),
            clientSecret: (string) ($data['client_secret'] ?? ''),
            redirectUri: (string) ($data['redirect_uri'] ?? ''),
            scopes: array_values(array_map('strval', $scopes)),
            usePkce: (bool) ($data['use_pkce'] ?? true),
            clockSkewSeconds: (int) ($data['clock_skew_seconds'] ?? 60),
        );
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'issuer_url' => $this->issuerUrl,
            'client_id' => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri' => $this->redirectUri,
            'scopes' => $this->scopes,
            'use_pkce' => $this->usePkce,
            'clock_skew_seconds' => $this->clockSkewSeconds,
        ];
    }
}
