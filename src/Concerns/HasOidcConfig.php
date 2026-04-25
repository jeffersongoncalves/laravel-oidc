<?php

declare(strict_types=1);

namespace JeffersonGoncalves\LaravelOidc\Concerns;

use JeffersonGoncalves\LaravelOidc\Data\OidcConfig;

/**
 * @property string $issuer_url
 * @property string $client_id
 * @property string $client_secret
 * @property string $redirect_uri
 * @property array<int, string>|null $scopes
 */
trait HasOidcConfig
{
    public function toOidcConfig(): OidcConfig
    {
        $scopes = $this->scopes;

        return new OidcConfig(
            issuerUrl: (string) $this->issuer_url,
            clientId: (string) $this->client_id,
            clientSecret: (string) $this->client_secret,
            redirectUri: (string) $this->redirect_uri,
            scopes: is_array($scopes) && $scopes !== []
                ? array_values(array_map('strval', $scopes))
                : ['openid', 'email', 'profile'],
        );
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        $parentCasts = method_exists(get_parent_class($this) ?: '', 'casts')
            ? parent::casts()
            : [];

        return array_merge($parentCasts, [
            'client_secret' => 'encrypted',
            'scopes' => 'array',
        ]);
    }
}
