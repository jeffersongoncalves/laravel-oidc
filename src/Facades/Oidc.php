<?php

declare(strict_types=1);

namespace JeffersonGoncalves\LaravelOidc\Facades;

use Illuminate\Support\Facades\Facade;
use JeffersonGoncalves\LaravelOidc\Services\OidcDiscoveryService;

/**
 * @method static \JeffersonGoncalves\LaravelOidc\Data\OidcDiscoveryDocument discover(string $issuerUrl)
 * @method static array<string, mixed> getJwks(string $jwksUri)
 * @method static void clearCache(string $issuerUrl)
 *
 * @see OidcDiscoveryService
 */
class Oidc extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return OidcDiscoveryService::class;
    }
}
