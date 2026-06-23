<?php

declare(strict_types=1);

namespace JeffersonGoncalves\LaravelOidc\Tests\Support;

use Illuminate\Database\Eloquent\Model;
use JeffersonGoncalves\LaravelOidc\Concerns\HasOidcConfig;

/**
 * Test-only Eloquent model that exercises the HasOidcConfig trait, including
 * its encrypted/array casts and the toOidcConfig() factory.
 *
 * @property string $issuer_url
 * @property string $client_id
 * @property string $client_secret
 * @property string $redirect_uri
 * @property array<int, string>|null $scopes
 */
class OidcConnection extends Model
{
    use HasOidcConfig;

    protected $table = 'oidc_connections';

    public $timestamps = false;

    protected $guarded = [];
}
