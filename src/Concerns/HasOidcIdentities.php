<?php

declare(strict_types=1);

namespace JeffersonGoncalves\LaravelOidc\Concerns;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphMany;
use JeffersonGoncalves\LaravelOidc\Models\OidcIdentity;

/**
 * @mixin Model
 */
trait HasOidcIdentities
{
    /**
     * @return MorphMany<OidcIdentity, $this>
     */
    public function oidcIdentities(): MorphMany
    {
        return $this->morphMany(OidcIdentity::class, 'authenticatable');
    }
}
