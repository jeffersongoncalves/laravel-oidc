<?php

declare(strict_types=1);

namespace JeffersonGoncalves\LaravelOidc\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\MorphTo;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $authenticatable_type
 * @property int|string $authenticatable_id
 * @property string $issuer
 * @property string $subject
 * @property string|null $email
 * @property string|null $name
 * @property array<string, mixed>|null $claims
 * @property string|null $id_token
 * @property string|null $access_token
 * @property string|null $refresh_token
 * @property Carbon|null $expires_at
 * @property Carbon $created_at
 * @property Carbon $updated_at
 */
class OidcIdentity extends Model
{
    protected $guarded = [];

    /**
     * @var list<string>
     */
    protected $hidden = [
        'id_token',
        'access_token',
        'refresh_token',
    ];

    public function getTable(): string
    {
        return (string) config('oidc.identities_table', 'oidc_identities');
    }

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'claims' => 'array',
            'expires_at' => 'datetime',
        ];
    }

    /**
     * @return MorphTo<Model, $this>
     */
    public function authenticatable(): MorphTo
    {
        return $this->morphTo();
    }
}
