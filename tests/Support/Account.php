<?php

declare(strict_types=1);

namespace JeffersonGoncalves\LaravelOidc\Tests\Support;

use Illuminate\Database\Eloquent\Model;
use JeffersonGoncalves\LaravelOidc\Concerns\HasOidcIdentities;

class Account extends Model
{
    use HasOidcIdentities;

    protected $guarded = [];

    public $timestamps = false;
}
