<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use JeffersonGoncalves\LaravelOidc\Models\OidcIdentity;
use JeffersonGoncalves\LaravelOidc\Tests\Support\Account;

beforeEach(function () {
    Schema::create('accounts', function (Blueprint $table) {
        $table->increments('id');
        $table->string('name');
    });

    (require __DIR__.'/../../database/migrations/create_oidc_identities_table.php.stub')->up();
});

afterEach(function () {
    Schema::dropIfExists('oidc_identities');
    Schema::dropIfExists('accounts');
});

it('links identities to an authenticatable through the trait', function () {
    $account = Account::create(['name' => 'Jane']);

    $identity = $account->oidcIdentities()->create([
        'issuer' => 'https://idp.example.com',
        'subject' => 'sub-123',
        'email' => 'jane@example.com',
        'claims' => ['sub' => 'sub-123'],
        'access_token' => 'secret-token',
        'expires_at' => now()->addHour(),
    ]);

    $fresh = OidcIdentity::query()->findOrFail($identity->id);

    expect($fresh->authenticatable)->toBeInstanceOf(Account::class)
        ->and($fresh->authenticatable->is($account))->toBeTrue()
        ->and($fresh->claims)->toBe(['sub' => 'sub-123'])
        ->and($fresh->toArray())->not->toHaveKey('access_token')
        ->and($account->oidcIdentities)->toHaveCount(1);
});

it('reads the table name from config', function () {
    config()->set('oidc.identities_table', 'sso_identities');

    expect((new OidcIdentity)->getTable())->toBe('sso_identities');
});
