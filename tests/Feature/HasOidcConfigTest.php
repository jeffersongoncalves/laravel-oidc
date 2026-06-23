<?php

declare(strict_types=1);

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use JeffersonGoncalves\LaravelOidc\Data\OidcConfig;
use JeffersonGoncalves\LaravelOidc\Tests\Support\OidcConnection;

beforeEach(function () {
    Schema::create('oidc_connections', function (Blueprint $table) {
        $table->increments('id');
        $table->string('issuer_url');
        $table->string('client_id');
        $table->text('client_secret');
        $table->string('redirect_uri');
        $table->text('scopes')->nullable();
    });
});

afterEach(function () {
    Schema::dropIfExists('oidc_connections');
});

it('encrypts the client secret at rest and decrypts it on read', function () {
    $model = OidcConnection::create([
        'issuer_url' => 'https://idp.example.com',
        'client_id' => 'client-abc',
        'client_secret' => 'top-secret',
        'redirect_uri' => 'https://app.example.com/callback',
        'scopes' => ['openid', 'email'],
    ]);

    $rawSecret = DB::table('oidc_connections')->where('id', $model->id)->value('client_secret');

    expect($rawSecret)->not->toBe('top-secret')
        ->and(Crypt::decryptString($rawSecret))->toBe('top-secret')
        ->and($model->fresh()->client_secret)->toBe('top-secret');
});

it('casts scopes to an array', function () {
    $model = OidcConnection::create([
        'issuer_url' => 'https://idp.example.com',
        'client_id' => 'client-abc',
        'client_secret' => 'top-secret',
        'redirect_uri' => 'https://app.example.com/callback',
        'scopes' => ['openid', 'profile'],
    ]);

    expect($model->fresh()->scopes)->toBe(['openid', 'profile']);
});

it('builds an OidcConfig from the model attributes', function () {
    $model = OidcConnection::create([
        'issuer_url' => 'https://idp.example.com',
        'client_id' => 'client-abc',
        'client_secret' => 'top-secret',
        'redirect_uri' => 'https://app.example.com/callback',
        'scopes' => ['openid', 'email', 'profile'],
    ]);

    $config = $model->toOidcConfig();

    expect($config)->toBeInstanceOf(OidcConfig::class)
        ->and($config->issuerUrl)->toBe('https://idp.example.com')
        ->and($config->clientId)->toBe('client-abc')
        ->and($config->clientSecret)->toBe('top-secret')
        ->and($config->redirectUri)->toBe('https://app.example.com/callback')
        ->and($config->scopes)->toBe(['openid', 'email', 'profile']);
});

it('falls back to default scopes when none are stored', function () {
    $model = OidcConnection::create([
        'issuer_url' => 'https://idp.example.com',
        'client_id' => 'client-abc',
        'client_secret' => 'top-secret',
        'redirect_uri' => 'https://app.example.com/callback',
        'scopes' => null,
    ]);

    expect($model->fresh()->toOidcConfig()->scopes)->toBe(['openid', 'email', 'profile']);
});
