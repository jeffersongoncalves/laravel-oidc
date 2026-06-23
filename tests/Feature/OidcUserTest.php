<?php

declare(strict_types=1);

use JeffersonGoncalves\LaravelOidc\Data\OidcUser;
use Laravel\Socialite\Two\User as SocialiteUser;

it('is a Socialite user', function () {
    expect(new OidcUser)->toBeInstanceOf(SocialiteUser::class);
});

it('stores the id_token and its claims', function () {
    $user = new OidcUser;

    $claims = ['sub' => 'user-1', 'email' => 'jane@example.com'];

    $returned = $user->setIdToken('header.payload.signature')->setIdTokenClaims($claims);

    expect($returned)->toBe($user)
        ->and($user->idToken)->toBe('header.payload.signature')
        ->and($user->idTokenClaims)->toBe($claims);
});

it('defaults to a null id_token and empty claims', function () {
    $user = new OidcUser;

    expect($user->idToken)->toBeNull()
        ->and($user->idTokenClaims)->toBe([]);
});

it('accepts a null id_token', function () {
    $user = (new OidcUser)->setIdToken('something')->setIdToken(null);

    expect($user->idToken)->toBeNull();
});
