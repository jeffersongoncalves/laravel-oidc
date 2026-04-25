<?php

declare(strict_types=1);

namespace JeffersonGoncalves\LaravelOidc\Data;

use Laravel\Socialite\Two\User as SocialiteUser;

class OidcUser extends SocialiteUser
{
    public ?string $idToken = null;

    /**
     * @var array<string, mixed>
     */
    public array $idTokenClaims = [];

    public function setIdToken(?string $idToken): self
    {
        $this->idToken = $idToken;

        return $this;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function setIdTokenClaims(array $claims): self
    {
        $this->idTokenClaims = $claims;

        return $this;
    }
}
