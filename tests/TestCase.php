<?php

declare(strict_types=1);

namespace JeffersonGoncalves\LaravelOidc\Tests;

use JeffersonGoncalves\LaravelOidc\OidcServiceProvider;
use Laravel\Socialite\SocialiteServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            SocialiteServiceProvider::class,
            OidcServiceProvider::class,
        ];
    }

    public function getEnvironmentSetUp($app): void
    {
        config()->set('database.default', 'testing');
        config()->set('cache.default', 'array');
        config()->set('session.driver', 'array');
    }
}
