<?php

declare(strict_types=1);

namespace JeffersonGoncalves\LaravelOidc;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use JeffersonGoncalves\LaravelOidc\Data\OidcConfig;
use JeffersonGoncalves\LaravelOidc\Providers\GenericOidcProvider;
use JeffersonGoncalves\LaravelOidc\Services\JwtValidator;
use JeffersonGoncalves\LaravelOidc\Services\OidcDiscoveryService;
use Laravel\Socialite\Contracts\Factory as SocialiteFactory;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class OidcServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('laravel-oidc')
            ->hasConfigFile('oidc');
    }

    public function packageRegistered(): void
    {
        $this->app->singleton(OidcDiscoveryService::class);
        $this->app->singleton(JwtValidator::class);
    }

    public function packageBooted(): void
    {
        if (! $this->app->bound(SocialiteFactory::class)) {
            return;
        }

        $this->app->make(SocialiteFactory::class)->extend(
            'oidc',
            function (Application $app): GenericOidcProvider {
                /** @var ConfigRepository $config */
                $config = $app->make(ConfigRepository::class);
                /** @var Request $request */
                $request = $app->make(Request::class);

                /** @var array<string, mixed> $defaults */
                $defaults = (array) $config->get('oidc.default', []);

                $provider = new GenericOidcProvider(
                    $request,
                    (string) ($defaults['client_id'] ?? ''),
                    (string) ($defaults['client_secret'] ?? ''),
                    (string) ($defaults['redirect_uri'] ?? ''),
                );

                if (! empty($defaults['issuer_url'])) {
                    $provider->setConfig(OidcConfig::fromArray($defaults));
                }

                return $provider;
            }
        );
    }
}
