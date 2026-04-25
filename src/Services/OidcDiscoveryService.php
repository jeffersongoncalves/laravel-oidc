<?php

declare(strict_types=1);

namespace JeffersonGoncalves\LaravelOidc\Services;

use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\PendingRequest;
use JeffersonGoncalves\LaravelOidc\Data\OidcDiscoveryDocument;
use JeffersonGoncalves\LaravelOidc\Exceptions\DiscoveryFailedException;
use JeffersonGoncalves\LaravelOidc\Exceptions\JwksFetchException;
use Throwable;

class OidcDiscoveryService
{
    public function __construct(
        protected HttpFactory $http,
        protected CacheFactory $cache,
        protected ConfigRepository $config,
    ) {}

    /**
     * Fetch and parse the OpenID Provider discovery document.
     *
     * @throws DiscoveryFailedException
     */
    public function discover(string $issuerUrl): OidcDiscoveryDocument
    {
        $url = $this->buildDiscoveryUrl($issuerUrl);
        $cacheKey = $this->discoveryCacheKey($issuerUrl);
        $ttl = (int) $this->config->get('oidc.cache.discovery_ttl', 3600);

        $payload = $this->cacheRepository()->remember(
            $cacheKey,
            $ttl,
            fn (): array => $this->fetchDiscoveryPayload($url),
        );

        return OidcDiscoveryDocument::fromArray($payload);
    }

    /**
     * Fetch the JWKS document, returning the raw decoded payload.
     *
     * @return array<string, mixed>
     *
     * @throws JwksFetchException
     */
    public function getJwks(string $jwksUri): array
    {
        $cacheKey = $this->jwksCacheKey($jwksUri);
        $ttl = (int) $this->config->get('oidc.cache.jwks_ttl', 21600);

        return $this->cacheRepository()->remember(
            $cacheKey,
            $ttl,
            fn (): array => $this->fetchJwksPayload($jwksUri),
        );
    }

    public function clearCache(string $issuerUrl): void
    {
        $cache = $this->cacheRepository();

        try {
            $document = $this->discover($issuerUrl);
            $cache->forget($this->jwksCacheKey($document->jwksUri));
        } catch (Throwable) {
            // Discovery may already be unavailable; we still clear what we can.
        }

        $cache->forget($this->discoveryCacheKey($issuerUrl));
    }

    /**
     * @return array<string, mixed>
     *
     * @throws DiscoveryFailedException
     */
    protected function fetchDiscoveryPayload(string $url): array
    {
        try {
            $response = $this->httpClient()->get($url);
        } catch (Throwable $e) {
            throw new DiscoveryFailedException(
                "Failed to fetch discovery document from {$url}: {$e->getMessage()}",
                previous: $e,
            );
        }

        if ($response->failed()) {
            throw new DiscoveryFailedException(
                "Discovery endpoint returned HTTP {$response->status()} for {$url}",
            );
        }

        try {
            $payload = $response->json();
        } catch (Throwable $e) {
            throw new DiscoveryFailedException(
                "Discovery endpoint returned invalid JSON: {$e->getMessage()}",
                previous: $e,
            );
        }

        if (! is_array($payload) || $payload === []) {
            throw new DiscoveryFailedException(
                "Discovery endpoint returned an empty or non-object payload for {$url}",
            );
        }

        return $payload;
    }

    /**
     * @return array<string, mixed>
     *
     * @throws JwksFetchException
     */
    protected function fetchJwksPayload(string $jwksUri): array
    {
        try {
            $response = $this->httpClient()->get($jwksUri);
        } catch (Throwable $e) {
            throw new JwksFetchException(
                "Failed to fetch JWKS from {$jwksUri}: {$e->getMessage()}",
                previous: $e,
            );
        }

        if ($response->failed()) {
            throw new JwksFetchException(
                "JWKS endpoint returned HTTP {$response->status()} for {$jwksUri}",
            );
        }

        try {
            $payload = $response->json();
        } catch (Throwable $e) {
            throw new JwksFetchException(
                "JWKS endpoint returned invalid JSON: {$e->getMessage()}",
                previous: $e,
            );
        }

        if (! is_array($payload) || empty($payload['keys'])) {
            throw new JwksFetchException(
                "JWKS endpoint returned an invalid payload (no 'keys' array) for {$jwksUri}",
            );
        }

        return $payload;
    }

    protected function httpClient(): PendingRequest
    {
        return $this->http
            ->timeout((int) $this->config->get('oidc.http.timeout', 5))
            ->connectTimeout((int) $this->config->get('oidc.http.connect_timeout', 3))
            ->acceptJson();
    }

    protected function cacheRepository(): CacheRepository
    {
        $store = $this->config->get('oidc.cache.store');

        return $store === null
            ? $this->cache->store()
            : $this->cache->store(is_string($store) ? $store : null);
    }

    protected function buildDiscoveryUrl(string $issuerUrl): string
    {
        $issuer = rtrim($issuerUrl, '/');

        if (str_ends_with($issuer, '/.well-known/openid-configuration')) {
            return $issuer;
        }

        return $issuer.'/.well-known/openid-configuration';
    }

    protected function discoveryCacheKey(string $issuerUrl): string
    {
        return 'oidc:discovery:'.hash('sha256', rtrim($issuerUrl, '/'));
    }

    protected function jwksCacheKey(string $jwksUri): string
    {
        return 'oidc:jwks:'.hash('sha256', $jwksUri);
    }
}
