<?php

declare(strict_types=1);

namespace JeffersonGoncalves\LaravelOidc\Tests\Support;

use Firebase\JWT\JWT;
use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * Test-only helper that generates an in-memory RSA key pair, signs JWTs with it
 * and exposes a JWKS document derived from the public key. Lets tests run
 * without bundling pre-generated keys.
 */
final class RsaKeyset
{
    public string $kid;

    public OpenSSLAsymmetricKey $privateKey;

    /**
     * @var array{n: string, e: string}
     */
    public array $publicComponents;

    private function __construct(OpenSSLAsymmetricKey $privateKey, string $kid, array $publicComponents)
    {
        $this->privateKey = $privateKey;
        $this->kid = $kid;
        $this->publicComponents = $publicComponents;
    }

    public static function generate(string $kid = 'test-key'): self
    {
        $options = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        $configPath = __DIR__.DIRECTORY_SEPARATOR.'openssl.cnf';

        if (is_file($configPath)) {
            $options['config'] = $configPath;
        }

        $resource = @openssl_pkey_new($options);

        if ($resource === false) {
            $errors = [];
            while (($error = openssl_error_string()) !== false) {
                $errors[] = $error;
            }

            throw new RuntimeException(
                'Failed to generate RSA test key: '.implode('; ', $errors)
            );
        }

        $details = openssl_pkey_get_details($resource);

        if ($details === false || ! isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new RuntimeException('Failed to extract RSA key details.');
        }

        return new self(
            $resource,
            $kid,
            [
                'n' => self::base64UrlEncode($details['rsa']['n']),
                'e' => self::base64UrlEncode($details['rsa']['e']),
            ],
        );
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    public function sign(array $claims, string $alg = 'RS256'): string
    {
        return JWT::encode($claims, $this->privateKey, $alg, $this->kid);
    }

    /**
     * @return array{keys: array<int, array<string, string>>}
     */
    public function jwks(): array
    {
        return [
            'keys' => [
                [
                    'kty' => 'RSA',
                    'use' => 'sig',
                    'alg' => 'RS256',
                    'kid' => $this->kid,
                    'n' => $this->publicComponents['n'],
                    'e' => $this->publicComponents['e'],
                ],
            ],
        ];
    }

    private static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
