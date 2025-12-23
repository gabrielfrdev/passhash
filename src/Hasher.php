<?php

declare(strict_types=1);

namespace PassHash;

use PassHash\Exception\HasherException;
use PassHash\Exception\InvalidConfigurationException;
use PassHash\Exception\WeakPasswordException;

class Hasher
{
    private const MIN_MEMORY_COST = 65536;
    private const MAX_MEMORY_COST = 524288;

    private const MIN_TIME_COST = 4;
    private const MAX_TIME_COST = 100;

    private const MIN_THREADS = 1;
    private const MAX_THREADS = 8;

    private const MIN_BCRYPT_COST = 10;
    private const MAX_BCRYPT_COST = 20;

    public static function config(): array
    {
        if (defined('PASSWORD_ARGON2ID')) {
            return [
                'algo' => PASSWORD_ARGON2ID,
                'name' => 'Argon2id',
                'options' => [
                    'memory_cost' => self::MIN_MEMORY_COST,
                    'time_cost' => self::MIN_TIME_COST,
                    'threads' => 1,
                ],
            ];
        }

        return [
            'algo' => PASSWORD_BCRYPT,
            'name' => 'Bcrypt',
            'options' => [
                'cost' => 12,
            ],
        ];
    }

    public static function hash(string $password, array $options = []): array
    {
        if (empty($password)) {
            throw new WeakPasswordException('Password cannot be empty.');
        }

        if (strlen($password) > 4096) {
            throw new HasherException('Password is too long (Max 4096 bytes).');
        }

        $defaultConfig = self::config();

        $mergedOptions = $options + $defaultConfig['options'];
        $algo = $defaultConfig['algo'];

        if ($algo === PASSWORD_ARGON2ID) {
            self::validateArgonParameters($mergedOptions);
        } elseif ($algo === PASSWORD_BCRYPT) {
            self::validateBcryptParameters($mergedOptions);
        }

        $hash = password_hash($password, $algo, $mergedOptions);

        if ($hash === false) {
            throw new HasherException('Failed to generate password hash. Internal error.');
        }

        return [
            'algorithm' => $defaultConfig['name'],
            'hash' => $hash,
        ];
    }

    public static function verify(string $password, string $hash): bool
    {
        if (empty($password) || empty($hash)) {
            return false;
        }

        if (strlen($hash) < 13) {
            return false;
        }

        return password_verify($password, $hash);
    }

    private static function validateArgonParameters(array $options): void
    {
        $mem = $options['memory_cost'] ?? 0;
        $time = $options['time_cost'] ?? 0;
        $threads = $options['threads'] ?? 1;

        if ($mem < self::MIN_MEMORY_COST) {
            throw new InvalidConfigurationException("Memory cost too low. Minimum required: " . self::MIN_MEMORY_COST . " KiB (64 MiB).");
        }
        if ($mem > self::MAX_MEMORY_COST) {
            throw new InvalidConfigurationException("Memory cost too high (DoS protection).");
        }

        if ($time < self::MIN_TIME_COST) {
            throw new InvalidConfigurationException("Time cost too low. Minimum: " . self::MIN_TIME_COST);
        }
        if ($time > self::MAX_TIME_COST) {
            throw new InvalidConfigurationException("Time cost too high.");
        }

        if ($threads < self::MIN_THREADS || $threads > self::MAX_THREADS) {
            throw new InvalidConfigurationException("Threads must be between " . self::MIN_THREADS . " and " . self::MAX_THREADS);
        }
    }

    private static function validateBcryptParameters(array $options): void
    {
        $cost = $options['cost'] ?? 0;
        if ($cost < self::MIN_BCRYPT_COST) {
            throw new InvalidConfigurationException("Bcrypt cost too low. Minimum: " . self::MIN_BCRYPT_COST);
        }
        if ($cost > self::MAX_BCRYPT_COST) {
            throw new InvalidConfigurationException("Bcrypt cost too high. Maximum: " . self::MAX_BCRYPT_COST);
        }
    }
}
