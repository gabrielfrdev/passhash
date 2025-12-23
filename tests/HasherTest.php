<?php

declare(strict_types=1);

namespace PassHash\Tests;

use PHPUnit\Framework\TestCase;
use PassHash\Hasher;
use PassHash\Exception\WeakPasswordException;
use PassHash\Exception\InvalidConfigurationException;
use PassHash\Exception\HasherException;

class HasherTest extends TestCase
{
    public function testHashGeneratesValidArray(): void
    {
        $result = Hasher::hash('password123');

        $this->assertIsArray($result);
        $this->assertArrayHasKey('algorithm', $result);
        $this->assertArrayHasKey('hash', $result);
        $this->assertNotEmpty($result['hash']);
    }

    public function testHashThrowsExceptionForEmptyPassword(): void
    {
        $this->expectException(WeakPasswordException::class);
        Hasher::hash('');
    }

    public function testThrowsExceptionForVeryLongPassword(): void
    {
        $this->expectException(HasherException::class);
        $this->expectExceptionMessage('Password is too long');
        $password = str_repeat('a', 5000);
        Hasher::hash($password);
    }

    public function testVerifyReturnsTrueForCorrectPassword(): void
    {
        $password = 'securepassword';
        $result = Hasher::hash($password);
        $hash = $result['hash'];

        $this->assertTrue(Hasher::verify($password, $hash));
    }

    public function testVerifyReturnsFalseForIncorrectPassword(): void
    {
        $password = 'securepassword';
        $result = Hasher::hash($password);
        $hash = $result['hash'];

        $this->assertFalse(Hasher::verify('wrongpassword', $hash));
    }

    public function testVerifyReturnsFalseForInvalidHash(): void
    {
        $this->assertFalse(Hasher::verify('password', 'invalidhash'));
        $this->assertFalse(Hasher::verify('password', ''));
    }

    public function testConfigReturnsValidOptions(): void
    {
        $config = Hasher::config();

        $this->assertIsArray($config);
        $this->assertArrayHasKey('algo', $config);
        $this->assertArrayHasKey('name', $config);
        $this->assertArrayHasKey('options', $config);
    }

    public function testThrowsExceptionForInsecureMemoryCost(): void
    {
        if (!defined('PASSWORD_ARGON2ID')) {
            $this->markTestSkipped('Argon2id not supported');
        }

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('Memory cost too low');

        Hasher::hash('password', ['memory_cost' => 1024]);
    }

    public function testThrowsExceptionForInvalidThreads(): void
    {
        if (!defined('PASSWORD_ARGON2ID')) {
            $this->markTestSkipped('Argon2id not supported');
        }

        $this->expectException(InvalidConfigurationException::class);
        $this->expectExceptionMessage('Threads must be between');

        Hasher::hash('password', ['threads' => 0]);
    }
}
