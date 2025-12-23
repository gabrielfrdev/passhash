<?php

declare(strict_types=1);

namespace PassHash\Console;

use PassHash\Hasher;
use PassHash\Exception\HasherException;
use Throwable;

class CLI
{
    public function run(array $argv): void
    {
        try {
            array_shift($argv);
            $command = $argv[0] ?? null;

            if (!$command) {
                $this->showHelp();
                exit(0);
            }

            if ($command === 'hash') {
                $this->handleHash($argv);
            } elseif ($command === 'verify') {
                $this->handleVerify($argv);
            } elseif ($command === 'config') {
                $this->handleConfig();
            } else {
                fwrite(STDERR, "\033[1;31mError:\033[0m Unknown command '$command'\n");
                exit(1);
            }
        } catch (HasherException $e) {
            fwrite(STDERR, "\033[1;31mSecurity Error:\033[0m " . $e->getMessage() . "\n");
            exit(1);
        } catch (Throwable $e) {
            $isVerbose = in_array('--verbose', $argv, true) || in_array('-v', $argv, true);

            fwrite(STDERR, "\033[1;31mCritical Error:\033[0m An unexpected internal error occurred.\n");

            if ($isVerbose) {
                fwrite(STDERR, "\n\033[1;30mDebug Details:\033[0m\n");
                fwrite(STDERR, "Message: " . $e->getMessage() . "\n");
                fwrite(STDERR, "File: " . $e->getFile() . ":" . $e->getLine() . "\n");
                fwrite(STDERR, "Trace:\n" . $e->getTraceAsString() . "\n");
            } else {
                fwrite(STDERR, "Use --verbose to see technical details.\n");
            }
            exit(1);
        }
    }

    private function handleHash(array $args): void
    {
        if (isset($args[1])) {
            fwrite(STDERR, "\033[1;31mSECURITY WARNING:\033[0m Passing passwords as arguments is UNSAFE and blocked.\n");
            fwrite(STDERR, "Please use STDIN (pipes) or interactive mode to prevent history leakage.\n\n");
            fwrite(STDERR, "Correct usage:\n");
            fwrite(STDERR, "  Interactive: \033[32mphp bin/passhash hash\033[0m\n");
            fwrite(STDERR, "  Pipe:        \033[32mecho \"mypass\" | php bin/passhash hash\033[0m\n");
            exit(1);
        }

        $password = $this->getPassword();

        if (empty($password)) {
            fwrite(STDERR, "Error: Password cannot be empty.\n");
            exit(1);
        }

        $result = Hasher::hash($password);

        echo "\033[1;32m✔\033[0m Hash generated securely.\n\n";
        echo "\033[1mAlgorithm:\033[0m {$result['algorithm']}\n";
        echo "\033[1mHash:\033[0m\n{$result['hash']}\n";
    }

    private function handleVerify(array $args): void
    {
        $hash = $args[1] ?? null;

        if (!$hash) {
            fwrite(STDERR, "Error: Hash argument required.\n");
            fwrite(STDERR, "Usage: passhash verify <hash>\n");
            exit(1);
        }

        if (isset($args[2])) {
            fwrite(STDERR, "\033[1;33mWarning:\033[0m Extra arguments ignored. Ensure you didn't type the password.\n");
        }

        echo "\033[1;34mInfo:\033[0m Please enter the password to verify.\n";
        $password = $this->getPassword("Password: ");

        if (Hasher::verify($password, $hash)) {
            echo "\033[1;32m✔ MATCH\033[0m Password is valid.\n";
            exit(0);
        } else {
            echo "\033[1;31m✖ MISMATCH\033[0m Invalid password.\n";
            exit(1);
        }
    }

    private function handleConfig(): void
    {
        $config = Hasher::config();
        echo "\033[1;36mCurrent Security Configuration:\033[0m\n\n";
        echo "Algorithm:   {$config['name']}\n";
        foreach ($config['options'] as $key => $val) {
            echo str_pad($key . ":", 15) . $val . "\n";
        }
    }

    private function getPassword(string $prompt = "Enter Password: "): string
    {
        if (function_exists('posix_isatty') && !posix_isatty(STDIN)) {
            return rtrim(file_get_contents('php://stdin'), "\r\n");
        }

        echo "\033[1m$prompt\033[0m";

        $password = '';
        if (strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN') {
            $oldStyle = shell_exec('stty -g');
            shell_exec('stty -echo');
            $password = rtrim(fgets(STDIN), "\r\n");
            shell_exec("stty $oldStyle");
            echo "\n";
        } else {
            if (DIRECTORY_SEPARATOR === '\\') {
                echo "\n\033[1;33m[SECURITY NOTICE] Input might be visible on Windows terminals.\033[0m";
                echo "\n\033[0;33mSuggestion: Use WSL or PowerShell 'Read-Host -AsSecureString' via pipe for better security.\033[0m\n";
            }
            $password = rtrim(fgets(STDIN), "\r\n");
        }

        return $password;
    }

    private function showHelp(): void
    {
        $version = 'v1.0.0';
        try {
            if (class_exists('\Composer\InstalledVersions')) {
                $version = \Composer\InstalledVersions::getPrettyVersion('gabrielfrdev/secure-passhash') ?? $version;
            }
        } catch (Throwable $e) {
        }

        echo <<<HELP
\033[1;36mPassHash CLI\033[0m $version (Secure Mode)

\033[1mCommands:\033[0m
  hash        Generate secure hash (Interactive/Pipe only)
  verify      Verify a hash (Interactive/Pipe only)
  config      Show security parameters

\033[1mOptions:\033[0m
  --verbose, -v  Show detailed error messages (Debug mode)

\033[1mUsage Examples:\033[0m
  passhash hash
  echo "secret" | passhash hash
  passhash verify '\$argon2id\$...'

\033[1;30mReplace 'passhash' with './bin/passhash' or 'vendor/bin/passhash' based on your install.\033[0m

HELP;
    }
}
