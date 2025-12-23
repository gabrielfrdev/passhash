<?php

declare(strict_types=1);

namespace PassHash\Exception;

use RuntimeException;

class HasherException extends RuntimeException
{
}
class WeakPasswordException extends HasherException
{
}
class InvalidConfigurationException extends HasherException
{
}
