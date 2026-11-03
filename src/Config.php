<?php
declare(strict_types=1);

namespace MailApi;

use RuntimeException;

final class Config
{
    private static array $values;

    public static function set(array $values): void
    {
        self::$values = $values;
    }

    public static function get(string $key): mixed
    {
        if (!isset(self::$values[$key])) {
            throw new RuntimeException('Missing configuration value: ' . $key);
        }
        return self::$values[$key];
    }

    public static function adminEnabled(): bool
    {
        $hash = self::$values['admin_password_hash'] ?? '';
        return is_string($hash) && $hash !== '' && $hash !== 'REPLACE_WITH_PASSWORD_HASH';
    }
}
