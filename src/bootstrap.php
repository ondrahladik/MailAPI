<?php
declare(strict_types=1);

namespace MailApi;

use RuntimeException;

spl_autoload_register(static function (string $class): void {
    $prefix = __NAMESPACE__ . '\\';
    if (str_starts_with($class, $prefix)) {
        $file = __DIR__ . '/' . substr($class, strlen($prefix)) . '.php';
        if (is_file($file)) {
            require $file;
        }
    }
});

$configPath = getenv('MAIL_API_CONFIG')
    ?: dirname(__DIR__) . DIRECTORY_SEPARATOR . 'config.php';
if (!is_file($configPath)) {
    throw new RuntimeException('Configuration file not found: ' . $configPath);
}

$config = require $configPath;
if (!is_array($config)) {
    throw new RuntimeException('The configuration file must return a PHP array.');
}

if (is_file(dirname(__DIR__) . '/vendor/autoload.php')) {
    require dirname(__DIR__) . '/vendor/autoload.php';
}

Config::set($config);

if (PHP_SAPI !== 'cli' && session_status() !== PHP_SESSION_ACTIVE) {
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_set_cookie_params([
        'httponly' => true,
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'samesite' => 'Strict',
        'path' => '/',
    ]);
    session_start();
}
