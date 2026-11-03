<?php
declare(strict_types=1);

function prompt(string $label, string $default = ''): string
{
    $suffix = $default === '' ? '' : " [{$default}]";
    fwrite(STDOUT, $label . $suffix . ': ');
    $value = fgets(STDIN);
    if ($value === false) {
        throw new RuntimeException('Could not read input.');
    }
    $value = trim($value);
    return $value === '' ? $default : $value;
}

function promptSecret(string $label): string
{
    fwrite(STDOUT, $label . ': ');
    if (PHP_OS_FAMILY === 'Windows' && function_exists('shell_exec')) {
        $powershell = '$secret=Read-Host -AsSecureString;'
            . '$ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret);'
            . 'try{[Console]::Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('
            . '[Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr))))}'
            . 'finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)}';
        $encoded = shell_exec('powershell.exe -NoProfile -Command ' . escapeshellarg($powershell));
        if (is_string($encoded) && trim($encoded) !== '') {
            $decoded = base64_decode(trim($encoded), true);
            if ($decoded !== false) {
                fwrite(STDOUT, PHP_EOL);
                return $decoded;
            }
        }
        fwrite(STDERR, PHP_EOL . 'Secure password input failed; the password may be visible.' . PHP_EOL);
    } elseif (function_exists('shell_exec') && function_exists('stream_isatty') && stream_isatty(STDIN)) {
        $mode = trim((string) shell_exec('stty -g'));
        if ($mode !== '') {
            shell_exec('stty -echo');
            try {
                $value = fgets(STDIN);
            } finally {
                shell_exec('stty ' . escapeshellarg($mode));
                fwrite(STDOUT, PHP_EOL);
            }
            if ($value === false) {
                throw new RuntimeException('Could not read the password.');
            }
            return rtrim($value, "\r\n");
        }
    }

    fwrite(STDERR, 'Warning: password input may be visible in this terminal.' . PHP_EOL);
    $value = fgets(STDIN);
    if ($value === false) {
        throw new RuntimeException('Could not read the password.');
    }
    return rtrim($value, "\r\n");
}

try {
    $applicationRoot = realpath(dirname(__DIR__));
    if ($applicationRoot === false) {
        throw new RuntimeException('Could not determine the application directory.');
    }
    $defaultConfigPath = getenv('MAIL_API_CONFIG')
        ?: $applicationRoot . DIRECTORY_SEPARATOR . 'config.php';
    $configPath = prompt('Path to config.php', $defaultConfigPath);
    if (file_exists($configPath)) {
        throw new RuntimeException('The file already exists; the generator will not overwrite it.');
    }

    $databaseHost = prompt('Database host', '127.0.0.1');
    $databasePort = prompt('Database port', '3306');
    $databaseName = prompt('Database name', 'mail_api');
    $databaseUsername = prompt('Database username');
    $databasePassword = promptSecret('Database password');
    $adminPassword = promptSecret('New administrator password (at least 12 characters)');
    $adminPasswordConfirm = promptSecret('Confirm administrator password');

    if (!ctype_digit($databasePort) || (int) $databasePort < 1 || (int) $databasePort > 65535) {
        throw new RuntimeException('Database port must be a number from 1 to 65535.');
    }
    if (!preg_match('/^[A-Za-z0-9_]+$/', $databaseName)) {
        throw new RuntimeException('Database name may contain only letters, numbers, and underscores.');
    }
    if (strlen($adminPassword) < 12 || strlen($adminPassword) > 72
        || !hash_equals($adminPassword, $adminPasswordConfirm)) {
        throw new RuntimeException('Administrator passwords must match and be between 12 and 72 bytes long.');
    }

    $config = [
        'database' => [
            'host' => $databaseHost,
            'port' => (int) $databasePort,
            'name' => $databaseName,
            'username' => $databaseUsername,
            'password' => $databasePassword,
        ],
        'smtp_encryption_key' => base64_encode(random_bytes(32)),
        'admin_password_hash' => password_hash($adminPassword, PASSWORD_DEFAULT),
        'rate_limit_per_minute' => 30,
    ];

    $configDirectory = dirname($configPath);
    if (!is_dir($configDirectory) && !mkdir($configDirectory, 0700, true) && !is_dir($configDirectory)) {
        throw new RuntimeException('Could not create the configuration directory.');
    }
    $realDirectory = realpath($configDirectory);
    if ($realDirectory === false) {
        throw new RuntimeException('Could not resolve the configuration directory.');
    }
    $isWindows = PHP_OS_FAMILY === 'Windows';

    $temporaryPath = tempnam($realDirectory, '.mail-api-config-');
    if ($temporaryPath === false) {
        throw new RuntimeException('Could not create a temporary configuration file.');
    }
    try {
        $contents = "<?php\n\ndeclare(strict_types=1);\n\nreturn " . var_export($config, true) . ";\n";
        if (file_put_contents($temporaryPath, $contents, LOCK_EX) === false) {
            throw new RuntimeException('Could not write the configuration file.');
        }
        if (!$isWindows && !chmod($temporaryPath, 0600)) {
            throw new RuntimeException('Could not set configuration file permissions.');
        }
        if (!rename($temporaryPath, $configPath)) {
            throw new RuntimeException('Could not save the configuration file.');
        }
    } finally {
        if (file_exists($temporaryPath)) {
            unlink($temporaryPath);
        }
    }

    fwrite(STDOUT, 'Configuration created: ' . $configPath . PHP_EOL);
    fwrite(STDOUT, 'The encryption key and password hash are stored in this file.' . PHP_EOL);
    fwrite(STDOUT, 'Back up config.php securely; the generator will never overwrite it.' . PHP_EOL);
} catch (Throwable $exception) {
    fwrite(STDERR, 'Error: ' . $exception->getMessage() . PHP_EOL);
    exit(1);
}
