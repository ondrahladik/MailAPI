<?php

return [
    'database' => [
        'host' => '127.0.0.1',
        'port' => 3306,
        'name' => 'mail_api',
        'username' => 'mail_api_user',
        'password' => 'CHANGE_THIS_DATABASE_PASSWORD',
    ],
    'smtp_encryption_key' => 'GENERATE_A_BASE64_ENCODED_32_BYTE_KEY',
    'admin_password_hash' => 'REPLACE_WITH_PASSWORD_HASH',
    'rate_limit_per_minute' => 30,
];
