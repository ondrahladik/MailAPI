<?php
declare(strict_types=1);

namespace MailApi;

use RuntimeException;

final class SecretCipher
{
    public static function encrypt(string $plaintext): string
    {
        $nonce = random_bytes(12);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            self::key(),
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            '',
            16
        );
        if ($ciphertext === false || strlen($tag) !== 16) {
            throw new RuntimeException('The SMTP password could not be encrypted.');
        }
        return base64_encode($nonce . $tag . $ciphertext);
    }

    public static function decrypt(string $encoded): string
    {
        $payload = base64_decode($encoded, true);
        if ($payload === false || strlen($payload) < 29) {
            throw new RuntimeException('The stored SMTP password has an invalid format.');
        }

        $plaintext = openssl_decrypt(
            substr($payload, 28),
            'aes-256-gcm',
            self::key(),
            OPENSSL_RAW_DATA,
            substr($payload, 0, 12),
            substr($payload, 12, 16),
            ''
        );
        if ($plaintext === false) {
            throw new RuntimeException('The SMTP password could not be decrypted. Check smtp_encryption_key in the configuration.');
        }
        return $plaintext;
    }

    private static function key(): string
    {
        $encoded = Config::get('smtp_encryption_key');
        $key = is_string($encoded) ? base64_decode($encoded, true) : false;
        if ($key === false || strlen($key) !== 32) {
            throw new RuntimeException('smtp_encryption_key must be a Base64-encoded key of exactly 32 bytes.');
        }
        return $key;
    }
}
