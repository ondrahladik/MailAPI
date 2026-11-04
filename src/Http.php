<?php
declare(strict_types=1);

namespace MailApi;

use RuntimeException;

final class Http
{
    private static string $basePath = '';

    public static function setBasePath(string $basePath): void
    {
        self::$basePath = $basePath === '/' ? '' : rtrim($basePath, '/');
    }

    public static function url(string $path): string
    {
        return self::$basePath . '/' . ltrim($path, '/');
    }

    public static function withBasePath(string $html): string
    {
        if (self::$basePath === '') {
            return $html;
        }

        return preg_replace_callback(
            '~(["\'])/(admin|assets|send)(?=[/?#"\'])~',
            static fn (array $matches): string => $matches[1] . self::$basePath . '/' . $matches[2],
            $html
        ) ?? $html;
    }

    public static function jsonError(int $status, string $code, string $message, array $headers = []): void
    {
        self::json($status, ['success' => false, 'error' => ['code' => $code, 'message' => $message]], $headers);
    }

    public static function json(int $status, array $payload, array $headers = []): void
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        header('Cache-Control: no-store');
        header('X-Content-Type-Options: nosniff');
        foreach ($headers as $name => $value) {
            header($name . ': ' . $value);
        }
        echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        exit;
    }

    public static function requestJson(): array
    {
        $length = (int) ($_SERVER['CONTENT_LENGTH'] ?? 0);
        if ($length > 65536) {
            self::jsonError(413, 'payload_too_large', 'The request body exceeds the 64 KiB limit.');
        }
        $contentType = strtolower(trim(explode(';', $_SERVER['CONTENT_TYPE'] ?? '')[0]));
        if ($contentType !== 'application/json') {
            self::jsonError(415, 'unsupported_media_type', 'Content-Type: application/json is required.');
        }
        $raw = file_get_contents('php://input');
        if ($raw === false || strlen($raw) > 65536) {
            self::jsonError(413, 'payload_too_large', 'The request body exceeds the 64 KiB limit.');
        }
        try {
            $data = json_decode($raw, false, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            self::jsonError(400, 'invalid_json', 'The request body does not contain valid JSON.');
        }
        if (!$data instanceof \stdClass) {
            self::jsonError(400, 'invalid_json', 'The JSON body must be an object.');
        }
        return get_object_vars($data);
    }

    public static function escape(string|null $value): string
    {
        return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    public static function adminRedirect(string $path): void
    {
        header('Location: ' . self::url($path), true, 303);
        exit;
    }
}
