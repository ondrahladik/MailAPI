<?php
declare(strict_types=1);

use MailApi\Admin;
use MailApi\Api;
use MailApi\Http;

try {
    require __DIR__ . '/src/bootstrap.php';

    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
    $scriptName = str_replace('\\', '/', $_SERVER['SCRIPT_NAME'] ?? '/index.php');
    $basePath = rtrim(str_replace('\\', '/', dirname($scriptName)), '/');
    $basePath = $basePath === '.' ? '' : $basePath;
    if (preg_match('~^(.*?)/(admin|send)(?:/|$)~', $path, $routeMatch) === 1) {
        $basePath = $routeMatch[1];
    }
    Http::setBasePath($basePath);

    if ($basePath !== '' && ($path === $basePath || str_starts_with($path, $basePath . '/'))) {
        $path = substr($path, strlen($basePath)) ?: '/';
    }
    $path = rtrim($path, '/') ?: '/';
    $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

    if ($path === '/' && $method === 'GET') {
        Http::adminRedirect('/admin');
    }

    if ($path === '/send') {
        if ($method !== 'POST') {
            Http::jsonError(405, 'method_not_allowed', 'Use the POST method.', ['Allow' => 'POST']);
        }
        (new Api())->send();
    }

    if ($path === '/admin' || str_starts_with($path, '/admin/')) {
        (new Admin())->handle($path, $method);
    }

    Http::jsonError(404, 'not_found', 'The requested path was not found.');
} catch (Throwable $exception) {
    error_log('[mail-api] ' . $exception::class . ': ' . $exception->getMessage());
    if (!headers_sent()) {
        Http::jsonError(500, 'internal_error', 'The request could not be processed.');
    }
}
