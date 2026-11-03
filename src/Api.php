<?php
declare(strict_types=1);

namespace MailApi;

use PDO;

final class Api
{
    public function send(): void
    {
        $token = $this->bearerToken();
        $pdo = Database::connection();
        $statement = $pdo->prepare(
            'SELECT t.id AS token_id, t.application_id, a.default_to, a.smtp_server_id,
                    a.default_sender_id, default_sender.email AS default_sender_email
             FROM api_tokens t
             JOIN applications a ON a.id = t.application_id
             LEFT JOIN senders default_sender ON default_sender.id = a.default_sender_id
             WHERE t.token_hash = ? AND t.revoked_at IS NULL AND a.is_active = 1
             LIMIT 1'
        );
        $statement->execute([hash('sha256', $token)]);
        $application = $statement->fetch();
        if (!$application) {
            Http::jsonError(401, 'invalid_token', 'The API token is invalid or has been revoked.');
        }

        $pdo->prepare('UPDATE api_tokens SET last_used_at = UTC_TIMESTAMP() WHERE id = ?')
            ->execute([(int) $application['token_id']]);
        $this->checkRateLimit($pdo, (int) $application['token_id']);
        $data = Http::requestJson();
        $recipient = $this->emailField($data['to'] ?? $application['default_to'] ?? null, 'to', 254, true);
        $subject = $this->stringField($data['subject'] ?? null, 'subject', 1, 255);
        $body = $this->stringField($data['body'] ?? null, 'body', 1, 50000);
        $format = $data['format'] ?? 'text';
        if (!is_string($format) || !in_array($format, ['text', 'html'], true)) {
            Http::jsonError(422, 'validation_error', 'The format field must be text or html.');
        }

        $explicitSender = array_key_exists('from', $data);
        $requestedSender = $explicitSender ? $data['from'] : ($application['default_sender_email'] ?? null);
        if ($requestedSender === null || $requestedSender === '') {
            Http::jsonError(422, 'sender_required', 'The application has no default sender. Configure one or provide the from field.');
        }
        $senderEmail = $this->emailField(
            $requestedSender,
            'from',
            254,
            true
        );
        if ($application['smtp_server_id'] === null) {
            Http::jsonError(503, 'smtp_server_not_configured', 'The application has no SMTP server assigned.');
        }
        $smtpServerQuery = $pdo->prepare(
            'SELECT id FROM smtp_servers WHERE id = ? AND is_active = 1 LIMIT 1'
        );
        $smtpServerQuery->execute([(int) $application['smtp_server_id']]);
        if (!$smtpServerQuery->fetch()) {
            Http::jsonError(503, 'smtp_server_unavailable', 'The assigned SMTP server is not active.');
        }
        $senderQuery = $pdo->prepare(
            'SELECT senders.id AS sender_id, senders.email, senders.sender_name,
                    smtp_servers.host AS smtp_host, smtp_servers.port AS smtp_port,
                    smtp_servers.username AS smtp_username,
                    smtp_servers.password_encrypted AS smtp_password_encrypted,
                    smtp_servers.encryption AS smtp_encryption
             FROM application_senders
             JOIN senders ON senders.id = application_senders.sender_id
             JOIN smtp_servers ON smtp_servers.id = ?
             WHERE application_senders.application_id = ? AND senders.email = ?
               AND senders.is_active = 1 AND smtp_servers.is_active = 1
             LIMIT 1'
        );
        $senderQuery->execute([
            (int) $application['smtp_server_id'],
            (int) $application['application_id'],
            $senderEmail,
        ]);
        $sender = $senderQuery->fetch();
        if (!$sender) {
            if ($explicitSender) {
                Http::jsonError(403, 'sender_not_allowed', 'This address is not an active sender for the application.');
            }
            Http::jsonError(503, 'sender_not_configured', 'The application has no active default sender.');
        }

        $insert = $pdo->prepare(
            'INSERT INTO email_logs
                (smtp_server_id, sender_id, application_id, token_id, recipient, sender, subject, format, status, ip_address)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, "pending", ?)'
        );
        $insert->execute([
            $application['smtp_server_id'],
            $sender['sender_id'],
            $application['application_id'],
            $application['token_id'],
            $recipient,
            $sender['email'],
            $subject,
            $format,
            substr($_SERVER['REMOTE_ADDR'] ?? '', 0, 45),
        ]);
        $logId = (int) $pdo->lastInsertId();

        try {
            (new MailService())->send($recipient, $subject, $body, $format, $sender);
            $update = $pdo->prepare('UPDATE email_logs SET status = "sent", sent_at = UTC_TIMESTAMP() WHERE id = ?');
            $update->execute([$logId]);
            Http::json(200, ['success' => true, 'data' => ['message' => 'The email was sent.', 'id' => $logId]]);
        } catch (\Throwable $exception) {
            error_log('[mail-api] SMTP send failed, log ' . $logId . ': ' . $exception->getMessage());
            $update = $pdo->prepare(
                'UPDATE email_logs SET status = "failed", error_message = ? WHERE id = ?'
            );
            $update->execute([substr($exception->getMessage(), 0, 2000), $logId]);
            Http::jsonError(502, 'mail_delivery_failed', 'The email could not be delivered through SMTP.');
        }
    }

    private function bearerToken(): string
    {
        $header = '';
        foreach (['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'] as $serverKey) {
            if (isset($_SERVER[$serverKey]) && is_string($_SERVER[$serverKey]) && $_SERVER[$serverKey] !== '') {
                $header = $_SERVER[$serverKey];
                break;
            }
        }
        if ($header === '' && function_exists('getallheaders')) {
            foreach (getallheaders() as $name => $value) {
                if (strcasecmp((string) $name, 'Authorization') === 0 && is_string($value)) {
                    $header = $value;
                    break;
                }
            }
        }
        if (!preg_match('/^Bearer ([A-Za-z0-9_-]{40,100})$/D', $header, $matches)) {
            Http::jsonError(401, 'unauthorized', 'A valid Bearer API token is required.');
        }
        return $matches[1];
    }

    private function checkRateLimit(PDO $pdo, int $tokenId): void
    {
        $limit = max(1, min(600, (int) (Config::get('rate_limit_per_minute') ?? 30)));
        $statement = $pdo->prepare(
            'INSERT INTO api_rate_limits (token_id, window_started_at, request_count)
             VALUES (?, UTC_TIMESTAMP(), 1)
             ON DUPLICATE KEY UPDATE
               request_count = IF(window_started_at < UTC_TIMESTAMP() - INTERVAL 1 MINUTE, 1, LEAST(request_count + 1, 601)),
               window_started_at = IF(window_started_at < UTC_TIMESTAMP() - INTERVAL 1 MINUTE, UTC_TIMESTAMP(), window_started_at)'
        );
        $statement->execute([$tokenId]);
        $query = $pdo->prepare('SELECT request_count, window_started_at FROM api_rate_limits WHERE token_id = ?');
        $query->execute([$tokenId]);
        $state = $query->fetch();
        if ((int) $state['request_count'] > $limit) {
            $remaining = max(1, 60 - (time() - strtotime($state['window_started_at'] . ' UTC')));
            Http::jsonError(429, 'rate_limited', 'The request rate limit was exceeded. Try again later.', [
                'Retry-After' => (string) $remaining,
            ]);
        }
    }

    private function emailField(mixed $value, string $name, int $maxLength, bool $required): string
    {
        if ($value === null && !$required) {
            return '';
        }
        if (!is_string($value) || strlen($value) > $maxLength || !filter_var($value, FILTER_VALIDATE_EMAIL)) {
            Http::jsonError(422, 'validation_error', "The {$name} field must contain one valid email address.");
        }
        return $value;
    }

    private function stringField(mixed $value, string $name, int $minLength, int $maxLength): string
    {
        if (!is_string($value)) {
            Http::jsonError(422, 'validation_error', "The {$name} field must be a string.");
        }
        $value = trim($value);
        if (strlen($value) < $minLength || strlen($value) > $maxLength) {
            Http::jsonError(422, 'validation_error', "The {$name} field must be {$minLength} to {$maxLength} characters long.");
        }
        if ($name === 'subject' && preg_match('/[\r\n]/', $value)) {
            Http::jsonError(422, 'validation_error', 'The subject must not contain line breaks.');
        }
        return $value;
    }
}
