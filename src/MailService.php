<?php
declare(strict_types=1);

namespace MailApi;

use PHPMailer\PHPMailer\PHPMailer;
use RuntimeException;

final class MailService
{
    public function testConnection(array $server): void
    {
        if (!class_exists(PHPMailer::class)) {
            throw new RuntimeException('PHPMailer is missing. Run composer install.');
        }

        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = (string) $server['host'];
        $mail->Port = (int) $server['port'];
        $mail->SMTPAuth = true;
        $mail->Username = (string) $server['username'];
        $mail->Password = SecretCipher::decrypt((string) $server['password_encrypted']);
        $mail->Timeout = 15;
        $mail->SMTPKeepAlive = false;
        $encryption = strtolower((string) $server['encryption']);
        if ($encryption === 'tls') {
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        } elseif ($encryption === 'ssl') {
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
        } else {
            throw new RuntimeException('SMTP encryption must be tls or ssl.');
        }

        try {
            if (!$mail->smtpConnect()) {
                throw new RuntimeException($mail->ErrorInfo ?: 'The SMTP server rejected the connection.');
            }
        } finally {
            $mail->smtpClose();
        }
    }

    public function send(
        string $to,
        string $subject,
        string $body,
        string $format,
        array $sender
    ): void
    {
        if (!class_exists(PHPMailer::class)) {
            throw new RuntimeException('PHPMailer is missing. Run composer install.');
        }

        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = (string) $sender['smtp_host'];
        $mail->Port = (int) $sender['smtp_port'];
        $mail->SMTPAuth = true;
        $mail->Username = (string) $sender['smtp_username'];
        $mail->Password = SecretCipher::decrypt((string) $sender['smtp_password_encrypted']);
        $mail->Timeout = 15;
        $mail->SMTPKeepAlive = false;
        $encryption = strtolower((string) $sender['smtp_encryption']);
        if ($encryption === 'tls') {
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        } elseif ($encryption === 'ssl') {
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
        } else {
            throw new RuntimeException('SMTP encryption must be tls or ssl.');
        }
        $mail->CharSet = 'UTF-8';
        $mail->setFrom((string) $sender['email'], (string) ($sender['sender_name'] ?? ''));
        $mail->addAddress($to);
        $mail->Subject = $subject;
        $mail->isHTML($format === 'html');
        $mail->Body = $body;
        if ($format === 'html') {
            $mail->AltBody = trim(strip_tags($body));
        }
        $mail->send();
    }
}
