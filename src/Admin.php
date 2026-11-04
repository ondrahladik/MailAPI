<?php
declare(strict_types=1);

namespace MailApi;

use PDO;
use Throwable;

final class Admin
{
    private string $currentPath = '/admin';
    private string $cspNonce = '';

    public function handle(string $path, string $method): void
    {
        $this->cspNonce = base64_encode(random_bytes(18));
        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: no-referrer');
        header("Content-Security-Policy: default-src 'self'; style-src 'unsafe-inline'; script-src 'nonce-{$this->cspNonce}'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
        header('Cache-Control: no-store');

        if (!Config::adminEnabled()) {
            http_response_code(503);
            $this->page('Configuration', '<p>Administration is disabled. Set admin_password_hash in the configuration file.</p>');
        }

        if ($path === '/admin/login') {
            if ($method === 'POST') {
                $this->login();
            }
            if ($method !== 'GET') {
                http_response_code(405);
                header('Allow: GET, POST');
                $this->page('Error', '<p>Method not allowed.</p>');
            }
            if (!empty($_SESSION['admin_authenticated'])) {
                Http::adminRedirect('/admin');
            }
            $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
            $this->page('Sign in', $this->notifications() . '<form method="post" action="/admin/login">'
                . $this->csrfInput() . '<label>Administrator password <input type="password" name="password" required autofocus autocomplete="current-password"></label>'
                . '<button>Sign in</button></form>');
        }

        if (empty($_SESSION['admin_authenticated'])) {
            Http::adminRedirect('/admin/login');
        }

        if ($path === '/admin/logout') {
            $this->requirePost($method);
            $this->checkCsrf();
            $_SESSION = [];
            session_regenerate_id(true);
            Http::adminRedirect('/admin/login');
        }

        if ($path === '/admin/overview/activity') {
            if ($method !== 'GET') {
                Http::jsonError(405, 'method_not_allowed', 'Use the GET method.', ['Allow' => 'GET']);
            }
            $logs = $this->recentEmailActivity(Database::connection());
            Http::json(200, ['success' => true, 'data' => ['html' => $this->logTable($logs)]]);
        }

        if ($method === 'POST') {
            $this->checkCsrf();
            try {
                $this->postAction($path);
                $message = match ($path) {
                    '/admin/smtp-servers/test' => 'SMTP connection and authentication succeeded. No email was sent.',
                    '/admin/send-email' => 'Email sent successfully. The result is available in Email history.',
                    default => 'Changes saved.',
                };
                $_SESSION['flash'] = ['type' => 'success', 'message' => $message];
            } catch (Throwable $exception) {
                error_log('[mail-api admin] ' . $exception::class . ': ' . $exception->getMessage());
                $_SESSION['flash'] = ['type' => 'error', 'message' => $exception->getMessage()];
            }
            Http::adminRedirect($this->pageForAction($path));
        }

        if ($method !== 'GET') {
            http_response_code(405);
            header('Allow: GET, POST');
            $this->page('Error', '<p>Method not allowed.</p>');
        }

        $pages = [
            '/admin',
            '/admin/applications',
            '/admin/smtp-servers',
            '/admin/senders',
            '/admin/tokens',
            '/admin/send-email',
            '/admin/email-history',
            '/admin/templates',
            '/admin/docs',
            '/admin/docs/admin',
        ];
        if (!in_array($path, $pages, true)) {
            http_response_code(404);
            $this->page('Not found', '<p>The administration page was not found.</p>', true);
        }

        $this->currentPath = $path;
        $this->dashboard($path);
    }

    private function login(): void
    {
        if (!$this->validCsrf($_POST['csrf'] ?? null)) {
            http_response_code(400);
            $this->page('Sign in', $this->toastStack(
                $this->toast('error', 'Invalid request', 'Reload the sign-in page and try again.')
            ));
        }

        $pdo = Database::connection();
        $ipHash = hash_hmac('sha256', $_SERVER['REMOTE_ADDR'] ?? 'unknown', (string) Config::get('admin_password_hash'));
        $query = $pdo->prepare('SELECT attempts, window_started_at FROM admin_login_limits WHERE ip_hash = ?');
        $query->execute([$ipHash]);
        $limitState = $query->fetch();
        if ($limitState && (int) $limitState['attempts'] >= 8
            && strtotime($limitState['window_started_at'] . ' UTC') > time() - 900) {
            http_response_code(429);
            $this->page('Sign in', $this->toastStack(
                $this->toast('error', 'Too many attempts', 'Try again in 15 minutes.')
            ));
        }

        $password = $_POST['password'] ?? '';
        $hash = (string) Config::get('admin_password_hash');
        if (!is_string($password) || !password_verify($password, $hash)) {
            $pdo->prepare(
                'INSERT INTO admin_login_limits (ip_hash, window_started_at, attempts)
                 VALUES (?, UTC_TIMESTAMP(), 1)
                 ON DUPLICATE KEY UPDATE
                   attempts = IF(window_started_at < UTC_TIMESTAMP() - INTERVAL 15 MINUTE, 1, LEAST(attempts + 1, 100)),
                   window_started_at = IF(window_started_at < UTC_TIMESTAMP() - INTERVAL 15 MINUTE, UTC_TIMESTAMP(), window_started_at)'
            )->execute([$ipHash]);
            http_response_code(401);
            $this->page('Sign in', $this->toastStack(
                $this->toast('error', 'Sign-in failed', 'Invalid credentials.')
            ) . $this->loginForm());
        }

        $pdo->prepare('DELETE FROM admin_login_limits WHERE ip_hash = ?')->execute([$ipHash]);
        session_regenerate_id(true);
        $_SESSION['admin_authenticated'] = true;
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
        Http::adminRedirect('/admin');
    }

    private function loginForm(): string
    {
        $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
        return '<form method="post" action="/admin/login">' . $this->csrfInput()
            . '<label>Administrator password <input type="password" name="password" required autofocus autocomplete="current-password"></label>'
            . '<button>Sign in</button></form>';
    }

    private function dashboard(string $path): void
    {
        $pdo = Database::connection();
        $content = $this->notifications();
        $title = match ($path) {
            '/admin/applications' => 'Applications',
            '/admin/smtp-servers' => 'SMTP servers',
            '/admin/senders' => 'Senders',
            '/admin/tokens' => 'API tokens',
            '/admin/send-email' => 'Send email',
            '/admin/email-history' => 'Email history',
            '/admin/templates' => 'Email templates',
            '/admin/docs' => 'API documentation',
            '/admin/docs/admin' => 'Admin guide',
            default => 'Overview',
        };

        switch ($path) {
            case '/admin/applications':
                $content .= $this->applicationsContent($pdo);
                break;
            case '/admin/smtp-servers':
                $content .= $this->smtpServersContent($pdo);
                break;
            case '/admin/senders':
                $content .= $this->sendersContent($pdo);
                break;
            case '/admin/tokens':
                $content .= $this->tokensContent($pdo);
                break;
            case '/admin/send-email':
                $content .= $this->sendEmailContent($pdo);
                break;
            case '/admin/email-history':
                $content .= $this->emailHistoryContent($pdo);
                break;
            case '/admin/templates':
                $content .= $this->emailTemplatesContent($pdo);
                break;
            case '/admin/docs':
                $content .= $this->docsContent();
                break;
            case '/admin/docs/admin':
                $content .= $this->adminDocsContent();
                break;
            default:
                $content .= $this->overviewContent($pdo);
        }

        $this->page($title, $content, true);
    }

    private function notifications(): string
    {
        $content = '';
        if (isset($_SESSION['new_token'])) {
            $content .= '<div class="toast toast-notice" role="status" aria-live="polite" data-toast="persistent">'
                . '<span class="toast-icon" aria-hidden="true">!</span><div class="toast-content">'
                . '<strong>API token created</strong><code>' . Http::escape($_SESSION['new_token']) . '</code>'
                . '<p>Copy it now and store it securely. This token is shown only once.</p></div>'
                . '<button class="toast-dismiss" type="button" aria-label="Dismiss notification">×</button></div>';
            unset($_SESSION['new_token']);
        }
        if (isset($_SESSION['flash'])) {
            $flash = $_SESSION['flash'];
            $type = in_array($flash['type'] ?? '', ['success', 'error'], true) ? $flash['type'] : 'notice';
            $title = match ($type) {
                'success' => 'Completed',
                'error' => 'Action failed',
                default => 'Notice',
            };
            $content .= $this->toast($type, $title, (string) ($flash['message'] ?? ''));
            unset($_SESSION['flash']);
        }
        return $content === '' ? '' : '<div class="toast-stack">' . $content . '</div>';
    }

    private function toast(string $type, string $title, string $message): string
    {
        $role = $type === 'error' ? 'alert' : 'status';
        return '<div class="toast toast-' . Http::escape($type) . '" role="' . $role
            . '" aria-live="' . ($type === 'error' ? 'assertive' : 'polite') . '" data-toast="auto">'
            . '<span class="toast-icon" aria-hidden="true">' . ($type === 'success' ? '&#10003;' : '!') . '</span>'
            . '<div class="toast-content"><strong>' . Http::escape($title) . '</strong><p>'
            . Http::escape($message) . '</p></div>'
            . '<button class="toast-dismiss" type="button" aria-label="Dismiss notification">×</button></div>';
    }

    private function toastStack(string $toast): string
    {
        return '<div class="toast-stack">' . $toast . '</div>';
    }

    private function overviewContent(PDO $pdo): string
    {
        $applications = $pdo->query('SELECT COUNT(*) AS total, COALESCE(SUM(is_active = 1), 0) AS active FROM applications')->fetch();
        $servers = $pdo->query('SELECT COUNT(*) AS total, COALESCE(SUM(is_active = 1), 0) AS active FROM smtp_servers')->fetch();
        $senders = $pdo->query('SELECT COUNT(*) AS total, COALESCE(SUM(is_active = 1), 0) AS active FROM senders')->fetch();
        $tokens = $pdo->query('SELECT COUNT(*) AS total FROM api_tokens WHERE revoked_at IS NULL')->fetch();
        $logs = $this->recentEmailActivity($pdo);

        $content = '<div class="metrics"><article class="metric-card"><span class="metric-label">Applications</span><strong>'
            . (int) $applications['total'] . '</strong><span class="metric-detail">' . (int) $applications['active'] . ' active</span></article>'
            . '<article class="metric-card"><span class="metric-label">SMTP servers</span><strong>'
            . (int) $servers['total'] . '</strong><span class="metric-detail">' . (int) $servers['active'] . ' active</span></article>'
            . '<article class="metric-card"><span class="metric-label">Sender identities</span><strong>'
            . (int) $senders['total'] . '</strong><span class="metric-detail">' . (int) $senders['active'] . ' active</span></article>'
            . '<article class="metric-card"><span class="metric-label">Active API tokens</span><strong>'
            . (int) $tokens['total'] . '</strong><span class="metric-detail">Not revoked</span></article></div>'
            . '<section class="content-section"><div class="section-heading"><div><h2>Recent email activity</h2>'
            . '<p>Latest delivery attempts across all applications.</p></div><a class="text-link" href="/admin/email-history">View history</a></div>'
            . '<div id="overview-email-activity" data-refresh-url="/admin/overview/activity">'
            . $this->logTable($logs) . '</div><p class="activity-refresh-status" id="overview-activity-status"'
            . ' role="status" aria-live="polite">Live updates are enabled.</p></section>';
        return $content;
    }

    private function recentEmailActivity(PDO $pdo): array
    {
        return $pdo->query(
            'SELECT l.*, a.name AS application_name, smtp.name AS smtp_server_name,
                    template.slug AS template_slug
             FROM email_logs l
             JOIN applications a ON a.id = l.application_id
             LEFT JOIN smtp_servers smtp ON smtp.id = l.smtp_server_id
             LEFT JOIN email_templates template ON template.id = l.template_id
             ORDER BY l.created_at DESC, l.id DESC
             LIMIT 8'
        )->fetchAll();
    }

    private function applicationsContent(PDO $pdo): string
    {
        $applications = $pdo->query(
            'SELECT a.*, smtp.name AS smtp_server_name, sender.email AS default_sender_email,
                    (SELECT COUNT(*) FROM api_tokens t WHERE t.application_id = a.id AND t.revoked_at IS NULL) AS active_tokens
             FROM applications a
             LEFT JOIN smtp_servers smtp ON smtp.id = a.smtp_server_id
             LEFT JOIN senders sender ON sender.id = a.default_sender_id
             ORDER BY a.name'
        )->fetchAll();
        $servers = $pdo->query('SELECT id, name, is_active FROM smtp_servers ORDER BY name')->fetchAll();
        $senders = $pdo->query('SELECT id, email, sender_name, is_active FROM senders ORDER BY email')->fetchAll();
        $assignments = $pdo->query('SELECT application_id, sender_id FROM application_senders')->fetchAll();
        $senderIdsByApplication = [];
        foreach ($assignments as $assignment) {
            $senderIdsByApplication[(int) $assignment['application_id']][] = (int) $assignment['sender_id'];
        }

        $content = '<section class="content-section"><div class="section-heading"><div><h1 class="card-title">Applications</h1>'
            . '<p>Applications isolate API access and sender configuration.</p></div>'
            . '<button type="button" class="secondary" data-open-modal="application-create">Add application</button></div>'
            . '<dialog class="admin-modal" id="application-create" aria-labelledby="application-create-title">'
            . '<div class="modal-header"><h2 id="application-create-title">New application</h2>'
            . '<button type="button" class="modal-close" data-close-modal aria-label="Close dialog">×</button></div>'
            . '<form method="post" action="/admin/applications/create" class="form-grid modal-form">' . $this->csrfInput()
            . '<label>Name <input name="name" maxlength="120" required></label>'
            . '<label>Slug (optional) <input name="slug" maxlength="80"></label>'
            . '<label>Default recipient (optional) <input type="email" name="default_to" maxlength="254"></label>'
            . '<div class="form-actions"><button>Create application</button><button type="button" class="secondary" data-close-modal>Cancel</button></div>'
            . '</form></dialog></section><section class="content-section"><div class="section-heading"><div><h2>Configured applications</h2>'
            . '<p>Select one SMTP server and assign the sender addresses this application may use.</p></div>'
            . '<span class="section-count">' . count($applications) . '</span></div>';

        if (!$applications) {
            return $content . '<p class="empty-state">No applications yet. Create one to get started.</p></section>';
        }

        $content .= '<div class="table-wrap"><table><thead><tr><th>Application</th><th>Status</th><th></th></tr></thead><tbody>';
        $dialogs = '';
        foreach ($applications as $application) {
            $id = (int) $application['id'];
            $assignedIds = $senderIdsByApplication[$id] ?? [];
            $isActive = (int) $application['is_active'] === 1;
            $content .= '<tr><td><strong class="table-primary">' . Http::escape($application['name'])
                . '</strong></td><td><span class="status-badge ' . ($isActive ? 'is-active' : 'is-disabled') . '">'
                . ($isActive ? 'Active' : 'Disabled') . '</span></td><td class="actions-cell"><div class="management-actions">'
                . '<button type="button" class="secondary management-action" data-open-modal="application-detail-' . $id . '">'
                . $this->actionIcon('detail') . '<span>Detail</span></button>'
                . '<button type="button" class="secondary management-action" data-open-modal="application-edit-' . $id . '">'
                . $this->actionIcon('edit') . '<span>Edit</span></button>'
                . '<form method="post" action="/admin/applications/toggle" class="management-action-form">' . $this->csrfInput()
                . '<input type="hidden" name="application_id" value="' . $id . '"><button class="secondary management-action">'
                . $this->actionIcon($isActive ? 'disable' : 'enable') . '<span>' . ($isActive ? 'Disable' : 'Enable')
                . '</span></button></form></div></td></tr>';

            $allowedSenders = [];
            foreach ($senders as $sender) {
                if (in_array((int) $sender['id'], $assignedIds, true)) {
                    $allowedSenders[] = $sender['email'] . ((int) $sender['is_active'] === 1 ? '' : ' (disabled)');
                }
            }
            $dialogs .= $this->detailDialog('application-detail-' . $id, 'Application details', [
                'Name' => $application['name'],
                'Slug' => $application['slug'],
                'SMTP server' => $application['smtp_server_name'] ?: 'Not assigned',
                'Default sender' => $application['default_sender_email'] ?: 'Not set',
                'Default recipient' => $application['default_to'] ?: 'Not set',
                'Allowed senders' => $allowedSenders ? implode("\n", $allowedSenders) : 'None',
                'Active API tokens' => (string) $application['active_tokens'],
                'Status' => $isActive ? 'Active' : 'Disabled',
                'Created' => $application['created_at'],
                'Updated' => $application['updated_at'],
            ]) . '<dialog class="admin-modal" id="application-edit-' . $id . '" aria-labelledby="application-edit-title-' . $id . '">'
                . '<div class="modal-header"><h2 id="application-edit-title-' . $id . '">Application settings</h2>'
                . '<button type="button" class="modal-close" data-close-modal aria-label="Close dialog">×</button></div>'
                . '<form method="post" action="/admin/applications/update" class="form-grid modal-form">'
                . $this->csrfInput() . '<input type="hidden" name="application_id" value="' . $id . '">'
                . '<label>Name <input name="name" maxlength="120" required value="' . Http::escape($application['name']) . '"></label>'
                . '<label>Slug <input name="slug" maxlength="80" required value="' . Http::escape($application['slug']) . '"></label>'
                . '<label>Default recipient <input type="email" name="default_to" maxlength="254" value="'
                . Http::escape($application['default_to'] ?? '') . '"></label>'
                . '<label>SMTP server <select name="smtp_server_id"><option value="">Not assigned</option>';
            foreach ($servers as $server) {
                $selected = (int) $application['smtp_server_id'] === (int) $server['id'] ? ' selected' : '';
                $state = (int) $server['is_active'] ? '' : ' (disabled)';
                $dialogs .= '<option value="' . (int) $server['id'] . '"' . $selected . '>'
                    . Http::escape($server['name'] . $state) . '</option>';
            }
            $dialogs .= '</select></label><fieldset><legend>Allowed sender addresses</legend>';
            foreach ($senders as $sender) {
                $senderId = (int) $sender['id'];
                $checked = in_array($senderId, $assignedIds, true) ? ' checked' : '';
                $state = (int) $sender['is_active'] ? '' : ' (disabled)';
                $dialogs .= '<label class="choice"><input type="checkbox" name="sender_ids[]" value="' . $senderId . '"'
                    . $checked . '>' . Http::escape($sender['email'] . $state) . '</label>';
            }
            if (!$senders) {
                $dialogs .= '<p>No sender addresses exist. Add one on the <a href="/admin/senders">Senders</a> page.</p>';
            }
            $dialogs .= '</fieldset><p class="form-help">The default sender must also be selected above.</p>'
                . '<label>Default sender <select name="default_sender_id"><option value="">None</option>';
            foreach ($senders as $sender) {
                $senderId = (int) $sender['id'];
                $selected = (int) $application['default_sender_id'] === $senderId ? ' selected' : '';
                $state = (int) $sender['is_active'] ? '' : ' (disabled)';
                $dialogs .= '<option value="' . $senderId . '"' . $selected . '>'
                    . Http::escape($sender['email'] . $state) . '</option>';
            }
            $dialogs .= '</select></label><div class="form-actions"><button>Save application settings</button>'
                . '<button type="button" class="secondary" data-close-modal>Cancel</button></div></form></dialog>';
        }
        return $content . '</tbody></table></div>' . $dialogs . '</section>';
    }

    private function smtpServersContent(PDO $pdo): string
    {
        $servers = $pdo->query(
            'SELECT s.*, (SELECT COUNT(*) FROM applications a WHERE a.smtp_server_id = s.id) AS application_count
             FROM smtp_servers s ORDER BY s.name'
        )->fetchAll();
        $content = '<section class="content-section"><div class="section-heading"><div><h1 class="card-title">SMTP servers</h1>'
            . '<p>Credentials are encrypted before they are stored.</p></div>'
            . '<button type="button" class="secondary" data-open-modal="smtp-create">Add SMTP server</button></div>'
            . '<dialog class="admin-modal" id="smtp-create" aria-labelledby="smtp-create-title">'
            . '<div class="modal-header"><h2 id="smtp-create-title">New SMTP server</h2>'
            . '<button type="button" class="modal-close" data-close-modal aria-label="Close dialog">×</button></div>'
            . $this->smtpServerForm() . '</dialog></section><section class="content-section"><div class="section-heading"><div>'
            . '<h2>Configured SMTP servers</h2><p>Connection settings are managed independently of sender addresses.</p></div>'
            . '<span class="section-count">' . count($servers) . '</span></div>';
        if (!$servers) {
            return $content . '<p class="empty-state">No SMTP servers configured.</p></section>';
        }

        $content .= '<div class="table-wrap"><table><thead><tr><th>SMTP server</th><th>Status</th><th></th></tr></thead><tbody>';
        $dialogs = '';
        foreach ($servers as $server) {
            $isActive = (int) $server['is_active'] === 1;
            $content .= '<tr><td><strong class="table-primary">' . Http::escape($server['name']) . '</strong></td><td><span class="status-badge '
                . ($isActive ? 'is-active' : 'is-disabled') . '">' . ($isActive ? 'Active' : 'Disabled') . '</span>'
                . '</td><td class="actions-cell"><div class="management-actions">'
                . '<button type="button" class="secondary management-action" data-open-modal="smtp-detail-' . (int) $server['id'] . '">'
                . $this->actionIcon('detail') . '<span>Detail</span></button>'
                . '<button type="button" class="secondary management-action" data-open-modal="smtp-edit-' . (int) $server['id'] . '">'
                . $this->actionIcon('edit') . '<span>Edit</span></button>'
                . '<form method="post" action="/admin/smtp-servers/test" class="management-action-form">' . $this->csrfInput()
                . '<input type="hidden" name="server_id" value="' . (int) $server['id'] . '">'
                . '<button class="secondary management-action">' . $this->actionIcon('test') . '<span>Test</span></button></form>'
                . '<form method="post" action="/admin/smtp-servers/toggle" class="management-action-form">' . $this->csrfInput()
                . '<input type="hidden" name="server_id" value="' . (int) $server['id'] . '"><button class="secondary management-action">'
                . $this->actionIcon($isActive ? 'disable' : 'enable') . '<span>' . ($isActive ? 'Disable' : 'Enable')
                . '</span></button></form></div></td></tr>';
            $dialogs .= $this->detailDialog('smtp-detail-' . (int) $server['id'], 'SMTP server details', [
                'Name' => $server['name'],
                'Host' => $server['host'],
                'Port' => (string) $server['port'],
                'Encryption' => strtoupper($server['encryption']),
                'Username' => $server['username'],
                'Applications' => (string) $server['application_count'],
                'Status' => $isActive ? 'Active' : 'Disabled',
                'Created' => $server['created_at'],
                'Updated' => $server['updated_at'],
            ]) . '<dialog class="admin-modal" id="smtp-edit-' . (int) $server['id'] . '" aria-labelledby="smtp-edit-title-'
                . (int) $server['id'] . '"><div class="modal-header"><h2 id="smtp-edit-title-' . (int) $server['id']
                . '">SMTP server settings</h2><button type="button" class="modal-close" data-close-modal aria-label="Close dialog">×</button></div>'
                . $this->smtpServerForm($server) . '</dialog>';
        }
        return $content . '</tbody></table></div>' . $dialogs . '</section>';
    }

    private function sendersContent(PDO $pdo): string
    {
        $senders = $pdo->query(
            'SELECT s.*,
                    (SELECT COUNT(*) FROM application_senders x WHERE x.sender_id = s.id) AS application_count,
                    (SELECT GROUP_CONCAT(a.name ORDER BY a.name SEPARATOR "\n")
                     FROM application_senders x JOIN applications a ON a.id = x.application_id
                     WHERE x.sender_id = s.id) AS application_names
             FROM senders s ORDER BY s.email'
        )->fetchAll();
        $content = '<section class="content-section"><div class="section-heading"><div><h1 class="card-title">Sender addresses</h1>'
            . '<p>Sender identities are separate from SMTP connection credentials.</p></div>'
            . '<button type="button" class="secondary" data-open-modal="sender-create">Add sender address</button></div>'
            . '<dialog class="admin-modal" id="sender-create" aria-labelledby="sender-create-title">'
            . '<div class="modal-header"><h2 id="sender-create-title">New sender address</h2>'
            . '<button type="button" class="modal-close" data-close-modal aria-label="Close dialog">×</button></div>'
            . $this->senderForm() . '</dialog></section><section class="content-section"><div class="section-heading"><div>'
            . '<h2>Configured sender addresses</h2><p>Assign these identities to applications on the Applications page.</p></div>'
            . '<span class="section-count">' . count($senders) . '</span></div>';
        if (!$senders) {
            return $content . '<p class="empty-state">No sender addresses configured.</p></section>';
        }

        $content .= '<div class="table-wrap"><table><thead><tr><th>Sender address</th><th>Status</th><th></th></tr></thead><tbody>';
        $dialogs = '';
        foreach ($senders as $sender) {
            $isActive = (int) $sender['is_active'] === 1;
            $content .= '<tr><td><strong class="table-primary">' . Http::escape($sender['email'])
                . '</strong></td><td><span class="status-badge '
                . ($isActive ? 'is-active' : 'is-disabled') . '">' . ($isActive ? 'Active' : 'Disabled') . '</span>'
                . '</td><td class="actions-cell"><div class="management-actions">'
                . '<button type="button" class="secondary management-action" data-open-modal="sender-detail-' . (int) $sender['id'] . '">'
                . $this->actionIcon('detail') . '<span>Detail</span></button>'
                . '<button type="button" class="secondary management-action" data-open-modal="sender-edit-' . (int) $sender['id'] . '">'
                . $this->actionIcon('edit') . '<span>Edit</span></button>'
                . '<form method="post" action="/admin/senders/toggle" class="management-action-form">' . $this->csrfInput()
                . '<input type="hidden" name="sender_id" value="' . (int) $sender['id'] . '"><button class="secondary management-action">'
                . $this->actionIcon($isActive ? 'disable' : 'enable') . '<span>' . ($isActive ? 'Disable' : 'Enable')
                . '</span></button></form></div></td></tr>';
            $dialogs .= $this->detailDialog('sender-detail-' . (int) $sender['id'], 'Sender details', [
                'Email address' => $sender['email'],
                'Display name' => $sender['sender_name'] ?: 'Not set',
                'Assigned applications' => $sender['application_names'] ?: 'None',
                'Status' => $isActive ? 'Active' : 'Disabled',
                'Created' => $sender['created_at'],
                'Updated' => $sender['updated_at'],
            ]) . '<dialog class="admin-modal" id="sender-edit-' . (int) $sender['id'] . '" aria-labelledby="sender-edit-title-'
                . (int) $sender['id'] . '"><div class="modal-header"><h2 id="sender-edit-title-' . (int) $sender['id']
                . '">Sender address</h2><button type="button" class="modal-close" data-close-modal aria-label="Close dialog">×</button></div>'
                . $this->senderForm($sender) . '</dialog>';
        }
        return $content . '</tbody></table></div>' . $dialogs . '</section>';
    }

    private function tokensContent(PDO $pdo): string
    {
        $applications = $pdo->query('SELECT id, name FROM applications ORDER BY name')->fetchAll();
        $tokens = $pdo->query(
            'SELECT t.id, t.application_id, t.name, t.last_used_at, t.revoked_at, t.created_at, a.name AS application_name
             FROM api_tokens t JOIN applications a ON a.id = t.application_id
             ORDER BY t.created_at DESC LIMIT 100'
        )->fetchAll();
        $content = '<section class="content-section"><div class="section-heading"><div><h1 class="card-title">API tokens</h1>'
            . '<p>Tokens are displayed once. Store them in a secret manager.</p></div>'
            . '<button type="button" class="secondary" data-open-modal="token-create">Create token</button></div>'
            . '<dialog class="admin-modal" id="token-create" aria-labelledby="token-create-title">'
            . '<div class="modal-header"><h2 id="token-create-title">New API token</h2>'
            . '<button type="button" class="modal-close" data-close-modal aria-label="Close dialog">×</button></div>'
            . '<form method="post" action="/admin/tokens/create" class="form-grid modal-form">' . $this->csrfInput()
            . '<label>Application <select name="application_id" required><option value="">Select an application</option>';
        foreach ($applications as $application) {
            $content .= '<option value="' . (int) $application['id'] . '">' . Http::escape($application['name']) . '</option>';
        }
        $content .= '</select></label><label>Token name <input name="name" maxlength="120" required></label>'
            . '<div class="form-actions"><button>Create token</button><button type="button" class="secondary" data-close-modal>Cancel</button></div>'
            . '</form></dialog></section>'
            . '<section class="content-section"><div class="section-heading"><div><h2>Issued API tokens</h2>'
            . '<p>The 100 most recently created tokens.</p></div></div><div class="table-wrap"><table>'
            . '<thead><tr><th>Token</th><th>Status</th><th></th></tr></thead><tbody>';
        $dialogs = '';
        foreach ($tokens as $token) {
            $isActive = $token['revoked_at'] === null;
            $content .= '<tr><td><strong class="table-primary">' . Http::escape($token['name'])
                . '</strong><small class="table-secondary">' . Http::escape($token['application_name']) . '</small></td>'
                . '<td><span class="status-badge '
                . ($token['revoked_at'] ? 'is-disabled' : 'is-active') . '">'
                . ($token['revoked_at'] ? 'Revoked' : 'Active') . '</span></td><td class="actions-cell"><div class="management-actions">'
                . '<button type="button" class="secondary management-action" data-open-modal="token-detail-' . (int) $token['id'] . '">'
                . $this->actionIcon('detail') . '<span>Detail</span></button>';
            if (!$token['revoked_at']) {
                $content .= '<form method="post" action="/admin/tokens/revoke" class="management-action-form">' . $this->csrfInput()
                    . '<input type="hidden" name="token_id" value="' . (int) $token['id'] . '">'
                    . '<button class="danger management-action">' . $this->actionIcon('revoke') . '<span>Revoke</span></button></form>';
            }
            $content .= '</div></td></tr>';
            $dialogs .= $this->detailDialog('token-detail-' . (int) $token['id'], 'API token details', [
                'Token name' => $token['name'],
                'Application' => $token['application_name'],
                'Created' => $token['created_at'],
                'Last used' => $token['last_used_at'] ?: 'Never',
                'Status' => $token['revoked_at'] ? 'Revoked' : 'Active',
                'Revoked at' => $token['revoked_at'] ?: '—',
            ]);
        }
        if (!$tokens) {
            $content .= '<tr><td colspan="3">No tokens.</td></tr>';
        }
        return $content . '</tbody></table></div>' . $dialogs . '</section>';
    }

    private function emailHistoryContent(PDO $pdo): string
    {
        $filters = [];
        $parameters = [];
        $notice = '';
        $search = $_GET['q'] ?? '';
        if (!is_string($search)) {
            $search = '';
            $notice = $this->toast('error', 'Invalid search', 'The search value must be text.');
        } elseif (strlen($search) > 150) {
            $search = substr($search, 0, 150);
            $notice = $this->toast('error', 'Search shortened', 'Search text is limited to 150 characters.');
        }
        $search = trim($search);
        if ($search !== '') {
            $filters[] = '(l.recipient LIKE ? OR l.sender LIKE ? OR l.subject LIKE ? OR template.slug LIKE ?)';
            $searchLike = '%' . $search . '%';
            array_push($parameters, $searchLike, $searchLike, $searchLike, $searchLike);
        }

        $applicationId = null;
        $rawApplicationId = $_GET['application_id'] ?? '';
        if ($rawApplicationId !== '') {
            if (is_string($rawApplicationId) && ctype_digit($rawApplicationId) && (int) $rawApplicationId > 0) {
                $applicationId = (int) $rawApplicationId;
                $filters[] = 'l.application_id = ?';
                $parameters[] = $applicationId;
            } else {
                $notice .= $this->toast('error', 'Invalid application filter', 'Choose a valid application.');
            }
        }
        $status = $_GET['status'] ?? '';
        if (!is_string($status) || ($status !== '' && !in_array($status, ['pending', 'sent', 'failed'], true))) {
            $status = '';
            $notice .= $this->toast('error', 'Invalid status filter', 'Choose pending, sent, or failed.');
        }
        if ($status !== '') {
            $filters[] = 'l.status = ?';
            $parameters[] = $status;
        }
        $where = $filters ? ' WHERE ' . implode(' AND ', $filters) : '';
        $joins = ' FROM email_logs l
                   JOIN applications a ON a.id = l.application_id
                   LEFT JOIN smtp_servers smtp ON smtp.id = l.smtp_server_id
                   LEFT JOIN email_templates template ON template.id = l.template_id';

        $countQuery = $pdo->prepare('SELECT COUNT(*)' . $joins . $where);
        $countQuery->execute($parameters);
        $total = (int) $countQuery->fetchColumn();
        $perPage = 25;
        $totalPages = max(1, (int) ceil($total / $perPage));
        $page = 1;
        $rawPage = $_GET['page'] ?? '1';
        if (is_string($rawPage) && ctype_digit($rawPage) && (int) $rawPage > 0) {
            $page = min((int) $rawPage, $totalPages);
        } elseif ($rawPage !== '1') {
            $notice .= $this->toast('error', 'Invalid page', 'The requested page number is invalid.');
        }
        $offset = ($page - 1) * $perPage;
        $logsQuery = $pdo->prepare(
            'SELECT l.*, a.name AS application_name, smtp.name AS smtp_server_name,
                    template.slug AS template_slug'
            . $joins . $where . " ORDER BY l.created_at DESC, l.id DESC LIMIT {$perPage} OFFSET {$offset}"
        );
        $logsQuery->execute($parameters);
        $logs = $logsQuery->fetchAll();
        $applications = $pdo->query('SELECT id, name FROM applications ORDER BY name')->fetchAll();

        $content = '<section class="content-section"><div class="section-heading"><div><h1 class="card-title">Email history</h1>'
            . '<p>Search delivery attempts by sender, recipient, subject, or template. Message bodies are not stored.</p></div></div>'
            . $notice . '<form method="get" action="/admin/email-history" class="form-grid history-filters">'
            . '<label>Search <input name="q" maxlength="150" value="' . Http::escape($search) . '" placeholder="Email, subject, or template"></label>'
            . '<label>Application <select name="application_id"><option value="">All applications</option>';
        foreach ($applications as $application) {
            $selected = $applicationId === (int) $application['id'] ? ' selected' : '';
            $content .= '<option value="' . (int) $application['id'] . '"' . $selected . '>'
                . Http::escape($application['name']) . '</option>';
        }
        $content .= '</select></label><label>Status <select name="status"><option value="">All statuses</option>';
        foreach (['pending', 'sent', 'failed'] as $option) {
            $selected = $status === $option ? ' selected' : '';
            $content .= '<option value="' . $option . '"' . $selected . '>' . ucfirst($option) . '</option>';
        }
        $content .= '</select></label><div class="form-actions"><button>Search</button>'
            . '<a class="button-link" href="/admin/email-history">Clear filters</a></div></form>'
            . '<p class="history-summary">Showing ' . ($total === 0 ? '0' : ($offset + 1) . '–' . min($offset + $perPage, $total))
            . ' of ' . $total . ' attempts · Page ' . $page . ' of ' . $totalPages . '</p>'
            . $this->logTable($logs, true);
        if ($totalPages > 1) {
            $content .= '<nav class="pagination" aria-label="Email history pages">';
            $query = ['q' => $search, 'application_id' => $applicationId, 'status' => $status];
            if ($page > 1) {
                $query['page'] = $page - 1;
                $content .= '<a href="/admin/email-history?' . Http::escape(http_build_query($query)) . '">Previous</a>';
            }
            if ($page < $totalPages) {
                $query['page'] = $page + 1;
                $content .= '<a href="/admin/email-history?' . Http::escape(http_build_query($query)) . '">Next</a>';
            }
            $content .= '</nav>';
        }
        return $content . '</section>';
    }

    private function emailTemplatesContent(PDO $pdo): string
    {
        $applications = $pdo->query('SELECT id, name FROM applications ORDER BY name')->fetchAll();
        $templates = $pdo->query(
            'SELECT template.*, application.name AS application_name
             FROM email_templates template
             JOIN applications application ON application.id = template.application_id
             ORDER BY application.name, template.name'
        )->fetchAll();
        $content = '<section class="content-section"><div class="section-heading"><div><h1 class="card-title">Email templates</h1>'
            . '<p>Templates belong to one application and are available only to its API tokens. Use <code>{{variable}}</code> placeholders.</p></div>'
            . '<button type="button" class="secondary" data-open-modal="template-create">Create template</button></div>'
            . '<dialog class="admin-modal" id="template-create" aria-labelledby="template-create-title">'
            . '<div class="modal-header"><h2 id="template-create-title">New email template</h2>'
            . '<button type="button" class="modal-close" data-close-modal aria-label="Close dialog">×</button></div>'
            . $this->emailTemplateForm($applications) . '</dialog>';
        if (!$templates) {
            return $content . '<p class="empty-state">No email templates have been created.</p></section>';
        }
        $content .= '<div class="table-wrap"><table><thead><tr><th>Template</th><th>Status</th><th></th></tr></thead><tbody>';
        $dialogs = '';
        foreach ($templates as $template) {
            $id = (int) $template['id'];
            $isActive = (int) $template['is_active'] === 1;
            $content .= '<tr><td><strong class="table-primary">' . Http::escape($template['name'])
                . '</strong><small class="table-secondary">' . Http::escape($template['application_name']) . '</small></td>'
                . '<td><span class="status-badge '
                . ((int) $template['is_active'] === 1 ? 'is-active' : 'is-disabled') . '">'
                . ((int) $template['is_active'] === 1 ? 'Active' : 'Disabled') . '</span></td>'
                . '<td class="actions-cell"><div class="management-actions">'
                . '<button type="button" class="secondary management-action" data-open-modal="template-detail-' . $id . '">'
                . $this->actionIcon('detail') . '<span>Detail</span></button>'
                . '<button type="button" class="secondary management-action" data-open-modal="template-edit-' . $id . '">'
                . $this->actionIcon('edit') . '<span>Edit</span></button>'
                . '<form method="post" action="/admin/templates/toggle" class="management-action-form">' . $this->csrfInput()
                . '<input type="hidden" name="template_id" value="' . $id . '"><button class="secondary management-action">'
                . $this->actionIcon((int) $template['is_active'] === 1 ? 'disable' : 'enable')
                . '<span>' . ((int) $template['is_active'] === 1 ? 'Disable' : 'Enable') . '</span></button></form></div></td></tr>';
            $dialogs .= $this->detailDialog('template-detail-' . $id, 'Email template details', [
                'Name' => $template['name'],
                'Application' => $template['application_name'],
                'API slug' => $template['slug'],
                'Format' => $template['format'],
                'Subject template' => $template['subject_template'],
                'Message template' => $template['body_template'],
                'Status' => $isActive ? 'Active' : 'Disabled',
                'Created' => $template['created_at'],
                'Updated' => $template['updated_at'],
            ]) . '<dialog class="admin-modal" id="template-edit-' . $id . '" aria-labelledby="template-edit-title-' . $id . '">'
                . '<div class="modal-header"><h2 id="template-edit-title-' . $id . '">Edit email template</h2>'
                . '<button type="button" class="modal-close" data-close-modal aria-label="Close dialog">×</button></div>'
                . $this->emailTemplateForm($applications, $template) . '</dialog>';
        }
        return $content . '</tbody></table></div>' . $dialogs . '</section>';
    }

    private function emailTemplateForm(array $applications, ?array $template = null): string
    {
        $editing = $template !== null;
        $form = '<form method="post" action="/admin/templates/' . ($editing ? 'update' : 'create')
            . '" class="form-grid modal-form template-form">' . $this->csrfInput();
        if ($editing) {
            $form .= '<input type="hidden" name="template_id" value="' . (int) $template['id'] . '">';
        }
        $form .= '<label>Application <select name="application_id" required><option value="">Select an application</option>';
        foreach ($applications as $application) {
            $selected = $editing && (int) $template['application_id'] === (int) $application['id'] ? ' selected' : '';
            $form .= '<option value="' . (int) $application['id'] . '"' . $selected . '>'
                . Http::escape($application['name']) . '</option>';
        }
        return $form . '</select></label>'
            . '<label>Template name <input name="name" maxlength="120" required value="'
            . Http::escape($template['name'] ?? '') . '"></label>'
            . '<label>API slug <input name="slug" maxlength="80" pattern="[a-z0-9][a-z0-9_-]*" required value="'
            . Http::escape($template['slug'] ?? '') . '"><span class="form-help">Lowercase letters, numbers, hyphens, and underscores.</span></label>'
            . '<label>Format <select name="format" required><option value="text"'
            . (($template['format'] ?? 'text') === 'text' ? ' selected' : '') . '>Plain text</option><option value="html"'
            . (($template['format'] ?? '') === 'html' ? ' selected' : '') . '>HTML</option></select></label>'
            . '<label class="template-subject">Subject template <input name="subject_template" maxlength="255" required value="'
            . Http::escape($template['subject_template'] ?? '') . '"></label>'
            . '<label class="template-message">Message template <textarea class="template-body" name="body_template" rows="9" maxlength="50000" required>'
            . Http::escape($template['body_template'] ?? '') . '</textarea></label>'
            . '<p class="form-help template-help">For HTML templates, variable values are HTML-escaped before insertion.</p>'
            . '<div class="form-actions"><button>' . ($editing ? 'Save template' : 'Create template') . '</button>'
            . '<button type="button" class="secondary" data-close-modal>Cancel</button></div></form>';
    }

    private function sendEmailContent(PDO $pdo): string
    {
        $applications = $pdo->query(
            'SELECT a.id, a.name, a.default_to, a.default_sender_id, smtp.is_active AS smtp_is_active,
                    (SELECT COUNT(*) FROM application_senders x
                     JOIN senders s ON s.id = x.sender_id
                     WHERE x.application_id = a.id AND s.is_active = 1) AS active_sender_count
             FROM applications a
             LEFT JOIN smtp_servers smtp ON smtp.id = a.smtp_server_id
             WHERE a.is_active = 1 AND a.smtp_server_id IS NOT NULL AND smtp.is_active = 1
             ORDER BY a.name'
        )->fetchAll();
        $senders = $pdo->query(
            'SELECT x.application_id, s.id, s.email, s.sender_name
             FROM application_senders x
             JOIN applications a ON a.id = x.application_id AND a.is_active = 1
             JOIN smtp_servers smtp ON smtp.id = a.smtp_server_id AND smtp.is_active = 1
             JOIN senders s ON s.id = x.sender_id AND s.is_active = 1
             ORDER BY a.name, s.email'
        )->fetchAll();
        $senderOptions = [];
        foreach ($senders as $sender) {
            $senderId = (int) $sender['id'];
            if (!isset($senderOptions[$senderId])) {
                $senderOptions[$senderId] = [
                    'email' => $sender['email'],
                    'sender_name' => $sender['sender_name'],
                    'application_ids' => [],
                ];
            }
            $senderOptions[$senderId]['application_ids'][] = (int) $sender['application_id'];
        }
        $readyApplications = array_values(array_filter(
            $applications,
            static fn(array $application): bool => (int) $application['active_sender_count'] > 0
        ));

        $content = '<section class="content-section"><div class="section-heading"><div><h1 class="card-title">Send an email</h1>'
            . '<p>Send through an active application using its assigned SMTP server and sender identities.</p></div></div>';
        if (!$readyApplications) {
            return $content . '<p class="empty-state">No active application is ready to send. Configure an active SMTP server and at least one active sender for an application first.</p>'
                . '<p class="form-help"><a href="/admin/applications">Applications</a> · '
                . '<a href="/admin/smtp-servers">SMTP servers</a> · <a href="/admin/senders">Senders</a></p></section>';
        }

        $content .= '<form method="post" action="/admin/send-email" class="form-grid send-email-form">'
            . $this->csrfInput() . '<label>Application <select name="application_id" id="send-email-application" required>'
            . '<option value="">Select an application</option>';
        foreach ($readyApplications as $application) {
            $defaultTo = $application['default_to'] ?? '';
            $content .= '<option value="' . (int) $application['id'] . '" data-default-sender="'
                . (int) ($application['default_sender_id'] ?? 0) . '" data-default-recipient="'
                . Http::escape($defaultTo) . '">' . Http::escape($application['name']) . '</option>';
        }
        $content .= '</select></label><label>From <select name="sender_id" id="send-email-sender" required disabled>'
            . '<option value="">Select an application first</option>';
        foreach ($senderOptions as $senderId => $sender) {
            $content .= '<option value="' . $senderId . '" data-application-ids="'
                . Http::escape(implode(',', $sender['application_ids'])) . '">' . Http::escape($sender['email'])
                . ($sender['sender_name'] ? ' — ' . Http::escape($sender['sender_name']) : '') . '</option>';
        }
        $content .= '</select></label><label>To <input type="email" name="to" id="send-email-to" maxlength="254" required></label>'
            . '<label>Subject <input name="subject" maxlength="255" required></label>'
            . '<label>Format <select name="format"><option value="text">Plain text</option><option value="html">HTML</option></select></label>'
            . '<label class="body-field">Message <textarea name="body" maxlength="50000" rows="10" required></textarea></label>'
            . '<div class="form-actions"><button>Send email</button></div>'
            . '</form></section>';
        return $content;
    }

    private function adminDocsContent(): string
    {
        return '<section class="content-section docs-content"><h1 class="card-title">Admin guide</h1>'
            . '<p>Manage SMTP delivery, sender identities, applications, and API access from the administration menu.</p>'
            . '<h3>Configure an application</h3><ol>'
            . '<li>Open <a href="/admin/smtp-servers">SMTP servers</a>, add the central SMTP connection, and use <strong>Test connection</strong>. The test checks connectivity and authentication; it does not send an email.</li>'
            . '<li>Add one or more active addresses under <a href="/admin/senders">Senders</a>.</li>'
            . '<li>In <a href="/admin/applications">Applications</a>, assign the SMTP server and allowed senders. Choose a default sender and, if useful, a default recipient.</li>'
            . '<li>Create an application-scoped key under <a href="/admin/tokens">API tokens</a>. Copy and store it securely when it is displayed; it cannot be viewed again.</li>'
            . '</ol>'
            . '<h3>Send and review messages</h3>'
            . '<p>Use <a href="/admin/send-email">Messaging → Send email</a> to send a message manually. Select an active application and one of its assigned senders, then enter the recipient, subject, format, and message. A configured default recipient is prefilled but can be changed. Sending happens immediately.</p>'
            . '<p><a href="/admin/templates">Messaging → Email templates</a> lets you create application-scoped templates for API requests. Their variables use <code>{{name}}</code> placeholders; values inserted into HTML templates are escaped.</p>'
            . '<p><a href="/admin/email-history">Messaging → Email history</a> shows searchable, paginated delivery attempts, including status and errors. Message bodies are not stored. Revoke unused or exposed keys from API tokens, and update the application if its SMTP server or sender assignments change.</p>'
            . '</section>';
    }

    private function docsContent(): string
    {
        $phpExample = <<<'PHP'
<?php

$payload = [
    'to' => 'recipient@example.com',
    'from' => 'billing@example.com',
    'subject' => 'Order confirmation',
    'body' => '<p>Thank you for your order.</p>',
    'format' => 'html',
];

$curl = curl_init('https://mail.example.com/send');
curl_setopt_array($curl, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => [
        'Authorization: Bearer ' . getenv('MAIL_API_TOKEN'),
        'Content-Type: application/json',
    ],
    CURLOPT_POSTFIELDS => json_encode($payload, JSON_THROW_ON_ERROR),
    CURLOPT_TIMEOUT => 20,
]);

$response = curl_exec($curl);
if ($response === false) {
    throw new RuntimeException('MailAPI connection failed: ' . curl_error($curl));
}
$status = curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
curl_close($curl);

$result = json_decode($response, true, 32, JSON_THROW_ON_ERROR);
if ($status < 200 || $status >= 300 || !($result['success'] ?? false)) {
    throw new RuntimeException($result['error']['message'] ?? 'MailAPI request failed.');
}
PHP;
        $requestJson = json_encode([
            'to' => 'recipient@example.com',
            'from' => 'billing@example.com',
            'subject' => 'Order confirmation',
            'body' => '<p>Thank you for your order.</p>',
            'format' => 'html',
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $templateRequestJson = json_encode([
            'to' => 'recipient@example.com',
            'from' => 'billing@example.com',
            'template' => 'order-confirmation',
            'variables' => [
                'customer_name' => 'Alex',
                'order_id' => 'A-1042',
            ],
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        return '<section class="content-section docs-content"><h1 class="card-title">MailAPI documentation</h1>'
            . '<p>Send email through the SMTP server assigned to an application.</p>'
            . '<h3>Endpoint</h3><pre><code>POST ' . Http::escape(Http::url('/send')) . '
Content-Type: application/json
Authorization: Bearer YOUR_API_TOKEN</code></pre>'
            . '<h3>Request body</h3><pre><code>' . $this->highlightJson($requestJson) . '</code></pre>'
            . '<h3>Direct-send request fields</h3><ul><li><code>to</code>: one recipient email; may be omitted when the application has a default recipient.</li>'
            . '<li><code>from</code>: optional sender email, restricted to active sender addresses assigned to the application. When omitted, the application default is used.</li>'
            . '<li><code>subject</code>: required, 1–255 characters, no line breaks.</li>'
            . '<li><code>body</code>: required, 1–50,000 characters.</li>'
            . '<li><code>format</code>: <code>text</code> or <code>html</code>; defaults to <code>text</code>.</li></ul>'
            . '<h3>Using an email template</h3><p>Alternatively, send <code>template</code> and an optional <code>variables</code> object. In this mode, omit <code>subject</code>, <code>body</code>, and <code>format</code>; those are defined by the template.</p>'
            . '<pre><code>' . $this->highlightJson($templateRequestJson) . '</code></pre>'
            . '<p>Templates must be active and assigned to the application associated with the Bearer token. Add templates under Messaging → Email templates. Replace placeholders such as <code>{{customer_name}}</code> in the subject or body. Every referenced variable is required and must be a string, number, or boolean. Values inserted into HTML templates are escaped. Existing direct subject/body requests continue to work.</p>'
            . '<h3>Successful response</h3><pre><code>' . $this->highlightJson('{"success":true,"data":{"message":"The email was sent.","id":123}}') . '</code></pre>'
            . '<h3>Error response</h3><pre><code>' . $this->highlightJson('{"success":false,"error":{"code":"sender_not_allowed","message":"This address is not an active sender for the application."}}') . '</code></pre>'
            . '<p>HTTP statuses include 400, 401, 403, 404, 405, 413, 415, 422, 429, 502, and 503. Each API token is limited to 30 requests per minute by default.</p>'
            . '<h3>PHP example</h3><pre><code>' . $this->highlightPhp($phpExample) . '</code></pre>'
            . '<h3>Configure delivery</h3><ol><li>Create an SMTP server and test its connection.</li>'
            . '<li>Create sender addresses, then assign an SMTP server, allowed senders, and a default sender to an application.</li>'
            . '<li>Create an API token for that application. The token is shown only once; store it securely.</li></ol>'
            . '<h3>Security and delivery history</h3><p>SMTP passwords are encrypted at rest. API tokens are stored as hashes. Email bodies are not stored in delivery history. HTTPS is not enforced, but is strongly recommended in production to protect credentials and messages in transit. Use SMTP over TLS or SSL and restrict access to the database and configuration.</p>'
            . '<p>Messages submitted with the API use the same application settings and are visible in Email history.</p></section>';
    }

    private function highlightJson(string $json): string
    {
        json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        $pattern = <<<'REGEX'
/"((?:\\\\.|[^"\\\\])*)"(?=\s*:)|"((?:\\\\.|[^"\\\\])*)"|(-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)|\b(true|false|null)\b|([{}\[\],:])/
REGEX;
        $highlighted = preg_replace_callback(
            $pattern,
            static function (array $matches): string {
                foreach ([1 => 'syntax-key', 2 => 'syntax-string', 3 => 'syntax-number', 4 => 'syntax-literal', 5 => 'syntax-punctuation'] as $index => $class) {
                    if (($matches[$index] ?? '') !== '') {
                        return '<span class="' . $class . '">' . Http::escape($matches[0]) . '</span>';
                    }
                }
                return Http::escape($matches[0]);
            },
            $json
        );
        if ($highlighted === null) {
            throw new \RuntimeException('Unable to highlight JSON documentation.');
        }
        return $highlighted;
    }

    private function highlightPhp(string $source): string
    {
        $highlighted = '';
        foreach (token_get_all($source) as $token) {
            if (is_string($token)) {
                $highlighted .= Http::escape($token);
                continue;
            }

            [$id, $text] = $token;
            $class = match ($id) {
                T_COMMENT, T_DOC_COMMENT => 'syntax-comment',
                T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE => 'syntax-string',
                T_VARIABLE => 'syntax-variable',
                T_LNUMBER, T_DNUMBER => 'syntax-number',
                T_IF, T_RETURN, T_THROW, T_NEW, T_FUNCTION, T_USE, T_ARRAY, T_FOREACH,
                T_AS, T_TRY, T_CATCH, T_FINALLY, T_ELSE, T_ELSEIF => 'syntax-keyword',
                T_STRING => in_array(strtolower($text), ['true', 'false', 'null'], true)
                    ? 'syntax-literal' : 'syntax-name',
                default => '',
            };
            $escaped = Http::escape($text);
            $highlighted .= $class === ''
                ? $escaped
                : '<span class="' . $class . '">' . $escaped . '</span>';
        }
        return $highlighted;
    }

    private function logTable(array $logs, bool $showServer = false): string
    {
        $columns = $showServer ? '<th>Recipient</th>' : '';
        $content = '<div class="table-wrap"><table><thead><tr><th>Time (UTC)</th><th>Application</th>'
            . $columns . '<th>Subject</th><th>Status</th><th></th></tr></thead><tbody>';
        $dialogs = '';
        foreach ($logs as $log) {
            $statusClass = match ($log['status']) {
                'sent' => 'is-active',
                'failed' => 'is-error',
                default => 'is-pending',
            };
            $content .= '<tr><td>' . Http::escape($log['created_at']) . '</td><td>'
                . Http::escape($log['application_name']) . '</td>';
            if ($showServer) {
                $content .= '<td>' . Http::escape($log['recipient']) . '</td>';
            }
            $content .= '<td>' . Http::escape($log['subject']) . '</td><td><span class="status-badge '
                . $statusClass . '">' . Http::escape($log['status']) . '</span></td>'
                . '<td class="actions-cell"><div class="management-actions"><button type="button" class="secondary management-action"'
                . ' data-open-modal="email-log-detail-' . (int) $log['id'] . '">'
                . $this->actionIcon('detail') . '<span>Detail</span></button></div></td></tr>';
            $dialogs .= $this->detailDialog('email-log-detail-' . (int) $log['id'], 'Email details', [
                'Log ID' => (string) $log['id'],
                'Application' => $log['application_name'],
                'SMTP server' => $log['smtp_server_name'] ?? 'Unavailable',
                'Template' => $log['template_slug'] ?? '—',
                'Sender' => $log['sender'],
                'Recipient' => $log['recipient'],
                'Subject' => $log['subject'],
                'Format' => $log['format'],
                'Status' => $log['status'],
                'Error' => $log['error_message'] ?: '—',
                'Created (UTC)' => $log['created_at'],
                'Sent (UTC)' => $log['sent_at'] ?: '—',
            ]);
        }
        if (!$logs) {
            $content .= '<tr><td colspan="' . ($showServer ? '6' : '5') . '">'
                . ($showServer ? 'No email attempts match these filters.' : 'No emails have been sent yet.')
                . '</td></tr>';
        }
        return $content . '</tbody></table></div>' . $dialogs;
    }

    private function detailDialog(string $id, string $title, array $fields): string
    {
        $content = '<dialog class="admin-modal detail-modal" id="' . Http::escape($id)
            . '" aria-labelledby="' . Http::escape($id) . '-title">'
            . '<div class="modal-header"><h2 id="' . Http::escape($id) . '-title">' . Http::escape($title) . '</h2>'
            . '<button type="button" class="modal-close" data-close-modal aria-label="Close dialog">×</button></div>'
            . '<dl class="detail-list">';
        foreach ($fields as $label => $value) {
            $wide = in_array($label, ['Allowed senders', 'Assigned applications', 'Subject template', 'Message template', 'Error'], true)
                ? ' detail-item-wide'
                : '';
            $content .= '<div class="detail-item' . $wide . '"><dt>' . Http::escape((string) $label) . '</dt><dd class="detail-value">'
                . Http::escape((string) $value) . '</dd></div>';
        }
        return $content . '</dl></dialog>';
    }

    private function postAction(string $path): void
    {
        $pdo = Database::connection();
        if ($path === '/admin/applications/create') {
            [$name, $slug] = $this->applicationIdentity($_POST['name'] ?? null, $_POST['slug'] ?? '');
            $defaultTo = $this->optionalEmail($_POST['default_to'] ?? '');
            $statement = $pdo->prepare('INSERT INTO applications (name, slug, default_to) VALUES (?, ?, ?)');
            $statement->execute([$name, $slug, $defaultTo ?: null]);
            return;
        }

        if ($path === '/admin/applications/update') {
            $applicationId = (int) ($_POST['application_id'] ?? 0);
            $this->requireApplication($pdo, $applicationId);
            [$name, $slug] = $this->applicationIdentity($_POST['name'] ?? null, $_POST['slug'] ?? '');
            $defaultTo = $this->optionalEmail($_POST['default_to'] ?? '');
            $smtpServerId = $this->optionalId($_POST['smtp_server_id'] ?? '', 'SMTP server');
            if ($smtpServerId !== null) {
                $this->requireRecord($pdo, 'smtp_servers', $smtpServerId, 'SMTP server');
            }
            $senderIds = $this->idList($_POST['sender_ids'] ?? []);
            $this->requireSenderRecords($pdo, $senderIds);
            $defaultSenderId = $this->optionalId($_POST['default_sender_id'] ?? '', 'default sender');
            if ($defaultSenderId !== null && !in_array($defaultSenderId, $senderIds, true)) {
                throw new \RuntimeException('The default sender must also be assigned to this application.');
            }
            if ($defaultSenderId !== null) {
                $defaultSender = $pdo->prepare('SELECT is_active FROM senders WHERE id = ?');
                $defaultSender->execute([$defaultSenderId]);
                if ((int) $defaultSender->fetchColumn() !== 1) {
                    throw new \RuntimeException('The default sender must be active.');
                }
            }

            $pdo->beginTransaction();
            try {
                $pdo->prepare(
                    'UPDATE applications
                     SET name = ?, slug = ?, default_to = ?, smtp_server_id = ?, default_sender_id = ?
                     WHERE id = ?'
                )->execute([$name, $slug, $defaultTo ?: null, $smtpServerId, $defaultSenderId, $applicationId]);
                $pdo->prepare('DELETE FROM application_senders WHERE application_id = ?')->execute([$applicationId]);
                $assignment = $pdo->prepare(
                    'INSERT INTO application_senders (application_id, sender_id) VALUES (?, ?)'
                );
                foreach ($senderIds as $senderId) {
                    $assignment->execute([$applicationId, $senderId]);
                }
                $pdo->commit();
            } catch (Throwable $exception) {
                $pdo->rollBack();
                throw $exception;
            }
            return;
        }

        if ($path === '/admin/applications/toggle') {
            $applicationId = (int) ($_POST['application_id'] ?? 0);
            $this->requireApplication($pdo, $applicationId);
            $pdo->prepare('UPDATE applications SET is_active = 1 - is_active WHERE id = ?')->execute([$applicationId]);
            return;
        }

        if ($path === '/admin/smtp-servers/create') {
            $settings = $this->smtpServerSettings(true);
            $pdo->prepare(
                'INSERT INTO smtp_servers (name, host, port, username, password_encrypted, encryption)
                 VALUES (?, ?, ?, ?, ?, ?)'
            )->execute([
                $settings['name'],
                $settings['host'],
                $settings['port'],
                $settings['username'],
                SecretCipher::encrypt($settings['password']),
                $settings['encryption'],
            ]);
            return;
        }

        if ($path === '/admin/smtp-servers/update') {
            $serverId = (int) ($_POST['server_id'] ?? 0);
            $this->requireRecord($pdo, 'smtp_servers', $serverId, 'SMTP server');
            $settings = $this->smtpServerSettings(false);
            $sql = 'UPDATE smtp_servers SET name = ?, host = ?, port = ?, username = ?, encryption = ?';
            $parameters = [
                $settings['name'],
                $settings['host'],
                $settings['port'],
                $settings['username'],
                $settings['encryption'],
            ];
            if ($settings['password'] !== '') {
                $sql .= ', password_encrypted = ?';
                $parameters[] = SecretCipher::encrypt($settings['password']);
            }
            $sql .= ' WHERE id = ?';
            $parameters[] = $serverId;
            $pdo->prepare($sql)->execute($parameters);
            return;
        }

        if ($path === '/admin/smtp-servers/toggle') {
            $serverId = (int) ($_POST['server_id'] ?? 0);
            $this->requireRecord($pdo, 'smtp_servers', $serverId, 'SMTP server');
            $pdo->prepare('UPDATE smtp_servers SET is_active = 1 - is_active WHERE id = ?')->execute([$serverId]);
            return;
        }

        if ($path === '/admin/smtp-servers/test') {
            $serverId = (int) ($_POST['server_id'] ?? 0);
            $this->requireRecord($pdo, 'smtp_servers', $serverId, 'SMTP server');
            $statement = $pdo->prepare('SELECT * FROM smtp_servers WHERE id = ?');
            $statement->execute([$serverId]);
            $server = $statement->fetch();
            if (!$server) {
                throw new \RuntimeException('SMTP server not found.');
            }
            (new MailService())->testConnection($server);
            return;
        }

        if ($path === '/admin/senders/create') {
            $settings = $this->senderSettings();
            $pdo->prepare('INSERT INTO senders (email, sender_name) VALUES (?, ?)')
                ->execute([$settings['email'], $settings['sender_name'] ?: null]);
            return;
        }

        if ($path === '/admin/senders/update') {
            $senderId = (int) ($_POST['sender_id'] ?? 0);
            $this->requireRecord($pdo, 'senders', $senderId, 'Sender');
            $settings = $this->senderSettings();
            $pdo->prepare('UPDATE senders SET email = ?, sender_name = ? WHERE id = ?')
                ->execute([$settings['email'], $settings['sender_name'] ?: null, $senderId]);
            return;
        }

        if ($path === '/admin/senders/toggle') {
            $senderId = (int) ($_POST['sender_id'] ?? 0);
            $this->requireRecord($pdo, 'senders', $senderId, 'Sender');
            $pdo->prepare('UPDATE senders SET is_active = 1 - is_active WHERE id = ?')->execute([$senderId]);
            return;
        }

        if ($path === '/admin/send-email') {
            $applicationId = (int) ($_POST['application_id'] ?? 0);
            $senderId = (int) ($_POST['sender_id'] ?? 0);
            $recipient = $this->optionalEmail($_POST['to'] ?? null);
            if ($recipient === '') {
                throw new \RuntimeException('The recipient email is required.');
            }

            $subject = $_POST['subject'] ?? null;
            if (!is_string($subject)) {
                throw new \RuntimeException('The subject must be text.');
            }
            $subject = trim($subject);
            if ($subject === '' || strlen($subject) > 255 || preg_match('/[\r\n]/', $subject)) {
                throw new \RuntimeException('The subject must be 1 to 255 characters and contain no line breaks.');
            }

            $body = $_POST['body'] ?? null;
            if (!is_string($body) || trim($body) === '' || strlen($body) > 50000) {
                throw new \RuntimeException('The message must contain 1 to 50,000 characters.');
            }
            $format = $_POST['format'] ?? 'text';
            if (!is_string($format) || !in_array($format, ['text', 'html'], true)) {
                throw new \RuntimeException('Select text or HTML message format.');
            }

            $senderQuery = $pdo->prepare(
                'SELECT sender.id AS sender_id, sender.email, sender.sender_name,
                        smtp.id AS smtp_server_id, smtp.host AS smtp_host, smtp.port AS smtp_port,
                        smtp.username AS smtp_username, smtp.password_encrypted AS smtp_password_encrypted,
                        smtp.encryption AS smtp_encryption
                 FROM applications a
                 JOIN smtp_servers smtp ON smtp.id = a.smtp_server_id AND smtp.is_active = 1
                 JOIN application_senders assigned ON assigned.application_id = a.id
                 JOIN senders sender ON sender.id = assigned.sender_id AND sender.is_active = 1
                 WHERE a.id = ? AND a.is_active = 1 AND sender.id = ?
                 LIMIT 1'
            );
            $senderQuery->execute([$applicationId, $senderId]);
            $sender = $senderQuery->fetch();
            if (!$sender) {
                throw new \RuntimeException('Choose an active application, its assigned sender, and an active SMTP server.');
            }

            $pdo->prepare(
                'INSERT INTO email_logs
                    (smtp_server_id, sender_id, application_id, recipient, sender, subject, format, status, ip_address)
                 VALUES (?, ?, ?, ?, ?, ?, ?, "pending", ?)'
            )->execute([
                $sender['smtp_server_id'],
                $sender['sender_id'],
                $applicationId,
                $recipient,
                $sender['email'],
                $subject,
                $format,
                substr($_SERVER['REMOTE_ADDR'] ?? '', 0, 45),
            ]);
            $logId = (int) $pdo->lastInsertId();

            $sessionWasActive = session_status() === PHP_SESSION_ACTIVE;
            if ($sessionWasActive) {
                session_write_close();
            }
            try {
                try {
                    (new MailService())->send($recipient, $subject, $body, $format, $sender);
                } catch (Throwable $exception) {
                    $pdo->prepare('UPDATE email_logs SET status = "failed", error_message = ? WHERE id = ?')
                        ->execute([substr($exception->getMessage(), 0, 2000), $logId]);
                    throw new \RuntimeException(
                        'Email delivery failed. Check the email history for details.',
                        0,
                        $exception
                    );
                }
                $pdo->prepare('UPDATE email_logs SET status = "sent", sent_at = UTC_TIMESTAMP() WHERE id = ?')
                    ->execute([$logId]);
            } finally {
                if ($sessionWasActive && !session_start()) {
                    throw new \RuntimeException('Could not resume the administrator session after email delivery.');
                }
            }
            return;
        }

        if ($path === '/admin/templates/create') {
            $settings = $this->emailTemplateSettings($pdo);
            $pdo->prepare(
                'INSERT INTO email_templates
                    (application_id, slug, name, subject_template, body_template, format)
                 VALUES (?, ?, ?, ?, ?, ?)'
            )->execute([
                $settings['application_id'],
                $settings['slug'],
                $settings['name'],
                $settings['subject_template'],
                $settings['body_template'],
                $settings['format'],
            ]);
            return;
        }

        if ($path === '/admin/templates/update') {
            $templateId = (int) ($_POST['template_id'] ?? 0);
            $this->requireRecord($pdo, 'email_templates', $templateId, 'Email template');
            $settings = $this->emailTemplateSettings($pdo);
            $pdo->prepare(
                'UPDATE email_templates
                 SET application_id = ?, slug = ?, name = ?, subject_template = ?, body_template = ?, format = ?
                 WHERE id = ?'
            )->execute([
                $settings['application_id'],
                $settings['slug'],
                $settings['name'],
                $settings['subject_template'],
                $settings['body_template'],
                $settings['format'],
                $templateId,
            ]);
            return;
        }

        if ($path === '/admin/templates/toggle') {
            $templateId = (int) ($_POST['template_id'] ?? 0);
            $this->requireRecord($pdo, 'email_templates', $templateId, 'Email template');
            $pdo->prepare('UPDATE email_templates SET is_active = 1 - is_active WHERE id = ?')
                ->execute([$templateId]);
            return;
        }

        if ($path === '/admin/tokens/create') {
            $applicationId = (int) ($_POST['application_id'] ?? 0);
            $this->requireApplication($pdo, $applicationId);
            $name = trim((string) ($_POST['name'] ?? ''));
            if ($name === '' || strlen($name) > 120) {
                throw new \RuntimeException('The token name must be 1 to 120 characters long.');
            }
            $rawToken = 'mapi_' . rtrim(strtr(base64_encode(random_bytes(36)), '+/', '-_'), '=');
            $statement = $pdo->prepare('INSERT INTO api_tokens (application_id, name, token_hash) VALUES (?, ?, ?)');
            $statement->execute([$applicationId, $name, hash('sha256', $rawToken)]);
            $_SESSION['new_token'] = $rawToken;
            return;
        }

        if ($path === '/admin/tokens/revoke') {
            $statement = $pdo->prepare('UPDATE api_tokens SET revoked_at = UTC_TIMESTAMP() WHERE id = ? AND revoked_at IS NULL');
            $statement->execute([(int) ($_POST['token_id'] ?? 0)]);
            if ($statement->rowCount() === 0) {
                throw new \RuntimeException('No active token was found.');
            }
            return;
        }

        throw new \RuntimeException('Unknown administration action.');
    }

    private function optionalEmail(mixed $value): string
    {
        if (!is_string($value)) {
            throw new \RuntimeException('Email must be a string.');
        }
        $value = trim($value);
        if ($value !== '' && (!filter_var($value, FILTER_VALIDATE_EMAIL) || strlen($value) > 254)) {
            throw new \RuntimeException('Enter a valid email address.');
        }
        return $value;
    }

    private function emailTemplateSettings(PDO $pdo): array
    {
        $applicationId = $this->optionalId($_POST['application_id'] ?? '', 'application');
        if ($applicationId === null) {
            throw new \RuntimeException('Select an application for the email template.');
        }
        $this->requireApplication($pdo, $applicationId);

        $name = $_POST['name'] ?? null;
        $slug = $_POST['slug'] ?? null;
        $subject = $_POST['subject_template'] ?? null;
        $body = $_POST['body_template'] ?? null;
        $format = $_POST['format'] ?? null;
        if (!is_string($name) || trim($name) === '' || strlen(trim($name)) > 120
            || preg_match('/[\x00-\x1F]/', $name)) {
            throw new \RuntimeException('The template name must be 1 to 120 characters and contain no control characters.');
        }
        if (!is_string($slug) || !preg_match('/^[a-z0-9][a-z0-9_-]{0,79}$/', $slug)) {
            throw new \RuntimeException('The template slug must start with a lowercase letter or number and contain only lowercase letters, numbers, hyphens, or underscores.');
        }
        if (!is_string($subject) || trim($subject) === '' || strlen(trim($subject)) > 255
            || preg_match('/[\r\n\x00-\x1F]/', $subject)) {
            throw new \RuntimeException('The subject template must be 1 to 255 characters and contain no line breaks.');
        }
        if (!is_string($body) || trim($body) === '' || strlen($body) > 50000
            || str_contains($body, "\0")) {
            throw new \RuntimeException('The message template must be 1 to 50000 characters and contain no null bytes.');
        }
        if (!is_string($format) || !in_array($format, ['text', 'html'], true)) {
            throw new \RuntimeException('Choose text or HTML template format.');
        }
        return [
            'application_id' => $applicationId,
            'slug' => $slug,
            'name' => trim($name),
            'subject_template' => trim($subject),
            'body_template' => $body,
            'format' => $format,
        ];
    }

    private function applicationIdentity(mixed $rawName, mixed $rawSlug): array
    {
        if (!is_string($rawName) || !is_string($rawSlug)) {
            throw new \RuntimeException('Application name and slug must be text.');
        }
        $name = trim($rawName);
        if ($name === '' || strlen($name) > 120) {
            throw new \RuntimeException('The application name must be 1 to 120 characters long.');
        }
        $slug = strtolower(trim($rawSlug));
        if ($slug === '') {
            $transliterated = iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $name);
            $slug = strtolower(trim(preg_replace('/[^a-z0-9]+/i', '-', $transliterated ?: $name) ?? '', '-'));
        }
        if (!preg_match('/^[a-z0-9][a-z0-9-]{0,79}$/', $slug)) {
            throw new \RuntimeException('The slug may contain only lowercase letters, numbers, and hyphens.');
        }
        return [$name, $slug];
    }

    private function optionalId(mixed $value, string $label): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }
        if ((!is_string($value) && !is_int($value)) || !ctype_digit((string) $value) || (int) $value < 1) {
            throw new \RuntimeException("Select a valid {$label}.");
        }
        return (int) $value;
    }

    private function idList(mixed $values): array
    {
        if (!is_array($values)) {
            throw new \RuntimeException('Sender selection is invalid.');
        }
        $ids = [];
        foreach ($values as $value) {
            $id = $this->optionalId($value, 'sender');
            if ($id === null) {
                throw new \RuntimeException('Sender selection is invalid.');
            }
            $ids[$id] = $id;
        }
        return array_values($ids);
    }

    private function requireSenderRecords(PDO $pdo, array $senderIds): void
    {
        if (!$senderIds) {
            return;
        }
        $placeholders = implode(',', array_fill(0, count($senderIds), '?'));
        $statement = $pdo->prepare("SELECT id FROM senders WHERE id IN ({$placeholders})");
        $statement->execute($senderIds);
        if (count($statement->fetchAll()) !== count($senderIds)) {
            throw new \RuntimeException('One or more selected senders do not exist.');
        }
    }

    private function requireApplication(PDO $pdo, int $applicationId): void
    {
        $this->requireRecord($pdo, 'applications', $applicationId, 'Application');
    }

    private function requireRecord(PDO $pdo, string $table, int $id, string $label): void
    {
        if (!in_array($table, ['applications', 'smtp_servers', 'senders', 'email_templates'], true) || $id < 1) {
            throw new \RuntimeException("{$label} not found.");
        }
        $statement = $pdo->prepare("SELECT id FROM {$table} WHERE id = ?");
        $statement->execute([$id]);
        if (!$statement->fetch()) {
            throw new \RuntimeException("{$label} not found.");
        }
    }

    private function senderSettings(): array
    {
        $email = $this->optionalEmail($_POST['email'] ?? null);
        if ($email === '') {
            throw new \RuntimeException('The sender email is required.');
        }
        $senderName = $_POST['sender_name'] ?? '';
        if (!is_string($senderName) || strlen(trim($senderName)) > 120
            || preg_match('/[\r\n\x00-\x1F]/', $senderName)) {
            throw new \RuntimeException('The sender name must be at most 120 characters and contain no control characters.');
        }
        return ['email' => $email, 'sender_name' => trim($senderName)];
    }

    private function smtpServerSettings(bool $requirePassword): array
    {
        $name = $_POST['name'] ?? '';
        $host = $_POST['host'] ?? '';
        $port = $_POST['port'] ?? '';
        $username = $_POST['username'] ?? '';
        $password = $_POST['password'] ?? '';
        $encryption = $_POST['encryption'] ?? '';
        if (!is_string($name) || trim($name) === '' || strlen(trim($name)) > 120
            || preg_match('/[\r\n\x00-\x1F]/', $name)) {
            throw new \RuntimeException('The SMTP server name must be 1 to 120 characters and contain no control characters.');
        }
        if (!is_string($host) || strlen($host) > 253
            || (filter_var($host, FILTER_VALIDATE_IP) === false
                && filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false
                && $host !== 'localhost')) {
            throw new \RuntimeException('Enter a valid SMTP host or IP address.');
        }
        if (!is_string($port) || !ctype_digit($port) || (int) $port < 1 || (int) $port > 65535) {
            throw new \RuntimeException('The SMTP port must be a number from 1 to 65535.');
        }
        if (!is_string($username) || trim($username) === '' || strlen($username) > 255
            || preg_match('/[\r\n\x00]/', $username)) {
            throw new \RuntimeException('The SMTP username is invalid.');
        }
        if (!is_string($password) || strlen($password) > 512 || ($requirePassword && $password === '')) {
            throw new \RuntimeException($requirePassword ? 'The SMTP password is required.' : 'The SMTP password is too long.');
        }
        if (!is_string($encryption) || !in_array($encryption, ['tls', 'ssl'], true)) {
            throw new \RuntimeException('SMTP encryption must be TLS or SSL.');
        }
        return [
            'name' => trim($name),
            'host' => $host,
            'port' => (int) $port,
            'username' => trim($username),
            'password' => $password,
            'encryption' => $encryption,
        ];
    }

    private function smtpServerForm(?array $server = null): string
    {
        $editing = $server !== null;
        $form = '<form method="post" action="/admin/smtp-servers/' . ($editing ? 'update' : 'create')
            . '" class="form-grid">' . $this->csrfInput();
        if ($editing) {
            $form .= '<input type="hidden" name="server_id" value="' . (int) $server['id'] . '">';
        }
        $form .= '<label>Server name <input name="name" maxlength="120" required value="'
            . Http::escape($server['name'] ?? '') . '"></label>'
            . '<label>SMTP host <input name="host" maxlength="253" required value="'
            . Http::escape($server['host'] ?? '') . '"></label>'
            . '<label>Port <input type="number" name="port" min="1" max="65535" required value="'
            . Http::escape(isset($server['port']) ? (string) $server['port'] : '587') . '"></label>'
            . '<label>Username <input name="username" maxlength="255" required value="'
            . Http::escape($server['username'] ?? '') . '"></label>'
            . '<label>Password <input type="password" name="password" maxlength="512" '
            . ($editing ? 'autocomplete="new-password" placeholder="Leave blank to keep the current password"' : 'required autocomplete="new-password"')
            . '></label><label>Encryption <select name="encryption" required>'
            . '<option value="tls"' . (($server['encryption'] ?? 'tls') === 'tls' ? ' selected' : '') . '>TLS (STARTTLS)</option>'
            . '<option value="ssl"' . (($server['encryption'] ?? '') === 'ssl' ? ' selected' : '') . '>SSL</option>'
            . '</select></label><div class="form-actions"><button>'
            . ($editing ? 'Save SMTP server' : 'Add SMTP server') . '</button>'
            . ($editing ? '<button type="button" class="secondary" data-close-modal>Cancel</button>' : '')
            . '</div></form>';
        return $form;
    }

    private function senderForm(?array $sender = null): string
    {
        $editing = $sender !== null;
        $form = '<form method="post" action="/admin/senders/' . ($editing ? 'update' : 'create')
            . '" class="form-grid">' . $this->csrfInput();
        if ($editing) {
            $form .= '<input type="hidden" name="sender_id" value="' . (int) $sender['id'] . '">';
        }
        return $form
            . '<label>Email address <input type="email" name="email" maxlength="254" required value="'
            . Http::escape($sender['email'] ?? '') . '"></label>'
            . '<label>Display name <input name="sender_name" maxlength="120" value="'
            . Http::escape($sender['sender_name'] ?? '') . '"></label>'
            . '<div class="form-actions"><button>' . ($editing ? 'Save sender' : 'Add sender') . '</button>'
            . ($editing ? '<button type="button" class="secondary" data-close-modal>Cancel</button>' : '')
            . '</div></form>';
    }

    private function pageForAction(string $path): string
    {
        if (str_starts_with($path, '/admin/applications/')) {
            return '/admin/applications';
        }
        if (str_starts_with($path, '/admin/smtp-servers/')) {
            return '/admin/smtp-servers';
        }
        if (str_starts_with($path, '/admin/senders/')) {
            return '/admin/senders';
        }
        if (str_starts_with($path, '/admin/tokens/')) {
            return '/admin/tokens';
        }
        if (str_starts_with($path, '/admin/templates/')) {
            return '/admin/templates';
        }
        if ($path === '/admin/send-email') {
            return '/admin/send-email';
        }
        return '/admin';
    }

    private function requirePost(string $method): void
    {
        if ($method !== 'POST') {
            http_response_code(405);
            header('Allow: POST');
            $this->page('Error', '<p>The POST method is required.</p>', true);
        }
    }

    private function csrfInput(): string
    {
        $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
        return '<input type="hidden" name="csrf" value="' . Http::escape($_SESSION['csrf']) . '">';
    }

    private function validCsrf(mixed $value): bool
    {
        return is_string($value) && isset($_SESSION['csrf']) && hash_equals($_SESSION['csrf'], $value);
    }

    private function checkCsrf(): void
    {
        if (!$this->validCsrf($_POST['csrf'] ?? null)) {
            http_response_code(400);
            $this->page('Invalid request', $this->toastStack(
                $this->toast('error', 'Invalid request', 'The security token expired. Reload the page and try again.')
            ), true);
        }
    }

    private function navigationLink(string $route, string $label, string $icon): string
    {
        $current = $this->currentPath === $route ? ' current' : '';
        return '<a class="nav-link' . $current . '" href="' . Http::escape($route) . '">'
            . $this->navigationIcon($icon) . '<span>' . Http::escape($label) . '</span></a>';
    }

    private function navigationIcon(string $icon): string
    {
        $paths = match ($icon) {
            'overview' => '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
            'send' => '<path d="m21 3-7.5 18-3.8-7.7L2 9.5 21 3Z"/><path d="m9.7 13.3 4.8-4.8"/>',
            'history' => '<path d="M3 11a9 9 0 1 1 2.6 6.4"/><path d="M3 4v7h7"/><path d="M12 7v5l3 2"/>',
            'template' => '<path d="M4 4h16v16H4z"/><path d="M8 8h8M8 12h8M8 16h5"/>',
            'applications' => '<rect x="3" y="3" width="8" height="8" rx="1"/><rect x="13" y="3" width="8" height="8" rx="1"/><rect x="3" y="13" width="8" height="8" rx="1"/><rect x="13" y="13" width="8" height="8" rx="1"/>',
            'server' => '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01M11 7.5h6M11 16.5h6"/>',
            'senders' => '<circle cx="9" cy="8" r="3"/><path d="M3 20v-1a6 6 0 0 1 12 0v1H3ZM17 11a3 3 0 1 0-1-5.8M18 14a5 5 0 0 1 3 4.6v1h-3"/>',
            'key' => '<circle cx="8" cy="15" r="5"/><path d="m11.5 11.5 8-8L22 6l-2 2 1.5 1.5L19 12l-1.5-1.5-2 2"/>',
            'api' => '<path d="m8 5-5 7 5 7M16 5l5 7-5 7M14 4l-4 16"/>',
            'admin' => '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0M18 8h4M20 6v4"/>',
            default => throw new \LogicException('Unknown navigation icon.'),
        };
        return '<svg class="nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"'
            . ' stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            . $paths . '</svg>';
    }

    private function actionIcon(string $icon): string
    {
        $paths = match ($icon) {
            'edit' => '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z"/>',
            'detail' => '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
            'disable' => '<circle cx="12" cy="12" r="9"/><path d="m5.6 5.6 12.8 12.8"/>',
            'enable' => '<circle cx="12" cy="12" r="9"/><path d="m8 12 2.5 2.5L16 9"/>',
            'test' => '<path d="M9 3h6M10 3v6.2L5.5 17a2.5 2.5 0 0 0 2.1 3.8h8.8a2.5 2.5 0 0 0 2.1-3.8L14 9.2V3"/><path d="M8 15h8"/>',
            'revoke' => '<circle cx="8" cy="15" r="5"/><path d="m11.5 11.5 8-8L22 6l-2 2 1.5 1.5L19 12l-1.5-1.5-2 2"/>',
            default => throw new \LogicException('Unknown management action icon.'),
        };
        return '<svg class="action-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"'
            . ' stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            . $paths . '</svg>';
    }

    private function page(string $title, string $content, bool $authenticated = false): void
    {
        $logout = $authenticated
            ? '<form method="post" action="/admin/logout" class="logout">' . $this->csrfInput() . '<button class="secondary">Sign out</button></form>'
            : '';
        $menuToggle = $authenticated
            ? '<button class="menu-toggle secondary" type="button" aria-controls="admin-sidebar"'
                . ' aria-expanded="false" aria-label="Open navigation menu">'
                . '<svg class="menu-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"'
                . ' stroke-width="2" stroke-linecap="round" aria-hidden="true">'
                . '<path d="M4 6h16M4 12h16M4 18h16"/></svg>'
                . '<svg class="close-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor"'
                . ' stroke-width="2" stroke-linecap="round" aria-hidden="true">'
                . '<path d="m6 6 12 12M18 6 6 18"/></svg></button>'
            : '';
        $navigation = '';
        if ($authenticated) {
            $navigation = '<aside class="sidebar" id="admin-sidebar"><nav aria-label="Overview">'
                . $this->navigationLink('/admin', 'Overview', 'overview') . '</nav>'
                . '<div class="sidebar-group messaging-group"><span class="sidebar-label">Messaging</span><nav aria-label="Messaging">';
            foreach ([
                '/admin/send-email' => ['Send email', 'send'],
                '/admin/email-history' => ['Email history', 'history'],
                '/admin/templates' => ['Email templates', 'template'],
            ] as $route => [$label, $icon]) {
                $navigation .= $this->navigationLink($route, $label, $icon);
            }
            $navigation .= '</nav></div><div class="sidebar-group"><span class="sidebar-label">Manage</span><nav aria-label="Manage">';
            foreach ([
                '/admin/applications' => ['Applications', 'applications'],
                '/admin/smtp-servers' => ['SMTP servers', 'server'],
                '/admin/senders' => ['Senders', 'senders'],
                '/admin/tokens' => ['API tokens', 'key'],
            ] as $route => [$label, $icon]) {
                $navigation .= $this->navigationLink($route, $label, $icon);
            }
            $navigation .= '</nav></div><div class="sidebar-docs"><span class="sidebar-label">Docs</span><nav aria-label="Documentation">'
                . $this->navigationLink('/admin/docs', 'API', 'api')
                . $this->navigationLink('/admin/docs/admin', 'Admin', 'admin') . '</nav></div>'
                . '<div class="sidebar-note"><a href="https://github.com/ondrahladik/MailAPI" target="_blank"'
                . ' rel="noopener noreferrer">MailAPI on GitHub</a><span>MIT License</span></div></aside>';
        }
        $styles = <<<'CSS'
:root{color-scheme:dark;--bg:#111315;--surface:#191c1f;--surface-soft:#15181b;--border:#2c3136;--border-strong:#3a4249;--text:#e5e8eb;--muted:#a0a7af;--accent:#007e49;--accent-strong:#007e49;--accent-hover:#00965a;--accent-link:#39c985;--danger:#d58b8f;--success:#90b7a0}
*{box-sizing:border-box}
body{min-height:100vh;margin:0;background:var(--bg);color:var(--text);font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
.shell{width:min(1280px,calc(100% - 3rem));margin:0 auto}
header{min-height:72px;display:flex;align-items:center;justify-content:space-between;gap:1.25rem;border-bottom:1px solid var(--border)}
.brand{display:inline-flex;align-items:center;text-decoration:none}
.brand-logo{display:block;width:min(196px,38vw);height:34px;object-fit:contain;object-position:left center}
.menu-toggle{display:none;width:40px;height:40px;min-height:40px;margin:0;padding:.5rem;border-color:var(--border);background:var(--surface);color:var(--text)}
.menu-toggle svg{width:19px;height:19px}
.menu-toggle .close-icon,.menu-toggle[aria-expanded=true] .menu-icon{display:none}
.menu-toggle[aria-expanded=true] .close-icon{display:block}
.status-dot{width:7px;height:7px;border-radius:50%;background:var(--success)}
header form{margin:0}
main{padding:.9rem 0 4rem}
.page-title{margin:.15rem 0 1rem;color:var(--muted);font-size:.78rem;font-weight:550;letter-spacing:.02em}
h1,h2,h3,p{margin-top:0}
h1{letter-spacing:-.025em}
h2,h1.card-title{margin-bottom:.35rem;font-size:1.16rem;letter-spacing:-.015em}
h3{margin-bottom:.45rem;font-size:1rem;letter-spacing:-.01em}
p{color:var(--muted)}
.hero{position:relative;display:flex;align-items:center;justify-content:space-between;gap:2rem;overflow:hidden;margin:1.3rem 0 1rem;padding:1.7rem 2rem;border:1px solid var(--border);border-radius:10px;background:#181b1e}
.hero h1{max-width:700px;margin:.45rem 0 .4rem;font-size:clamp(1.45rem,3vw,2.1rem);line-height:1.2}
.hero h1.card-title{max-width:none;margin:0 0 .35rem;font-size:1.16rem;line-height:1.55;letter-spacing:-.015em}
.hero p{max-width:680px;margin:0;font-size:.9rem}
.eyebrow{display:block;margin-bottom:.25rem;color:#aab1b7;font-size:.74rem;font-weight:550;letter-spacing:.02em}
.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.8rem;margin:0 0 1.6rem}
.metric-card{display:grid;grid-template-columns:1fr auto;align-items:center;gap:.1rem .7rem;padding:1rem 1.1rem;border:1px solid var(--border);border-radius:8px;background:var(--surface)}
.metric-label{color:#c0c5ca;font-size:.78rem;font-weight:600}
.metric-card strong{grid-row:span 2;color:var(--text);font-size:1.8rem;line-height:1}
.metric-detail{color:var(--muted);font-size:.73rem}
.admin-layout{display:grid;grid-template-columns:205px minmax(0,1fr);align-items:start;gap:1.5rem}
.page-main{min-width:0;padding:1.35rem 0 4rem}
.sidebar{position:sticky;top:1.25rem;padding:.8rem .65rem;border:1px solid var(--border);border-radius:8px;background:var(--surface)}
.admin-layout>.sidebar{margin-top:1.35rem}
.sidebar-label{display:block;padding:.35rem .65rem .65rem;color:#858b91;font-size:.65rem;font-weight:700;letter-spacing:.1em}
.sidebar nav{display:grid;gap:.2rem}
.sidebar-group{margin-top:.85rem}
.sidebar-group.messaging-group{margin-top:.75rem;padding-top:.7rem;border-top:1px solid var(--border)}
.sidebar-group+.sidebar-group{padding-top:.7rem;border-top:1px solid var(--border)}
.sidebar-docs{margin-top:1rem;padding-top:.7rem;border-top:1px solid var(--border)}
.sidebar-docs .sidebar-label{padding-bottom:.35rem}
.nav-link{display:flex;align-items:center;gap:.55rem;min-height:38px;padding:.5rem .65rem;border-radius:5px;color:#afb5bc;text-decoration:none;font-size:.82rem;font-weight:550;transition:background .15s ease,color .15s ease}
.nav-icon{width:16px;height:16px;flex:0 0 16px;color:#8997a4}
.nav-link.current .nav-icon{color:var(--accent-link)}
.nav-link span{min-width:0;overflow-wrap:anywhere}
.nav-link:hover,.nav-link:focus-visible{background:rgba(0,126,73,.12);color:var(--accent-link);outline:none}
.nav-link.current{border-left:2px solid var(--accent);background:rgba(0,126,73,.16);color:var(--accent-link);padding-left:calc(.65rem - 2px)}
a:not(.brand):not(.nav-link){color:var(--accent-link);text-decoration-color:rgba(0,126,73,.65)}
a:not(.brand):not(.nav-link):hover{color:#75dfa9;text-decoration-color:currentColor}
.sidebar-note{display:flex;flex-direction:column;align-items:flex-start;gap:.25rem;margin:.75rem .2rem 0;padding:.75rem .5rem 0;border-top:1px solid var(--border);font-size:.68rem}
.sidebar-note a{font-weight:600}
.sidebar-note span{color:#969da4;font-size:.62rem}
.content-section{scroll-margin-top:1rem;margin:0 0 1rem;padding:1.15rem;border:1px solid var(--border);border-radius:8px;background:var(--surface)}
.section-heading,.panel-heading{display:flex;align-items:center;justify-content:space-between;gap:1rem}
.section-heading{margin:0 0 1rem;padding:0 0 .85rem;border-bottom:1px solid var(--border)}
.section-heading .eyebrow{margin-bottom:.25rem}
.section-heading p{margin:.25rem 0 0;font-size:.79rem}
.section-count{flex:0 0 auto;padding:.2rem .5rem;border:1px solid var(--border-strong);border-radius:5px;color:#b5bbc1;font-size:.7rem}
.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.15rem .9rem;align-items:end}
.send-email-form .body-field{grid-column:1/-1}
textarea{display:block;width:100%;margin-top:.35rem;padding:.7rem .75rem;border:1px solid #393f44;border-radius:5px;background:#111416;color:var(--text);font:inherit;font-size:.84rem;line-height:1.55;resize:vertical}
textarea:focus{border-color:var(--accent);outline:2px solid rgba(0,126,73,.25)}
.form-actions{grid-column:1/-1}
.history-filters{grid-template-columns:minmax(180px,2fr) minmax(150px,1fr) minmax(130px,1fr)}
.history-filters .form-actions{display:flex;align-items:center;gap:.75rem}
.history-summary{margin:.8rem 0 .45rem;font-size:.75rem}
.pagination{display:flex;justify-content:flex-end;gap:.55rem;margin-top:.7rem}
.pagination a,.button-link{display:inline-flex;align-items:center;min-height:34px;padding:.4rem .65rem;border:1px solid var(--border-strong);border-radius:5px;text-decoration:none}
.template-body{min-height:170px}
.template-form{align-items:start}
.template-form input,.template-form select{height:42px}
.template-form .template-subject,.template-form .template-message,.template-form .template-help,.template-form .form-actions{grid-column:1/-1}
.form-help{grid-column:1/-1;margin:0;color:var(--muted);font-size:.72rem}
fieldset{display:flex;flex-wrap:wrap;gap:.2rem .9rem;grid-column:1/-1;margin:.3rem 0 .6rem;padding:.7rem .8rem;border:1px solid var(--border);border-radius:5px}
legend{padding:0 .25rem;color:var(--muted);font-size:.76rem}
.choice{display:inline-flex;align-items:center;gap:.45rem;margin:.25rem 0;font-weight:450}
input[type=checkbox]{display:inline-block;width:auto;margin:0;accent-color:var(--accent)}
select[multiple]{min-height:120px}
.application{margin:.55rem 0;padding:.9rem;border:1px solid #303438;border-radius:6px;background:#191c1f}
.application-heading{display:flex;align-items:center;justify-content:space-between;gap:.8rem}
.application-heading h3{margin:0 0 .25rem}
.application-meta{margin:.5rem 0;color:var(--muted);font-size:.76rem}
.application-actions{display:flex;align-items:center;justify-content:flex-end;gap:.45rem;flex-wrap:wrap;margin-top:.7rem}
.application-actions form,.application-actions button,.management-action-form{margin:0}
.management-actions{display:flex;align-items:center;justify-content:flex-end;gap:.45rem;flex-wrap:wrap}
.management-action-form{display:inline-flex}
.management-action{display:inline-flex;align-items:center;gap:.55rem;min-height:34px;margin:0;padding:.42rem .65rem;font-size:.73rem;line-height:1.2}
.action-icon{width:14px;height:14px;flex:0 0 14px}
.admin-modal{width:min(720px,calc(100% - 2rem));max-height:90vh;margin:auto;padding:0;overflow:hidden;border:1px solid var(--border-strong);border-radius:10px;background:var(--surface);color:var(--text);box-shadow:0 24px 70px rgba(0,0,0,.5)}
.admin-modal::backdrop{background:rgba(5,7,9,.72);backdrop-filter:blur(3px)}
.modal-header{position:sticky;top:0;z-index:1;display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.85rem 1.15rem;border-bottom:1px solid var(--border);background:var(--surface)}
.modal-header h2{margin:0;font-size:1rem}
.modal-close{width:34px;min-height:34px;margin:0;padding:0;border-color:var(--border-strong);background:#23272b;color:#c7cdd2;font-size:1.15rem}
.admin-modal>form{max-height:calc(90vh - 3.7rem);margin:0;padding:1rem 1.15rem;overflow:auto}
.admin-modal .form-actions{display:flex;align-items:center;gap:.45rem;flex-wrap:wrap}
.detail-modal .detail-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.8rem 1rem;max-height:calc(90vh - 3.7rem);margin:0;padding:1rem 1.15rem;overflow:auto}
.detail-item{min-width:0;padding:.65rem .75rem;border:1px solid var(--border);border-radius:6px;background:var(--surface-soft)}
.detail-item-wide{grid-column:1/-1}
.detail-item dt{margin-bottom:.25rem;color:var(--muted);font-size:.68rem;font-weight:650}
.detail-item dd{margin:0;color:var(--text);font-size:.8rem}
.detail-value{white-space:pre-wrap;overflow-wrap:anywhere}
.empty-state{padding:1.25rem;border:1px dashed var(--border-strong);border-radius:6px;text-align:center}
.text-link{color:var(--accent-link);font-size:.78rem}
.activity-refresh-status{margin:.55rem 0 0;text-align:right;color:var(--muted);font-size:.68rem}
.activity-refresh-status.is-error{color:var(--danger)}
.docs-content h3{margin:1.4rem 0 .55rem}
.docs-content ul,.docs-content ol{padding-left:1.35rem;color:#c5c9cd}
.docs-content li{margin:.35rem 0}
.docs-content pre{overflow:auto;margin:.65rem 0;padding:.9rem 1rem;border:1px solid var(--border);border-radius:6px;background:#111416;color:#d4d8dc;font-size:.76rem;line-height:1.6;tab-size:4}
.docs-content pre code{padding:0;border:0;background:none;color:inherit;font-size:inherit}
.syntax-key{color:#8fc7e8}
.syntax-string{color:#b4cf99}
.syntax-variable{color:#e0ae91}
.syntax-number{color:#d6a8df}
.syntax-keyword{color:#c6a5e5;font-weight:600}
.syntax-name{color:#9fc3df}
.syntax-comment{color:#87939d;font-style:italic}
.syntax-literal{color:#e3c07d}
.syntax-punctuation{color:#c2c9cf}
.docs-content>p:last-child{margin-bottom:0}
.status-badge{display:inline-flex;align-items:center;gap:.35rem;flex:0 0 auto;padding:.2rem .45rem;border:1px solid transparent;border-radius:4px;font-size:.66rem;font-weight:650;line-height:1.3;text-transform:capitalize}
.status-badge::before{width:5px;height:5px;border-radius:50%;background:currentColor;content:""}
.status-badge.is-active{border-color:#344b3d;background:#202a23;color:#a2c6ad}
.status-badge.is-disabled,.status-badge.is-error{border-color:#51383a;background:#2a2021;color:#d59a9d}
.status-badge.is-pending{border-color:#4a4332;background:#29261f;color:#c9b788}
.form-grid .form-actions{margin-top:.25rem}
.application details form{padding:.25rem 0}
.application fieldset p{flex-basis:100%;margin:.2rem 0;font-size:.75rem}
.inline-create{display:flex;align-items:end;gap:.5rem}
.inline-create label{flex:1}
label{display:block;margin:.75rem 0;color:#bec3c8;font-size:.76rem;font-weight:600}
input,select{display:block;width:100%;margin-top:.35rem;padding:.63rem .72rem;border:1px solid #393f44;border-radius:5px;background:#111416;color:var(--text);font:inherit;font-size:.82rem}
input::placeholder{color:#777f86}
input:focus,select:focus{border-color:var(--accent);outline:2px solid rgba(0,126,73,.25)}
button{display:inline-flex;align-items:center;justify-content:center;min-height:35px;margin:.25rem .2rem .1rem 0;padding:.48rem .75rem;border:1px solid transparent;border-radius:5px;background:var(--accent-strong);color:#fff;font:inherit;font-size:.76rem;font-weight:650;cursor:pointer;transition:background .15s ease,border-color .15s ease}
button:hover{background:var(--accent-hover)}
button:focus-visible{outline:2px solid rgba(180,199,220,.45);outline-offset:2px}
button.secondary{border-color:#3a4147;background:#23272b;color:#d2d6d9}
button.secondary:hover{background:#2c3136}
button.danger{border-color:#51373a;background:#2a2021;color:#dba3a5}
button.danger:hover{background:#382729}
details{margin:.65rem 0}
summary{width:fit-content;color:#bac9d8;cursor:pointer;font-size:.77rem;font-weight:600}
details form{margin-top:.55rem}
.table-wrap{overflow:auto;margin:.4rem 0 0;border:1px solid var(--border);border-radius:8px;background:var(--surface-soft)}
table{width:100%;border-collapse:collapse}
.table-primary{display:block;color:var(--text);font-weight:600}
.table-secondary{display:block;margin-top:.18rem;color:var(--muted);font-size:.7rem}
td,th{padding:.68rem .72rem;border-bottom:1px solid #292e32;text-align:left;vertical-align:top}
th{background:#1b1e21;color:#969da3;font-size:.64rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;white-space:nowrap}
td{color:#c5c9cd;font-size:.75rem}
tbody tr:last-child td{border-bottom:0}
tbody tr:hover{background:#1b1e21}
td form{margin:0}
td button{min-height:29px;margin:0;font-size:.68rem}
.management-action{min-height:34px;font-size:.73rem}
td.actions-cell{text-align:right;white-space:nowrap;min-width:170px}
td .management-actions{flex-wrap:nowrap}
code{overflow-wrap:anywhere;border:1px solid #343a40;border-radius:4px;background:#15181b;color:#c0c9d1;padding:.12rem .38rem;font-size:.7rem}
.success,.error,.notice{margin:.6rem 0;padding:.75rem .9rem;border:1px solid;border-radius:8px;font-size:.82rem}
.success{border-color:#344b3d;background:#202a23;color:#a2c6ad}
.error{border-color:#51383a;background:#2a2021;color:#d59a9d}
.notice{border-color:#4a4332;background:#29261f;color:#c9b788}
.notice p{margin-bottom:0;color:#bcb39e}
.toast-stack{position:fixed;top:1rem;right:1rem;z-index:1000;display:grid;width:min(420px,calc(100vw - 2rem));gap:.65rem;pointer-events:none}
.toast{display:flex;align-items:flex-start;gap:.75rem;padding:.9rem 1rem;border:1px solid var(--border-strong);border-radius:8px;background:#202326;color:var(--text);box-shadow:0 12px 32px rgba(0,0,0,.32);pointer-events:auto;animation:toast-enter .2s ease-out}
.toast-success{border-left:3px solid #90b7a0}
.toast-error{border-left:3px solid #d58b8f}
.toast-notice{border-left:3px solid #c6ae7c}
.toast-icon{display:grid;flex:0 0 22px;width:22px;height:22px;place-items:center;border:1px solid currentColor;border-radius:50%;font-size:.76rem;font-weight:700}
.toast-success .toast-icon{color:#a2c6ad}
.toast-error .toast-icon{color:#d59a9d}
.toast-notice .toast-icon{color:#c9b788}
.toast-content{min-width:0;flex:1}
.toast-content>strong{display:block;margin:.05rem 0 .2rem;font-size:.82rem}
.toast-content p{margin:0;color:#b6bcc2;font-size:.76rem}
.toast-content code{display:block;margin:.45rem 0;padding:.45rem;user-select:all;font-size:.74rem}
.toast-dismiss{flex:0 0 28px;width:28px;min-height:28px;margin:-.2rem -.35rem 0 0;padding:0;border:0;background:transparent;color:#aab0b6;font-size:1.2rem;font-weight:400}
.toast-dismiss:hover{background:#303438;color:var(--text);transform:none}
.toast.is-leaving{animation:toast-leave .18s ease-in forwards}
@keyframes toast-enter{from{opacity:0;transform:translateY(-6px)}to{opacity:1;transform:translateY(0)}}
@keyframes toast-leave{to{opacity:0;transform:translateY(-5px)}}
.toast-inline{position:relative;top:auto;right:auto;width:auto;margin-bottom:1rem}
.logout button{margin:0}
.auth-page main{max-width:440px;margin:10vh auto 0;padding:1.5rem;border:1px solid var(--border);border-radius:8px;background:var(--surface)}
.auth-page .page-title{margin:.2rem 0 1.25rem;color:var(--text);font-size:1.4rem;font-weight:700}
.auth-page label{margin-top:0}
@media(max-width:1050px){.admin-layout{grid-template-columns:175px minmax(0,1fr);gap:1rem}}
@media(max-width:760px){.shell{width:calc(100% - 1.5rem)}header{min-height:64px}.header-meta{display:none}.admin-layout{grid-template-columns:1fr}.sidebar{position:static;padding:.7rem}.admin-layout>.sidebar{margin-top:1rem}.sidebar-label{padding:.1rem .45rem .45rem}.sidebar nav{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.25rem}.sidebar-group{margin-top:.55rem}.nav-link{min-width:0;min-height:40px;padding:.5rem;font-size:.78rem}.nav-link.current{padding-left:calc(.5rem - 2px)}.sidebar-docs{display:flex;align-items:center;gap:.75rem;margin-top:.55rem;padding:.55rem .35rem 0}.sidebar-docs .sidebar-label{flex:0 0 auto;padding:0}.sidebar-docs .nav-link{min-height:34px}.sidebar-note{display:none}.page-main{padding:.9rem 0 3rem}.metrics{grid-template-columns:repeat(2,minmax(0,1fr));gap:.55rem}.metric-card{padding:.8rem}.metric-card strong{font-size:1.5rem}.hero{padding:1.3rem}}
@media(max-width:760px){.table-wrap table{width:max-content;min-width:100%}.table-wrap td{white-space:nowrap}}
@media(max-width:760px){.sidebar-docs{display:block}.sidebar-docs .sidebar-label{padding:.1rem .45rem .45rem}}
@media(max-width:760px){.sidebar-note{display:flex;flex-direction:row;align-items:center;margin:.55rem .35rem 0;padding:.55rem .35rem 0}}
@media(max-width:760px){.sidebar{padding:.55rem}.sidebar-group{margin-top:.4rem}.sidebar-label{padding:.1rem .45rem .3rem}.nav-link{min-height:34px;padding:.35rem .45rem}.sidebar-docs{display:block;margin-top:.4rem;padding:.45rem .35rem 0}.sidebar-docs .sidebar-label{padding:.1rem .45rem .3rem}.sidebar-docs nav{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.2rem}.sidebar-docs .nav-link{min-height:34px}.sidebar-note{margin-top:.45rem;padding-top:.45rem}}
@media(max-width:760px){body.menu-open::before{position:fixed;z-index:19;inset:0;background:rgba(5,7,9,.58);backdrop-filter:blur(2px);content:""}.shell{position:relative}.menu-toggle{display:inline-flex;margin-left:auto}.menu-toggle[aria-expanded=true]{position:relative;z-index:21}.sidebar{display:none;position:absolute;z-index:20;top:calc(64px + .45rem);left:0;right:0;max-height:calc(100vh - 84px);overflow-y:auto;box-shadow:0 14px 36px rgba(0,0,0,.45)}.sidebar.is-open{display:block}.admin-layout>.sidebar{margin-top:0}}
@media(max-width:540px){.form-grid{grid-template-columns:1fr}.form-actions,.send-email-form .body-field{grid-column:auto}.metric-card{grid-template-columns:1fr auto}.content-section{padding:.8rem}.section-heading{align-items:flex-start}.application-heading{align-items:flex-start}.send-email-form button{width:100%;min-height:42px}.docs-content pre{max-width:calc(100vw - 3.2rem);font-size:.7rem}.auth-page main{margin-top:8vh}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;transition:none!important}}
CSS;
        ob_start();
        try {
            echo '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
            . '<link rel="icon" href="/assets/favicon.ico" type="image/x-icon"><title>'
            . Http::escape($title) . ' - MailAPI</title><style>' . $styles
            . '</style></head><body' . ($authenticated ? '' : ' class="auth-page"') . '><div class="shell"><header>'
            . '<a class="brand" href="/admin"><img class="brand-logo" src="/assets/logo.png" alt="MailAPI Administration"></a>'
            . $menuToggle
            . $logout . '</header>'
            . ($authenticated ? '<div class="admin-layout">' . $navigation . '<main class="page-main">' : '<main>')
            . ($authenticated ? '' : '<h1 class="page-title">' . Http::escape($title) . '</h1>')
            . $content . '</main>' . ($authenticated ? '</div>' : '') . '</div>'
            . '<script nonce="' . Http::escape($this->cspNonce) . '">(function(){'
            . 'var menuToggle=document.querySelector(".menu-toggle");var sidebar=document.getElementById("admin-sidebar");'
            . 'if(menuToggle&&sidebar){var closeMenu=function(){sidebar.classList.remove("is-open");document.body.classList.remove("menu-open");'
            . 'menuToggle.setAttribute("aria-expanded","false");menuToggle.setAttribute("aria-label","Open navigation menu");};'
            . 'menuToggle.addEventListener("click",function(){var isOpen=menuToggle.getAttribute("aria-expanded")==="true";'
            . 'sidebar.classList.toggle("is-open",!isOpen);document.body.classList.toggle("menu-open",!isOpen);'
            . 'menuToggle.setAttribute("aria-expanded",isOpen?"false":"true");'
            . 'menuToggle.setAttribute("aria-label",isOpen?"Open navigation menu":"Close navigation menu");});'
            . 'sidebar.addEventListener("click",function(event){if(event.target.closest("a")){closeMenu();}});'
            . 'document.addEventListener("click",function(event){if(sidebar.classList.contains("is-open")'
            . '&&!sidebar.contains(event.target)&&!menuToggle.contains(event.target)){closeMenu();}});'
            . 'document.addEventListener("keydown",function(event){if(event.key==="Escape"&&sidebar.classList.contains("is-open")){'
            . 'closeMenu();menuToggle.focus();}});window.addEventListener("resize",function(){'
            . 'if(window.matchMedia("(min-width: 761px)").matches){closeMenu();}});}'
            . 'document.querySelectorAll(".toast").forEach(function(toast){'
            . 'var timer;var remove=function(){toast.classList.add("is-leaving");window.setTimeout(function(){toast.remove();},200);};'
            . 'var schedule=function(){window.clearTimeout(timer);timer=window.setTimeout(remove,7000);};'
            . 'toast.querySelector(".toast-dismiss").addEventListener("click",function(){window.clearTimeout(timer);remove();});'
            . 'if(toast.dataset.toast==="auto"){toast.addEventListener("mouseenter",function(){window.clearTimeout(timer);});'
            . 'toast.addEventListener("mouseleave",schedule);toast.addEventListener("focusin",function(){window.clearTimeout(timer);});'
            . 'toast.addEventListener("focusout",schedule);schedule();}});'
            . 'var appSelect=document.getElementById("send-email-application");'
            . 'var senderSelect=document.getElementById("send-email-sender");'
            . 'if(appSelect&&senderSelect){var syncSenders=function(){var appId=appSelect.value;'
            . 'var appOption=appSelect.options[appSelect.selectedIndex];var defaultSender=appOption?appOption.dataset.defaultSender:"";'
            . 'var available=[];Array.prototype.forEach.call(senderSelect.options,function(option){'
            . 'if(!option.value){option.textContent=appId?"Select a sender":"Select an application first";return;}'
            . 'option.hidden=option.dataset.applicationIds.split(",").indexOf(appId)===-1;if(!option.hidden){available.push(option.value);}});'
            . 'senderSelect.disabled=!appId||available.length===0;'
            . 'if(defaultSender&&available.indexOf(defaultSender)!==-1){senderSelect.value=defaultSender;}'
            . 'else if(available.indexOf(senderSelect.value)===-1){senderSelect.value=available[0]||"";}};'
            . 'appSelect.addEventListener("change",function(){syncSenders();var option=appSelect.options[appSelect.selectedIndex];'
            . 'var recipient=document.getElementById("send-email-to");if(option&&recipient){recipient.value=option.dataset.defaultRecipient||"";}});'
            . 'syncSenders();}'
            . 'var activity=document.getElementById("overview-email-activity");'
            . 'if(activity){var activityStatus=document.getElementById("overview-activity-status");var refreshing=false;'
            . 'var refreshActivity=async function(){if(refreshing||document.hidden)return;'
            . 'if(activity.querySelector("dialog[open]")){window.setTimeout(refreshActivity,500);return;}refreshing=true;'
            . 'try{var response=await fetch(activity.dataset.refreshUrl,{credentials:"same-origin",cache:"no-store",'
            . 'headers:{Accept:"application/json"}});if(!response.ok){throw new Error("Overview refresh returned HTTP "+response.status);}'
            . 'var result=await response.json();if(!result.success||!result.data||typeof result.data.html!=="string"){'
            . 'throw new Error("Overview refresh returned an invalid response.");}'
            . 'if(!activity.querySelector("dialog[open]")){activity.innerHTML=result.data.html;}'
            . 'activityStatus.textContent="Live updates are active.";'
            . 'activityStatus.classList.remove("is-error");}catch(error){activityStatus.textContent="Live updates are unavailable; retrying.";'
            . 'activityStatus.classList.add("is-error");}finally{refreshing=false;window.setTimeout(refreshActivity,500);}};'
            . 'window.setTimeout(refreshActivity,500);document.addEventListener("visibilitychange",function(){'
            . 'if(!document.hidden){window.setTimeout(refreshActivity,0);}});}'
            . 'document.addEventListener("click",function(event){'
            . 'var openButton=event.target.closest("[data-open-modal]");if(openButton){'
            . 'var dialog=document.getElementById(openButton.dataset.openModal);if(dialog){dialog.showModal();return;}}'
            . 'var closeButton=event.target.closest("dialog.admin-modal [data-close-modal]");'
            . 'if(closeButton){closeButton.closest("dialog").close();return;}'
            . 'var backdrop=event.target;if(backdrop instanceof HTMLDialogElement&&backdrop.classList.contains("admin-modal")){'
            . 'var bounds=backdrop.getBoundingClientRect();if(event.clientX<bounds.left||event.clientX>bounds.right'
            . '||event.clientY<bounds.top||event.clientY>bounds.bottom){backdrop.close();}}});'
                . '})();</script></body></html>';
            $html = ob_get_clean();
        } catch (\Throwable $exception) {
            ob_end_clean();
            throw $exception;
        }
        if (!is_string($html)) {
            throw new \RuntimeException('The administration page could not be rendered.');
        }
        echo Http::withBasePath($html);
        exit;
    }
}
