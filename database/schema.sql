CREATE DATABASE IF NOT EXISTS mail_api
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE mail_api;

CREATE TABLE smtp_servers (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(120) NOT NULL,
    host VARCHAR(253) NOT NULL,
    port SMALLINT UNSIGNED NOT NULL,
    username VARCHAR(255) NOT NULL,
    password_encrypted VARCHAR(1024) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    encryption ENUM('tls', 'ssl') NOT NULL DEFAULT 'tls',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_smtp_servers_name (name)
) ENGINE=InnoDB;

CREATE TABLE senders (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    email VARCHAR(254) NOT NULL,
    sender_name VARCHAR(120) NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_senders_email (email)
) ENGINE=InnoDB;

CREATE TABLE applications (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(120) NOT NULL,
    slug VARCHAR(80) NOT NULL,
    default_to VARCHAR(254) NULL,
    smtp_server_id BIGINT UNSIGNED NULL,
    default_sender_id BIGINT UNSIGNED NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_applications_slug (slug),
    KEY ix_applications_smtp_server (smtp_server_id),
    KEY ix_applications_default_sender (default_sender_id),
    CONSTRAINT fk_applications_smtp_server
        FOREIGN KEY (smtp_server_id) REFERENCES smtp_servers (id)
        ON DELETE SET NULL,
    CONSTRAINT fk_applications_default_sender
        FOREIGN KEY (default_sender_id) REFERENCES senders (id)
        ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE application_senders (
    application_id BIGINT UNSIGNED NOT NULL,
    sender_id BIGINT UNSIGNED NOT NULL,
    assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (application_id, sender_id),
    KEY ix_application_senders_sender (sender_id),
    CONSTRAINT fk_application_senders_application
        FOREIGN KEY (application_id) REFERENCES applications (id)
        ON DELETE CASCADE,
    CONSTRAINT fk_application_senders_sender
        FOREIGN KEY (sender_id) REFERENCES senders (id)
        ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE api_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    application_id BIGINT UNSIGNED NOT NULL,
    name VARCHAR(120) NOT NULL,
    token_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    last_used_at DATETIME NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_api_tokens_hash (token_hash),
    KEY ix_api_tokens_application (application_id),
    CONSTRAINT fk_api_tokens_application
        FOREIGN KEY (application_id) REFERENCES applications (id)
        ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE api_rate_limits (
    token_id BIGINT UNSIGNED NOT NULL,
    window_started_at DATETIME NOT NULL,
    request_count SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (token_id),
    CONSTRAINT fk_api_rate_limits_token
        FOREIGN KEY (token_id) REFERENCES api_tokens (id)
        ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE email_templates (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    application_id BIGINT UNSIGNED NOT NULL,
    slug VARCHAR(80) NOT NULL,
    name VARCHAR(120) NOT NULL,
    subject_template VARCHAR(255) NOT NULL,
    body_template MEDIUMTEXT NOT NULL,
    format ENUM('text', 'html') NOT NULL DEFAULT 'text',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_email_templates_application_slug (application_id, slug),
    KEY ix_email_templates_application_active (application_id, is_active),
    CONSTRAINT fk_email_templates_application
        FOREIGN KEY (application_id) REFERENCES applications (id)
        ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE email_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    smtp_server_id BIGINT UNSIGNED NULL,
    sender_id BIGINT UNSIGNED NULL,
    application_id BIGINT UNSIGNED NOT NULL,
    token_id BIGINT UNSIGNED NULL,
    template_id BIGINT UNSIGNED NULL,
    recipient VARCHAR(254) NOT NULL,
    sender VARCHAR(254) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    format ENUM('text', 'html') NOT NULL,
    status ENUM('pending', 'sent', 'failed') NOT NULL DEFAULT 'pending',
    error_message TEXT NULL,
    ip_address VARCHAR(45) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at DATETIME NULL,
    PRIMARY KEY (id),
    KEY ix_email_logs_smtp_server (smtp_server_id),
    KEY ix_email_logs_sender (sender_id),
    KEY ix_email_logs_template (template_id),
    KEY ix_email_logs_application_created (application_id, created_at),
    KEY ix_email_logs_created (created_at),
    CONSTRAINT fk_email_logs_smtp_server
        FOREIGN KEY (smtp_server_id) REFERENCES smtp_servers (id)
        ON DELETE SET NULL,
    CONSTRAINT fk_email_logs_sender
        FOREIGN KEY (sender_id) REFERENCES senders (id)
        ON DELETE SET NULL,
    CONSTRAINT fk_email_logs_application
        FOREIGN KEY (application_id) REFERENCES applications (id)
        ON DELETE RESTRICT,
    CONSTRAINT fk_email_logs_token
        FOREIGN KEY (token_id) REFERENCES api_tokens (id)
        ON DELETE SET NULL,
    CONSTRAINT fk_email_logs_template
        FOREIGN KEY (template_id) REFERENCES email_templates (id)
        ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE admin_login_limits (
    ip_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    window_started_at DATETIME NOT NULL,
    attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (ip_hash)
) ENGINE=InnoDB;
