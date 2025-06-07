<?php

define('DB_HOST', '');
define('DB_USERNAME', '');
define('DB_PASSWORD', '');
define('DB_NAME', '');
define('DB_PORT', '');

define('TEXT_MESSAGE_API_KEY', '');

define('SMTP_HOST', 'smtp.gmail.com');
define('SMTP_USERNAME', '');
define('SMTP_PASSWORD', '');
define('SMTP_PORT', 465);
define('SMTP_ENCRYPTION', 'ssl'); 

define("GOOGLE_CLIENT_ID", '');
define("GOOGLE_CLIENT_SECRET", '');
define("GOOGLE_REDIRECT_URI", '');

define('HCAPTCHA_SERVER_SECRET', '');
define('HCAPTCHA_SITE_KEY', ''); 

define('JWT_SECRET','');

/* DB 



    CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    full_name VARCHAR(255),
    username VARCHAR(255) UNIQUE,
    email VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255),
    phone_number VARCHAR(20),
    email_verified BOOLEAN DEFAULT FALSE,
    email_verification_token VARCHAR(255),
    email_verification_expires TIMESTAMP,
    otp_secret VARCHAR(255),
    two_fa_enabled BOOLEAN DEFAULT FALSE,
    recovery_codes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    totp_enabled BOOLEAN DEFAULT FALSE,
    sms_2fa_enabled BOOLEAN DEFAULT FALSE,
    email_2fa_enabled BOOLEAN DEFAULT FALSE,
    backup_codes_enabled BOOLEAN DEFAULT FALSE,
    sms_2fa_phone VARCHAR(20),
    email_2fa_address VARCHAR(255)
);

CREATE TABLE two_fa_codes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    code VARCHAR(255),
    method VARCHAR(50),
    expires_at TIMESTAMP,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255),
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE login_attempts (
    id SERIAL PRIMARY KEY,
    username_or_email VARCHAR(255),
    ip_address VARCHAR(45),
    success BOOLEAN,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE password_resets (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255),
    token VARCHAR(255),
    expires_at TIMESTAMP,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

*/