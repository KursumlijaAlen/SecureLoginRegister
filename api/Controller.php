<?php

namespace Sssd;

use OpenApi\Annotations as OA;
use Flight;
use OTPHP\TOTP;
use libphonenumber\PhoneNumberUtil;
use libphonenumber\PhoneNumberType;
use libphonenumber\NumberParseException;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Google\Client;
use Google\Service\Oauth2;
use Sssd\Utils;

class Controller {
    private $db;

    public function __construct() {
        $this->db = Database::getInstance()->getConnection();
    }

    private function verifyCaptcha($captchaResponse) {
        $data = [
            'secret' => HCAPTCHA_SERVER_SECRET,
            'response' => $captchaResponse
        ];

        $verify = curl_init();
        curl_setopt($verify, CURLOPT_URL, "https://hcaptcha.com/siteverify");
        curl_setopt($verify, CURLOPT_POST, true);
        curl_setopt($verify, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($verify, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($verify);
        curl_close($verify);

        $responseData = json_decode($response);
        return $responseData->success ?? false;
    }

    private function sendEmail($to, $subject, $body) {
        $mail = new PHPMailer(true);

        try {
            $mail->isSMTP();
            $mail->Host       = SMTP_HOST;
            $mail->SMTPAuth   = true;
            $mail->Username   = SMTP_USERNAME;
            $mail->Password   = SMTP_PASSWORD;
            $mail->SMTPSecure = SMTP_ENCRYPTION === 'tls' ? PHPMailer::ENCRYPTION_STARTTLS : PHPMailer::ENCRYPTION_SMTPS;
            $mail->Port       = SMTP_PORT;

            $mail->setFrom(SMTP_USERNAME, 'SSSD Project');
            $mail->addAddress($to);

            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body    = $body;
            $mail->AltBody = strip_tags($body);

            $mail->send();
            return true;
        } catch (Exception $e) {
            error_log("Email could not be sent. Mailer Error: {$mail->ErrorInfo}");
            return false;
        }
    }

    private function sendSMS($phone, $code) {
        if (!defined('TEXT_MESSAGE_API_KEY') || empty(TEXT_MESSAGE_API_KEY)) {
            return false;
        }

        $curl = curl_init();
        $data = [
            "messages" => [
                [
                    "from" => "SSSD",
                    "destinations" => [["to" => $phone]],
                    "text" => "Your verification code is: $code"
                ]
            ]
        ];

        curl_setopt_array($curl, [
            CURLOPT_URL => 'https://api.infobip.com/sms/2/text/advanced',
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => json_encode($data),
            CURLOPT_HTTPHEADER => [
                'Authorization: App ' . TEXT_MESSAGE_API_KEY,
                'Content-Type: application/json',
                'Accept: application/json'
            ],
        ]);

        $response = curl_exec($curl);
        curl_close($curl);

        return $response !== false;
    }

    private function validatePhoneNumber($phone_number, $country = "BA") {
        $phone_util = PhoneNumberUtil::getInstance();
        try {
            $number_proto = $phone_util->parse($phone_number, $country);
            return $phone_util->getNumberType($number_proto) === PhoneNumberType::MOBILE;
        } catch (NumberParseException $e) {
            return false;
        }
    }

    private function validateTld($email) {
        $tld_list = @file('https://data.iana.org/TLD/tlds-alpha-by-domain.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$tld_list) return true; 
        
        $tld_list = array_map('strtolower', array_slice($tld_list, 1));
        $email_parts = explode('.', $email);
        $tld = strtolower(end($email_parts));

        return in_array($tld, $tld_list);
    }

    private function validateMxRecord($email) {
        $domain = substr(strrchr($email, "@"), 1);
        return getmxrr($domain, $mx_details);
    }

    private function isPasswordPwned($password) {
        $sha1Password = strtoupper(sha1($password));
        $prefix = substr($sha1Password, 0, 5);
        $suffix = substr($sha1Password, 5);

        $ch = curl_init("https://api.pwnedpasswords.com/range/" . $prefix);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        $response = curl_exec($ch);
        curl_close($ch);

        if ($response === false) {
            return false; 
        }

        return str_contains($response, $suffix);
    }

    private function getFailedAttempts($usernameOrEmail, $timeWindow = 3600) {
        $stmt = $this->db->prepare("
            SELECT COUNT(*) FROM login_attempts 
            WHERE username_or_email = ? AND success = FALSE 
            AND attempted_at > DATE_SUB(NOW(), INTERVAL ? SECOND)
        ");
        $stmt->execute([$usernameOrEmail, $timeWindow]);
        return $stmt->fetchColumn();
    }

    private function logLoginAttempt($usernameOrEmail, $success) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO login_attempts (username_or_email, ip_address, success) 
                VALUES (?, ?, ?)
            ");
            
            $result = $stmt->execute([
                $usernameOrEmail, 
                $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1', 
                $success ? 1 : 0  
            ]);
            
            error_log("Logged login attempt: " . ($success ? 'SUCCESS' : 'FAILED') . " for {$usernameOrEmail}");
            
            if (!$result) {
                error_log("Failed to log attempt: " . print_r($stmt->errorInfo(), true));
            }
            
            return $result;
        } catch (Exception $e) {
            error_log("Error in logLoginAttempt: " . $e->getMessage());
            return false;
        }
    }

    private function generateJWT($userId) {
        $payload = [
            'user_id' => $userId,
            'iat' => time(),
            'exp' => time() + (24 * 60 * 60) // 24 hours
        ];
        return JWT::encode($payload, JWT_SECRET, 'HS256');
    }

    private function verifyJWT($token) {
        try {
            $decoded = JWT::decode($token, new Key(JWT_SECRET, 'HS256'));
            return $decoded->user_id;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * @OA\Post(
     *     path="/api/register",
     *     summary="Register a new user",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"full_name", "username", "password", "email", "phone_number"},
     *             @OA\Property(property="full_name", type="string", example="John Doe"),
     *             @OA\Property(property="username", type="string", example="johndoe123"),
     *             @OA\Property(property="password", type="string", example="SecurePass123"),
     *             @OA\Property(property="email", type="string", format="email", example="john@example.com"),
     *             @OA\Property(property="phone_number", type="string", example="+38761234567")
     *         )
     *     ),
     *     @OA\Response(
     *         response=201,
     *         description="User registered successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string", example="User registered successfully. Please check your email for verification.")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Validation error",
     *         @OA\JsonContent(
     *             @OA\Property(property="error", type="string")
     *         )
     *     )
     * )
     */
    public function register() {
        $data = Flight::request()->data->getData();

        $reserved_usernames = ['admin', 'root', 'superuser', 'administrator', 'system'];

        if (empty($data['full_name']) || strlen(trim($data['full_name'])) < 2) {
            Flight::json(["error" => "Full name is required and must be at least 2 characters"], 400);
            return;
        }

        if (empty($data['username']) || strlen($data['username']) < 3 || 
            !ctype_alnum($data['username']) || 
            in_array(strtolower($data['username']), $reserved_usernames)) {
            Flight::json(["error" => "Username must be at least 3 characters, alphanumeric only, and not reserved"], 400);
            return;
        }

        if (empty($data['password']) || strlen($data['password']) < 8) {
            Flight::json(["error" => "Password must be at least 8 characters long"], 400);
            return;
        }

        if ($this->isPasswordPwned($data['password'])) {
            Flight::json(["error" => "This password has been compromised in a data breach. Please choose a different password."], 400);
            return;
        }

        if (empty($data['email']) || !filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
            Flight::json(["error" => "Invalid email format"], 400);
            return;
        }

        if (!$this->validateTld($data['email'])) {
            Flight::json(["error" => "Invalid email domain extension"], 400);
            return;
        }

        if (!$this->validateMxRecord($data['email'])) {
            Flight::json(["error" => "Email domain does not accept emails"], 400);
            return;
        }

        if (empty($data['phone_number']) || !$this->validatePhoneNumber($data['phone_number'])) {
            Flight::json(["error" => "Invalid mobile phone number"], 400);
            return;
        }

        $stmt = $this->db->prepare("SELECT id FROM users WHERE username = ? OR email = ? OR phone_number = ?");
        $stmt->execute([$data['username'], $data['email'], $data['phone_number']]);
        if ($stmt->fetch()) {
            Flight::json(["error" => "Username, email, or phone number already exists"], 409);
            return;
        }

        $passwordHash = password_hash($data['password'], PASSWORD_DEFAULT);
        $verificationToken = bin2hex(random_bytes(32));
        $verificationExpires = date('Y-m-d H:i:s', time() + 24 * 60 * 60); // 24 hours

        $stmt = $this->db->prepare("
            INSERT INTO users (full_name, username, email, password_hash, phone_number, 
                             email_verification_token, email_verification_expires) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ");
        
        if ($stmt->execute([
            $data['full_name'], $data['username'], $data['email'], 
            $passwordHash, $data['phone_number'], 
            $verificationToken, $verificationExpires
        ])) {
            $projectPath = dirname($_SERVER['SCRIPT_NAME'], 2);
            $verificationLink = "http://" . $_SERVER['HTTP_HOST'] . $projectPath . "/api/verify-email/" . $verificationToken;
            $emailBody = "
                <h2>Welcome to SSSD Project!</h2>
                <p>Dear {$data['full_name']},</p>
                <p>Thank you for registering. Please click the link below to verify your email:</p>
                <p><a href='{$verificationLink}'>Verify Email</a></p>
                <p>This link will expire in 24 hours.</p>
            ";
            
            $this->sendEmail($data['email'], 'Email Verification - SSSD Project', $emailBody);
            
            Flight::json(["message" => "User registered successfully. Please check your email for verification."], 201);
        } else {
            Flight::json(["error" => "Registration failed"], 500);
        }
    }

    private function clearFailedAttempts($usernameOrEmail) {
        try {
            $stmt = $this->db->prepare("
                DELETE FROM login_attempts 
                WHERE username_or_email = ? AND success = FALSE
            ");
            
            $result = $stmt->execute([$usernameOrEmail]);
            
            if ($result) {
                error_log("Cleared failed login attempts for: {$usernameOrEmail}");
            } else {
                error_log("Failed to clear login attempts for: {$usernameOrEmail}");
            }
            
            return $result;
        } catch (Exception $e) {
            error_log("Error clearing failed attempts: " . $e->getMessage());
            return false;
        }
    }

    /**
     * @OA\Post(
     *     path="/api/login",
     *     summary="User login",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"username", "password"},
     *             @OA\Property(property="username", type="string", description="Username or email"),
     *             @OA\Property(property="password", type="string"),
     *             @OA\Property(property="h-captcha-response", type="string", description="Required after 3 failed attempts")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Login successful, 2FA required",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string"),
     *             @OA\Property(property="requires_2fa", type="boolean"),
     *             @OA\Property(property="qr_code_url", type="string", description="Only for first-time 2FA setup")
     *         )
     *     )
     * )
     */
    public function login() {
        $data = Flight::request()->data->getData();

        if (empty($data['username']) || empty($data['password'])) {
            Flight::json(["error" => "Username and password are required"], 400);
            return;
        }

        $usernameOrEmail = $data['username'];
        $failedAttempts = $this->getFailedAttempts($usernameOrEmail);

        error_log("Login attempt for: {$usernameOrEmail}, Previous failed attempts: {$failedAttempts}");

        if ($failedAttempts >= 3) {
            if (empty($data['h-captcha-response']) || !$this->verifyCaptcha($data['h-captcha-response'])) {
                Flight::json(["error" => "Captcha verification required after multiple failed attempts"], 400);
                return;
            }
        }

        $stmt = $this->db->prepare("SELECT * FROM users WHERE (username = ? OR email = ?) AND email_verified = TRUE");
        $stmt->execute([$usernameOrEmail, $usernameOrEmail]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($data['password'], $user['password_hash'])) {
            $this->logLoginAttempt($usernameOrEmail, false);
            
            $newFailedAttempts = $this->getFailedAttempts($usernameOrEmail);
            
            if ($newFailedAttempts >= 3) {
                Flight::json([
                    "error" => "Invalid credentials. Captcha required for security.",
                    "requires_captcha" => true  
                ], 401);
            } else {
                Flight::json(["error" => "Invalid credentials or email not verified"], 401);
            }
            return;
        }

        $this->logLoginAttempt($usernameOrEmail, true);

        $this->clearFailedAttempts($usernameOrEmail);

        $_SESSION['pending_user_id'] = $user['id'];
        $_SESSION['login_time'] = time();

        if (!$user['two_fa_enabled'] || empty($user['otp_secret'])) {
            $this->generateOtp();
        } else {
            Flight::json([
                "message" => "Please provide your 2FA code",
                "requires_2fa" => true
            ]);
        }
    }

    /**
     * @OA\Post(
     *     path="/api/generate-otp",
     *     summary="Generate OTP for 2FA setup",
     *     tags={"Authentication"}
     * )
     */
    public function generateOtp() {
        if (empty($_SESSION['pending_user_id'])) {
            Flight::json(["error" => "No active login session"], 401);
            return;
        }

        $userId = $_SESSION['pending_user_id'];
        
        $stmt = $this->db->prepare("SELECT email, otp_secret FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        if (!$user) {
            Flight::json(["error" => "User not found"], 404);
            return;
        }

        $secret = $user['otp_secret'] ?: TOTP::generate()->getSecret();
        
        if (!$user['otp_secret']) {
            $stmt = $this->db->prepare("UPDATE users SET otp_secret = ? WHERE id = ?");
            $stmt->execute([$secret, $userId]);
        }

        $otp = TOTP::createFromSecret($secret);
        $otp->setLabel($user['email']);
        $otp->setIssuer('SSSD Project');

        $qrCodeUri = $otp->getQrCodeUri(
            'https://api.qrserver.com/v1/create-qr-code/?data=[DATA]&size=300x300&ecc=M',
            '[DATA]'
        );

        Flight::json([
            "message" => "Scan this QR code with your authenticator app",
            "qr_code_url" => $qrCodeUri,
            "secret" => $secret,
            "requires_2fa" => true
        ]);
    }

    public function get2FAMethods() {
    if (empty($_SESSION['pending_user_id']) && empty($_SESSION['user_id'])) {
        Flight::json(["error" => "Authentication required"], 401);
        return;
    }

    $userId = $_SESSION['pending_user_id'] ?? $_SESSION['user_id'];
    
    $stmt = $this->db->prepare("
        SELECT totp_enabled, sms_2fa_enabled, email_2fa_enabled, backup_codes_enabled,
               sms_2fa_phone, email_2fa_address, email, phone_number, recovery_codes
        FROM users WHERE id = ?
    ");
    $stmt->execute([$userId]);
    $user = $stmt->fetch();

    if (!$user) {
        Flight::json(["error" => "User not found"], 404);
        return;
    }

    $methods = [];

    // TOTP (Authenticator App)
    if ($user['totp_enabled']) {
        $methods[] = [
            'type' => 'totp',
            'name' => 'Authenticator App',
            'description' => 'Google Authenticator, Authy, etc.',
            'icon' => '📱',
            'enabled' => true
        ];
    }

    // SMS
    if ($user['sms_2fa_enabled'] && $user['sms_2fa_phone']) {
        $maskedPhone = $this->maskPhoneNumber($user['sms_2fa_phone']);
        $methods[] = [
            'type' => 'sms',
            'name' => 'SMS Verification',
            'description' => "Send code to {$maskedPhone}",
            'icon' => '📞',
            'enabled' => true
        ];
    }

    // Email
    if ($user['email_2fa_enabled']) {
        $emailAddress = $user['email_2fa_address'] ?: $user['email'];
        $maskedEmail = $this->maskEmail($emailAddress);
        $methods[] = [
            'type' => 'email',
            'name' => 'Email Verification',
            'description' => "Send code to {$maskedEmail}",
            'icon' => '📧',
            'enabled' => true
        ];
    }

    // Backup Codes
    if ($user['backup_codes_enabled'] && !empty($user['recovery_codes'])) {
        $codes = json_decode($user['recovery_codes'], true);
        $remainingCodes = is_array($codes) ? count(array_filter($codes)) : 0;
        
        $methods[] = [
            'type' => 'backup',
            'name' => 'Backup Codes',
            'description' => "{$remainingCodes} codes remaining",
            'icon' => '🔑',
            'enabled' => true
        ];
    }

    Flight::json([
        'methods' => $methods,
        'user_id' => $userId
    ]);
}

/**
 * Send 2FA code via SMS or Email
 */
    public function send2FACode() {
        if (empty($_SESSION['pending_user_id'])) {
            Flight::json(["error" => "No active login session"], 401);
            return;
        }

        $data = Flight::request()->data->getData();
        $method = $data['method'] ?? '';
        $userId = $_SESSION['pending_user_id'];

        if (!in_array($method, ['sms', 'email'])) {
            Flight::json(["error" => "Invalid 2FA method"], 400);
            return;
        }

        $stmt = $this->db->prepare("
            SELECT sms_2fa_enabled, email_2fa_enabled, sms_2fa_phone, 
                email_2fa_address, email, full_name
            FROM users WHERE id = ?
        ");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        if (!$user) {
            Flight::json(["error" => "User not found"], 404);
            return;
        }

        // Generate 6-digit code
        $code = sprintf('%06d', random_int(100000, 999999));
        $expiresAt = date('Y-m-d H:i:s', time() + 300); // 5 minutes

        // Store code in database
        $stmt = $this->db->prepare("
            INSERT INTO two_fa_codes (user_id, code, method, expires_at) 
            VALUES (?, ?, ?, ?)
        ");
        $stmt->execute([$userId, $code, $method, $expiresAt]);

        if ($method === 'sms') {
            if (!$user['sms_2fa_enabled'] || !$user['sms_2fa_phone']) {
                Flight::json(["error" => "SMS 2FA not enabled"], 400);
                return;
            }

            $sent = $this->sendSMS($user['sms_2fa_phone'], $code);
            if ($sent) {
                Flight::json([
                    "message" => "SMS code sent successfully",
                    "method" => "sms",
                    "destination" => $this->maskPhoneNumber($user['sms_2fa_phone'])
                ]);
            } else {
                Flight::json(["error" => "Failed to send SMS"], 500);
            }

        } elseif ($method === 'email') {
            if (!$user['email_2fa_enabled']) {
                Flight::json(["error" => "Email 2FA not enabled"], 400);
                return;
            }

            $emailAddress = $user['email_2fa_address'] ?: $user['email'];
            $subject = 'Your 2FA Verification Code - SSSD Project';
            $body = "
                <div style='font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;'>
                    <div style='background: linear-gradient(45deg, #667eea, #764ba2); color: white; padding: 30px; text-align: center;'>
                        <h1>🔐 Two-Factor Authentication</h1>
                    </div>
                    <div style='padding: 30px; background: #f9f9f9;'>
                        <h2>Hello {$user['full_name']}!</h2>
                        <p>Your verification code is:</p>
                        <div style='background: white; border: 2px solid #667eea; border-radius: 10px; padding: 20px; text-align: center; margin: 20px 0;'>
                            <h2 style='color: #667eea; font-size: 2rem; margin: 0; letter-spacing: 0.2em;'>{$code}</h2>
                        </div>
                        <p>This code will expire in <strong>5 minutes</strong>.</p>
                        <p>If you didn't request this code, please ignore this email.</p>
                    </div>
                </div>
            ";

            $sent = $this->sendEmail($emailAddress, $subject, $body);
            if ($sent) {
                Flight::json([
                    "message" => "Email code sent successfully",
                    "method" => "email",
                    "destination" => $this->maskEmail($emailAddress)
                ]);
            } else {
                Flight::json(["error" => "Failed to send email"], 500);
            }
        }
    }

    /**
     * @OA\Post(
     *     path="/api/verify-otp",
     *     summary="Verify OTP code",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"otp"},
     *             @OA\Property(property="otp", type="string", example="123456")
     *         )
     *     )
     * )
     */
    public function verifyOtp() {
        if (empty($_SESSION['pending_user_id'])) {
            Flight::json(["error" => "No active login session"], 401);
            return;
        }

        $data = Flight::request()->data->getData();
        $code = $data['otp'] ?? '';
        $method = $data['method'] ?? 'totp';
        $userId = $_SESSION['pending_user_id'];

        if (empty($code)) {
            Flight::json(["error" => "Verification code is required"], 400);
            return;
        }

        $stmt = $this->db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        if (!$user) {
            Flight::json(["error" => "Invalid session"], 401);
            return;
        }

        $verified = false;

        switch ($method) {
            case 'totp':
                if (!empty($user['otp_secret'])) {
                    $otp = TOTP::createFromSecret($user['otp_secret']);
                    $verified = $otp->verify($code);
                }
                break;

            case 'sms':
            case 'email':
                $stmt = $this->db->prepare("
                    SELECT * FROM two_fa_codes 
                    WHERE user_id = ? AND code = ? AND method = ? 
                    AND expires_at > NOW() AND used = FALSE
                    ORDER BY created_at DESC LIMIT 1
                ");
                $stmt->execute([$userId, $code, $method]);
                $codeRecord = $stmt->fetch();

                if ($codeRecord) {
                    // Mark code as used
                    $stmt = $this->db->prepare("UPDATE two_fa_codes SET used = TRUE WHERE id = ?");
                    $stmt->execute([$codeRecord['id']]);
                    $verified = true;
                }
                break;

            case 'backup':
                if ($user['backup_codes_enabled'] && $user['recovery_codes']) {
                    $recoveryCodes = json_decode($user['recovery_codes'], true);
                    if (is_array($recoveryCodes) && in_array($code, $recoveryCodes)) {
                        // Remove used backup code
                        $recoveryCodes = array_diff($recoveryCodes, [$code]);
                        $stmt = $this->db->prepare("UPDATE users SET recovery_codes = ? WHERE id = ?");
                        $stmt->execute([json_encode(array_values($recoveryCodes)), $userId]);
                        $verified = true;
                    }
                }
                break;
        }

        if ($verified) {
            // Enable 2FA if first time (for TOTP)
            if ($method === 'totp' && !$user['totp_enabled']) {
                $stmt = $this->db->prepare("UPDATE users SET totp_enabled = TRUE, two_fa_enabled = TRUE WHERE id = ?");
                $stmt->execute([$userId]);
            }

            // Generate session token
            $token = $this->generateJWT($userId);
            
            // Clear pending session
            unset($_SESSION['pending_user_id']);
            unset($_SESSION['login_time']);
            
            // Set authenticated session
            $_SESSION['user_id'] = $userId;
            $_SESSION['token'] = $token;

            // Clear failed attempts
            $this->clearFailedAttempts($user['username']);
            $this->clearFailedAttempts($user['email']);

            Flight::json([
                "message" => "Login successful",
                "token" => $token,
                "method_used" => $method,
                "user" => [
                    "id" => $user['id'],
                    "full_name" => $user['full_name'],
                    "username" => $user['username'],
                    "email" => $user['email']
                ]
            ]);
        } else {
            Flight::json(["error" => "Invalid verification code"], 400);
        }
    }

    public function setup2FAMethod() {
        if (empty($_SESSION['user_id'])) {
            Flight::json(["error" => "Authentication required"], 401);
            return;
        }

        $data = Flight::request()->data->getData();
        $method = $data['method'] ?? '';
        $userId = $_SESSION['user_id'];

        switch ($method) {
            case 'totp':
                $this->setupTOTP($userId);
                break;
            case 'sms':
                $this->setupSMS($userId, $data);
                break;
            case 'email':
                $this->setupEmail2FA($userId, $data);
                break;
            case 'backup':
                $this->setupBackupCodes($userId);
                break;
            default:
                Flight::json(["error" => "Invalid 2FA method"], 400);
        }
    }

    public function remove2FAMethod() {
        if (empty($_SESSION['user_id'])) {
            Flight::json(["error" => "Authentication required"], 401);
            return;
        }

        $data = Flight::request()->data->getData();
        $method = $data['method'] ?? '';
        $userId = $_SESSION['user_id'];

        // Check if user has other 2FA methods enabled
        $stmt = $this->db->prepare("
            SELECT totp_enabled, sms_2fa_enabled, email_2fa_enabled, backup_codes_enabled
            FROM users WHERE id = ?
        ");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        $enabledMethods = array_filter([
            'totp' => $user['totp_enabled'],
            'sms' => $user['sms_2fa_enabled'],
            'email' => $user['email_2fa_enabled'],
            'backup' => $user['backup_codes_enabled']
        ]);

        if (count($enabledMethods) <= 1) {
            Flight::json(["error" => "Cannot remove the last 2FA method. You must have at least one 2FA method enabled."], 400);
            return;
        }

        switch ($method) {
            case 'totp':
                $stmt = $this->db->prepare("
                    UPDATE users SET totp_enabled = FALSE, otp_secret = NULL WHERE id = ?
                ");
                break;
            case 'sms':
                $stmt = $this->db->prepare("
                    UPDATE users SET sms_2fa_enabled = FALSE, sms_2fa_phone = NULL WHERE id = ?
                ");
                break;
            case 'email':
                $stmt = $this->db->prepare("
                    UPDATE users SET email_2fa_enabled = FALSE, email_2fa_address = NULL WHERE id = ?
                ");
                break;
            case 'backup':
                $stmt = $this->db->prepare("
                    UPDATE users SET backup_codes_enabled = FALSE, recovery_codes = NULL WHERE id = ?
                ");
                break;
            default:
                Flight::json(["error" => "Invalid 2FA method"], 400);
                return;
        }

        if ($stmt->execute([$userId])) {
            Flight::json(["message" => "2FA method removed successfully"]);
        } else {
            Flight::json(["error" => "Failed to remove 2FA method"], 500);
        }
    }

    private function setupTOTP($userId) {
        $secret = TOTP::generate()->getSecret();
        
        $stmt = $this->db->prepare("SELECT email FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        $stmt = $this->db->prepare("UPDATE users SET otp_secret = ? WHERE id = ?");
        $stmt->execute([$secret, $userId]);

        $otp = TOTP::createFromSecret($secret);
        $otp->setLabel($user['email']);
        $otp->setIssuer('SSSD Project');

        $qrCodeUri = $otp->getQrCodeUri(
            'https://api.qrserver.com/v1/create-qr-code/?data=[DATA]&size=300x300&ecc=M',
            '[DATA]'
        );

        Flight::json([
            "message" => "TOTP setup initiated",
            "qr_code_url" => $qrCodeUri,
            "secret" => $secret,
            "method" => "totp"
        ]);
    }

    private function setupSMS($userId, $data) {
        $phoneNumber = $data['phone_number'] ?? '';
        
        if (empty($phoneNumber) || !$this->validatePhoneNumber($phoneNumber)) {
            Flight::json(["error" => "Valid mobile phone number is required"], 400);
            return;
        }

        $stmt = $this->db->prepare("
            UPDATE users SET sms_2fa_enabled = TRUE, sms_2fa_phone = ? WHERE id = ?
        ");
        
        if ($stmt->execute([$phoneNumber, $userId])) {
            Flight::json([
                "message" => "SMS 2FA enabled successfully",
                "phone" => $this->maskPhoneNumber($phoneNumber)
            ]);
        } else {
            Flight::json(["error" => "Failed to enable SMS 2FA"], 500);
        }
    }

    private function setupEmail2FA($userId, $data) {
        $emailAddress = $data['email_address'] ?? '';
        
        if (empty($emailAddress) || !filter_var($emailAddress, FILTER_VALIDATE_EMAIL)) {
            Flight::json(["error" => "Valid email address is required"], 400);
            return;
        }

        $stmt = $this->db->prepare("
            UPDATE users SET email_2fa_enabled = TRUE, email_2fa_address = ? WHERE id = ?
        ");
        
        if ($stmt->execute([$emailAddress, $userId])) {
            Flight::json([
                "message" => "Email 2FA enabled successfully",
                "email" => $this->maskEmail($emailAddress)
            ]);
        } else {
            Flight::json(["error" => "Failed to enable Email 2FA"], 500);
        }
    }

    private function setupBackupCodes($userId) {
        $codes = [];
        for ($i = 0; $i < 10; $i++) {
            $codes[] = strtoupper(bin2hex(random_bytes(4)));
        }
        
        $stmt = $this->db->prepare("
            UPDATE users SET backup_codes_enabled = TRUE, recovery_codes = ? WHERE id = ?
        ");
        
        if ($stmt->execute([json_encode($codes), $userId])) {
            Flight::json([
                "message" => "Backup codes generated successfully",
                "codes" => $codes
            ]);
        } else {
            Flight::json(["error" => "Failed to generate backup codes"], 500);
        }
    }

    private function maskPhoneNumber($phone) {
        if (strlen($phone) <= 4) return $phone;
        return substr($phone, 0, -4) . '****';
    }

    private function maskEmail($email) {
        $parts = explode('@', $email);
        if (count($parts) !== 2) return $email;
        
        $username = $parts[0];
        $domain = $parts[1];
        
        if (strlen($username) <= 2) {
            return $username . '@' . $domain;
        }
        
        return substr($username, 0, 2) . str_repeat('*', strlen($username) - 2) . '@' . $domain;
    }

    /**
     * @OA\Get(
     *     path="/api/verify-email/{token}",
     *     summary="Verify email address",
     *     tags={"Authentication"},
     *     @OA\Parameter(
     *         name="token",
     *         in="path",
     *         required=true,
     *         @OA\Schema(type="string")
     *     )
     * )
     */
    public function verifyEmail($token) {
        $stmt = $this->db->prepare("
            SELECT id FROM users 
            WHERE email_verification_token = ? 
            AND email_verification_expires > NOW() 
            AND email_verified = FALSE
        ");
        $stmt->execute([$token]);
        $user = $stmt->fetch();

        if (!$user) {
            Flight::json(["error" => "Invalid or expired verification token"], 400);
            return;
        }

        $stmt = $this->db->prepare("
            UPDATE users 
            SET email_verified = TRUE, email_verification_token = NULL, email_verification_expires = NULL 
            WHERE id = ?
        ");
        $stmt->execute([$user['id']]);

        Flight::json(["message" => "Email verified successfully. You can now log in."]);
    }

    /**
     * @OA\Post(
     *     path="/api/forgot-password",
     *     summary="Request password reset",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email"},
     *             @OA\Property(property="email", type="string", format="email"),
     *             @OA\Property(property="h-captcha-response", type="string", description="Required after 2 attempts")
     *         )
     *     )
     * )
     */
    public function forgotPassword() {
        $data = Flight::request()->data->getData();

        if (empty($data['email'])) {
            Flight::json(["error" => "Email is required"], 400);
            return;
        }

        $stmt = $this->db->prepare("
            SELECT COUNT(*) FROM password_resets 
            WHERE email = ? AND created_at > DATE_SUB(NOW(), INTERVAL 10 MINUTE)
        ");
        $stmt->execute([$data['email']]);
        $recentAttempts = $stmt->fetchColumn();

        if ($recentAttempts >= 2) {
            if (empty($data['h-captcha-response']) || !$this->verifyCaptcha($data['h-captcha-response'])) {
                Flight::json(["error" => "Captcha verification required after multiple attempts"], 400);
                return;
            }
        }

        $stmt = $this->db->prepare("SELECT id, full_name FROM users WHERE email = ? AND email_verified = TRUE");
        $stmt->execute([$data['email']]);
        $user = $stmt->fetch();

        if ($user) {
            $token = bin2hex(random_bytes(32));
            $expiresAt = date('Y-m-d H:i:s', time() + 300); 

            $stmt = $this->db->prepare("
                INSERT INTO password_resets (email, token, expires_at) 
                VALUES (?, ?, ?)
            ");
            $stmt->execute([$data['email'], $token, $expiresAt]);

            $projectPath = dirname($_SERVER['SCRIPT_NAME'], 2);

            $resetLink = "http://" . $_SERVER['HTTP_HOST'] . $projectPath . "/front/reset-password.php?token=" . $token;
            $emailBody = "
                <h2>Password Reset Request</h2>
                <p>Dear {$user['full_name']},</p>
                <p>Click the link below to reset your password:</p>
                <p><a href='{$resetLink}'>Reset Password</a></p>
                <p>This link will expire in 5 minutes.</p>
            ";

            $this->sendEmail($data['email'], 'Password Reset - SSSD Project', $emailBody);
        }

        Flight::json(["message" => "If the email exists, a reset link has been sent"]);
    }

    /**
     * @OA\Post(
     *     path="/api/reset-password",
     *     summary="Reset password with token",
     *     tags={"Authentication"}
     * )
     */
    public function resetPassword() {
        $data = Flight::request()->data->getData();

        if (empty($data['token']) || empty($data['password'])) {
            Flight::json(["error" => "Token and new password are required"], 400);
            return;
        }

        if (strlen($data['password']) < 8) {
            Flight::json(["error" => "Password must be at least 8 characters long"], 400);
            return;
        }

        if ($this->isPasswordPwned($data['password'])) {
            Flight::json(["error" => "This password has been compromised. Please choose a different password."], 400);
            return;
        }

        $stmt = $this->db->prepare("
            SELECT email FROM password_resets 
            WHERE token = ? AND expires_at > NOW() AND used = FALSE
        ");
        $stmt->execute([$data['token']]);
        $reset = $stmt->fetch();

        if (!$reset) {
            Flight::json(["error" => "Invalid or expired reset token"], 400);
            return;
        }

        $passwordHash = password_hash($data['password'], PASSWORD_DEFAULT);
        $stmt = $this->db->prepare("UPDATE users SET password_hash = ? WHERE email = ?");
        $stmt->execute([$passwordHash, $reset['email']]);

        $stmt = $this->db->prepare("UPDATE password_resets SET used = TRUE WHERE token = ?");
        $stmt->execute([$data['token']]);

        $stmt = $this->db->prepare("SELECT full_name FROM users WHERE email = ?");
        $stmt->execute([$reset['email']]);
        $user = $stmt->fetch();

        if ($user) {
            $emailBody = "
                <h2>Password Changed Successfully</h2>
                <p>Dear {$user['full_name']},</p>
                <p>Your password has been successfully changed.</p>
                <p>If you did not make this change, please contact support immediately.</p>
            ";
            $this->sendEmail($reset['email'], 'Password Changed - SSSD Project', $emailBody);
        }

        Flight::json(["message" => "Password reset successfully"]);
    }

    /**
     * @OA\Get(
     *     path="/api/user/profile",
     *     summary="Get user profile",
     *     tags={"User"},
     *     security={{"bearerAuth": {}}}
     * )
     */
    public function getUserProfile() {
        if (empty($_SESSION['user_id'])) {
            Flight::json(["error" => "Authentication required"], 401);
            return;
        }

        $stmt = $this->db->prepare("
            SELECT id, full_name, username, email, phone_number, two_fa_enabled, created_at 
            FROM users WHERE id = ?
        ");
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch();

        if (!$user) {
            Flight::json(["error" => "User not found"], 404);
            return;
        }

        Flight::json(["user" => $user]);
    }

    /**
     * @OA\Post(
     *     path="/api/user/change-password",
     *     summary="Change user password",
     *     tags={"User"},
     *     security={{"bearerAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"current_password", "new_password"},
     *             @OA\Property(property="current_password", type="string"),
     *             @OA\Property(property="new_password", type="string")
     *         )
     *     )
     * )
     */
    public function changePassword() {
        if (empty($_SESSION['user_id'])) {
            Flight::json(["error" => "Authentication required"], 401);
            return;
        }

        $data = Flight::request()->data->getData();

        if (empty($data['current_password']) || empty($data['new_password'])) {
            Flight::json(["error" => "Current and new password are required"], 400);
            return;
        }

        if (strlen($data['new_password']) < 8) {
            Flight::json(["error" => "New password must be at least 8 characters long"], 400);
            return;
        }

        if ($this->isPasswordPwned($data['new_password'])) {
            Flight::json(["error" => "This password has been compromised. Please choose a different password."], 400);
            return;
        }

        $stmt = $this->db->prepare("SELECT password_hash, email, full_name FROM users WHERE id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $user = $stmt->fetch();

        if (!$user || !password_verify($data['current_password'], $user['password_hash'])) {
            Flight::json(["error" => "Current password is incorrect"], 400);
            return;
        }

        $newPasswordHash = password_hash($data['new_password'], PASSWORD_DEFAULT);
        $stmt = $this->db->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
        $stmt->execute([$newPasswordHash, $_SESSION['user_id']]);

        $emailBody = "
            <h2>Password Changed Successfully</h2>
            <p>Dear {$user['full_name']},</p>
            <p>Your password has been successfully changed from your account settings.</p>
        ";
        $this->sendEmail($user['email'], 'Password Changed - SSSD Project', $emailBody);

        Flight::json(["message" => "Password changed successfully"]);
    }

    /**
     * @OA\Post(
     *     path="/api/user/update-2fa",
     *     summary="Update 2FA settings",
     *     tags={"User"},
     *     security={{"bearerAuth": {}}}
     * )
     */
    public function update2FA() {
        if (empty($_SESSION['user_id'])) {
            Flight::json(["error" => "Authentication required"], 401);
            return;
        }

        $data = Flight::request()->data->getData();
        $action = $data['action'] ?? '';

        if ($action === 'disable') {
            $stmt = $this->db->prepare("UPDATE users SET two_fa_enabled = FALSE WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            Flight::json(["message" => "2FA disabled successfully"]);
        } else if ($action === 'generate_recovery') {
            $recoveryCodes = [];
            for ($i = 0; $i < 10; $i++) {
                $recoveryCodes[] = strtoupper(bin2hex(random_bytes(4)));
            }
            
            $stmt = $this->db->prepare("UPDATE users SET recovery_codes = ? WHERE id = ?");
            $stmt->execute([json_encode($recoveryCodes), $_SESSION['user_id']]);
            
            Flight::json([
                "message" => "Recovery codes generated",
                "recovery_codes" => $recoveryCodes
            ]);
        } else {
            Flight::json(["error" => "Invalid action"], 400);
        }
    }

    /**
     * @OA\Post(
     *     path="/api/user/update-profile",
     *     summary="Update user profile information",
     *     tags={"User"},
     *     security={{"bearerAuth": {}}},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"full_name"},
     *             @OA\Property(property="full_name", type="string", example="John Doe"),
     *             @OA\Property(property="phone_number", type="string", example="+38761234567")
     *         )
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Profile updated successfully",
     *         @OA\JsonContent(
     *             @OA\Property(property="message", type="string"),
     *             @OA\Property(property="user", type="object")
     *         )
     *     )
     * )
     */
    public function updateProfile() {
        if (empty($_SESSION['user_id'])) {
            Flight::json(["error" => "Authentication required"], 401);
            return;
        }

        $data = Flight::request()->data->getData();

        // Validation
        if (empty($data['full_name']) || strlen(trim($data['full_name'])) < 2) {
            Flight::json(["error" => "Full name is required and must be at least 2 characters"], 400);
            return;
        }

        // Validate phone number if provided
        if (!empty($data['phone_number']) && !$this->validatePhoneNumber($data['phone_number'])) {
            Flight::json(["error" => "Invalid mobile phone number"], 400);
            return;
        }

        try {
            // Check if phone number is already in use by another user
            if (!empty($data['phone_number'])) {
                $stmt = $this->db->prepare("SELECT id FROM users WHERE phone_number = ? AND id != ?");
                $stmt->execute([$data['phone_number'], $_SESSION['user_id']]);
                if ($stmt->fetch()) {
                    Flight::json(["error" => "Phone number is already in use"], 409);
                    return;
                }
            }

            // Update user profile
            $stmt = $this->db->prepare("
                UPDATE users SET 
                    full_name = ?, 
                    phone_number = ?,
                    updated_at = NOW()
                WHERE id = ?
            ");
            
            $success = $stmt->execute([
                trim($data['full_name']),
                $data['phone_number'] ?? null,
                $_SESSION['user_id']
            ]);

            if ($success) {
                // Get updated user data
                $stmt = $this->db->prepare("
                    SELECT id, full_name, username, email, phone_number, two_fa_enabled, created_at, updated_at
                    FROM users WHERE id = ?
                ");
                $stmt->execute([$_SESSION['user_id']]);
                $user = $stmt->fetch();

                Flight::json([
                    "message" => "Profile updated successfully",
                    "user" => $user
                ]);
            } else {
                Flight::json(["error" => "Failed to update profile"], 500);
            }

        } catch (Exception $e) {
            error_log("Error updating profile: " . $e->getMessage());
            Flight::json(["error" => "An error occurred while updating profile"], 500);
        }
    }

    /**
     * @OA\Post(
     *     path="/api/logout",
     *     summary="User logout",
     *     tags={"Authentication"}
     * )
     */
    public function logout() {
        session_destroy();
        Flight::json(["message" => "Logged out successfully"]);
    }

    /**
     * @OA\Post(
     *     path="/api/resend-verification",
     *     summary="Resend email verification",
     *     tags={"Authentication"},
     *     @OA\RequestBody(
     *         required=true,
     *         @OA\JsonContent(
     *             required={"email"},
     *             @OA\Property(property="email", type="string", format="email")
     *         )
     *     )
     * )
     */
    public function resendVerification() {
        $data = Flight::request()->data->getData();

        if (empty($data['email'])) {
            Flight::json(["error" => "Email is required"], 400);
            return;
        }

        $stmt = $this->db->prepare("
            SELECT id, full_name FROM users 
            WHERE email = ? AND email_verified = FALSE
        ");
        $stmt->execute([$data['email']]);
        $user = $stmt->fetch();

        if ($user) {
            $verificationToken = bin2hex(random_bytes(32));
            $verificationExpires = date('Y-m-d H:i:s', time() + 24 * 60 * 60);

            $stmt = $this->db->prepare("
                UPDATE users 
                SET email_verification_token = ?, email_verification_expires = ? 
                WHERE id = ?
            ");
            $stmt->execute([$verificationToken, $verificationExpires, $user['id']]);

            $verificationLink = "http://" . $_SERVER['HTTP_HOST'] . "/api/verify-email/" . $verificationToken;
            $emailBody = "
                <h2>Email Verification</h2>
                <p>Dear {$user['full_name']},</p>
                <p>Please click the link below to verify your email:</p>
                <p><a href='{$verificationLink}'>Verify Email</a></p>
            ";

            $this->sendEmail($data['email'], 'Email Verification - SSSD Project', $emailBody);
        }

        Flight::json(["message" => "If the email exists and is unverified, a new verification link has been sent"]);
    }

        /**
     * GET /google-login
     * Returns the URL to redirect the user to Google’s OAuth consent screen.
     */
    public function googleLogin() {
        $client = Utils::getGoogleClient();
        $authUrl = $client->createAuthUrl();
        if ($authUrl) {
            Flight::json(['authUrl' => $authUrl]);
        } else {
            Flight::json(['error' => 'Unable to create auth URL'], 500);
        }
    }

    /**
     * GET /google-callback
     * Handles Google's redirect, fetches the token & user info,
     * then logs in (or auto–registers) the user and requires 2FA setup.
     */
    public function googleCallback() {
        $request = Flight::request();
        $code = $request->query->code ?? null;
        if (!$code) {
            Flight::json(['error' => 'Authorization code not provided'], 400);
            return;
        }

        $client = Utils::getGoogleClient();
        $token  = $client->fetchAccessTokenWithAuthCode($code);

        if (isset($token['error'])) {
            Flight::json(['error' => $token['error_description']], 400);
            return;
        }

        $client->setAccessToken($token['access_token']);
        $oauth2 = new Oauth2($client);
        $gUser  = $oauth2->userinfo->get();

        $email     = $gUser->email;
        $firstName = $gUser->givenName;
        $lastName  = $gUser->familyName;

        // 1) Look up existing user by email
        $stmt = $this->db->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        $isNewUser = false;

        if (!$user) {
            // 2) Auto‐register a new user
            $baseUsername = preg_replace('/[^a-z0-9]/','', strtolower(explode('@',$email)[0]));
            $username     = $baseUsername;
            $i = 1;
            
            // Check for existing username
            while (true) {
                $checkStmt = $this->db->prepare("SELECT id FROM users WHERE username = ?");
                $checkStmt->execute([$username]);
                
                if (!$checkStmt->fetch()) {
                    // Username is available
                    break;
                }
                
                // Username exists, try next one
                $username = $baseUsername . $i++;
            }

            $randomPwd   = bin2hex(random_bytes(16));
            $pwdHash     = password_hash($randomPwd, PASSWORD_DEFAULT);
            $fullName    = trim("$firstName $lastName");
            
            // Insert with email_verified = TRUE and empty phone_number (or NULL if you fixed the DB)
            $ins = $this->db->prepare("
                INSERT INTO users 
                (full_name, username, email, password_hash, phone_number, email_verified, created_at)
                VALUES (?, ?, ?, ?, '', TRUE, NOW())
            ");
            $ins->execute([$fullName, $username, $email, $pwdHash]);
            $userId = $this->db->lastInsertId();
            $isNewUser = true;
            
            // Fetch the newly created user
            $stmt = $this->db->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $user = $stmt->fetch();
        } else {
            $userId = $user['id'];
        }

        // 3) Set up pending session for 2FA (ALWAYS for both new and existing users)
        $_SESSION['pending_user_id'] = $userId;
        $_SESSION['login_time'] = time();

        // 4) Check if user needs 2FA setup or verification
        if ($isNewUser || !$user['two_fa_enabled'] || empty($user['otp_secret'])) {
            // New user or existing user without 2FA - generate QR code for setup
            $this->generateOtp();
        } else {
            // Existing user with 2FA - require verification
            Flight::json([
                'message' => 'Please complete 2FA verification',
                'requires_2fa' => true
            ]);
        }
    }
}